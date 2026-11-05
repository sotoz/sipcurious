package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/engine"
	"github.com/sotoz/sipcurious/internal/export"
)

type exportOpts struct{ noMedia bool }

func init() {
	Register(NewCommand(Command{
		Name:    "export",
		Group:   "Share",
		Summary: "write a new pcap/pcapng with only the packets (SIP and media) of the matching calls",
		Usage:   "export [flags] -o OUT.pcapng CAPTURE...",
		Formats: []string{"pcapng", "pcap"},
	}, func(fs *flag.FlagSet, o *exportOpts) {
		fs.BoolVar(&o.noMedia, "no-media", false, "leave the RTP/RTCP out, export the signalling only")
	}, runExport))
}

func runExport(ctx context.Context, env *Env, c *Common, o *exportOpts) int {
	q, err := c.Query()
	if err != nil {
		return env.Fail(err)
	}
	if c.Output == "" {
		if f, ok := env.Stdout.(*os.File); ok && isTerminal(f) {
			return env.Fail(Usagef("refusing to write a capture to the terminal: use --output FILE (or redirect stdout)"))
		}
	}
	format, _ := export.ParseFormat(c.Format)
	paths, err := c.Paths()
	if err != nil {
		return env.Fail(err)
	}
	// export reads its inputs twice: standard input is spooled to a file first.
	if slices.Contains(paths, "-") {
		tmp, err := spoolStdin(ctx, env.Stdin)
		if err != nil {
			return env.Fail(err)
		}
		defer os.Remove(tmp)
		paths = slices.Clone(paths)
		for i, p := range paths {
			if p == "-" {
				paths[i] = tmp
			}
		}
	}
	c.Args, c.Files = paths, nil

	media := !o.noMedia && !c.NoRTP
	ds, err := c.Open(ctx, env, func(opt *engine.Options) { opt.RTP = media })
	if err != nil {
		return env.Fail(err)
	}
	sel, err := selectCalls(ctx, ds, q)
	if err != nil {
		return env.Fail(err)
	}
	calls := make([]call.Call, len(sel))
	for i, cl := range sel {
		calls[i] = *cl
	}
	c.Infof(env, "%s matched", plural(len(calls), "call"))

	dst := &lazyFile{name: c.Output, stdout: env.Stdout}
	bw := bufio.NewWriterSize(dst, 256<<10)
	st, err := export.Write(ctx, bw, ds.Files, export.SelectCalls(calls, media), export.Options{Format: format})
	if err == nil {
		err = bw.Flush()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	switch {
	case errors.Is(err, export.ErrNoPackets):
		if len(calls) == 0 {
			return env.Fail(errors.New("nothing to export: no call matches the filter"))
		}
		return env.Fail(errors.New("nothing to export: the matching calls have no packets"))
	case err != nil:
		if c.Output != "" && dst.created {
			os.Remove(c.Output) // do not leave a truncated capture behind
		}
		return env.Fail(err)
	}
	for _, w := range st.Warnings {
		c.Infof(env, "warning: %s", w)
	}
	c.Infof(env, "exported %s (%d SIP, %d media) of %s to %s, %d bytes",
		plural(st.Written, "packet"), st.SIP, st.Flows, plural(len(calls), "call"), destName(c.Output), st.Bytes)
	return ExitOK
}

func destName(out string) string {
	if out == "" {
		return "stdout"
	}
	return out
}

// lazyFile creates the output file at the first write, so that a run that
// exports nothing leaves no empty file behind. Without a name it writes to
// stdout.
type lazyFile struct {
	name    string
	stdout  io.Writer
	f       *os.File
	created bool
}

func (l *lazyFile) Write(p []byte) (int, error) {
	if l.name == "" {
		return l.stdout.Write(p)
	}
	if l.f == nil {
		f, err := os.Create(l.name)
		if err != nil {
			return 0, err
		}
		l.f, l.created = f, true
	}
	return l.f.Write(p)
}

func (l *lazyFile) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// spoolStdin copies r to a temporary file and returns its path.
func spoolStdin(ctx context.Context, r io.Reader) (string, error) {
	f, err := os.CreateTemp("", "sipcurious-stdin-*")
	if err != nil {
		return "", fmt.Errorf("-: %w", err)
	}
	_, err = io.Copy(f, ctxReader{ctx, r})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("-: %w", err)
	}
	return f.Name(), nil
}

// ctxReader stops a copy when the context is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
