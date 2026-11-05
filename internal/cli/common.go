package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/engine"
	"github.com/sotoz/sipcurious/internal/query"
	"github.com/sotoz/sipcurious/internal/report"
)

// Common is the flag vocabulary shared by every command that reads captures.
// Bind registers the flags, Finish validates them after parsing; NewCommand
// does both, so a command only touches Common through its helper methods.
type Common struct {
	Args  []string // positional arguments (capture paths); Paths expands them
	Files stringList

	Where         string
	From, To      string
	CallID, URI   string
	Method        string
	Status        string
	SrcIP, DstIP  string
	Since, Until  string
	CaseSensitive bool

	Format string
	Extra  bool
	UTC    bool
	Color  string
	Output string
	Limit  int
	NoRTP  bool
	Quiet  bool

	format  report.Format
	formats []string // command specific --format values (first is the default); nil = report.Formats()
}

// FilterFlagNames are the flags that select messages or calls; commands that
// accept them all share the same help text through Bind.
var filterFlagNames = []string{"where", "from", "to", "callid", "uri", "method", "status", "src-ip", "dst-ip", "since", "until", "case-sensitive"}

func init() { FlagChoices("format", report.Formats()...) }

// Bind registers the common flags on fs.
func (c *Common) Bind(fs *flag.FlagSet) {
	fs.Var(&c.Files, "file", "capture `FILE` (repeatable; same as a positional argument)")
	Alias(fs, "file", "f")
	fs.StringVar(&c.Where, "where", "", "filter `EXPR`, e.g. 'status >= 500 and from ~ alice' (see 'sipcurious fields')")
	Alias(fs, "where", "w")
	fs.StringVar(&c.From, "from", "", "From header contains `TEXT`")
	fs.StringVar(&c.To, "to", "", "To header contains `TEXT`")
	fs.StringVar(&c.CallID, "callid", "", "Call-ID contains `TEXT`")
	fs.StringVar(&c.URI, "uri", "", "Request-URI contains `TEXT`")
	fs.StringVar(&c.Method, "method", "", "SIP `METHOD` (INVITE, BYE, ...; responses match by their CSeq method)")
	fs.StringVar(&c.Status, "status", "", "response status `CODE` or class (486, 4xx)")
	fs.StringVar(&c.SrcIP, "src-ip", "", "source `IP` or CIDR")
	fs.StringVar(&c.DstIP, "dst-ip", "", "destination `IP` or CIDR")
	fs.StringVar(&c.Since, "since", "", "only messages at or after `TIME` (RFC 3339, 'YYYY-MM-DD HH:MM:SS' or HH:MM[:SS])")
	fs.StringVar(&c.Until, "until", "", "only messages at or before `TIME` (same formats as --since)")
	fs.BoolVar(&c.CaseSensitive, "case-sensitive", false, "match text case-sensitively")
	formats := c.formats
	if formats == nil {
		formats = report.Formats()
	}
	fs.StringVar(&c.Format, "format", formats[0], "output `FORMAT`: "+strings.Join(formats, ", "))
	Alias(fs, "format", "F")
	fs.BoolVar(&c.Extra, "extra", false, "show the extra columns")
	fs.BoolVar(&c.UTC, "utc", false, "print times in UTC instead of the local zone")
	fs.StringVar(&c.Color, "color", "auto", "colorize output: auto, always or never")
	FlagChoices("color", "auto", "always", "never")
	fs.StringVar(&c.Output, "output", "", "write the result to `FILE` instead of stdout")
	Alias(fs, "output", "o")
	fs.IntVar(&c.Limit, "limit", 0, "show at most `N` rows (0 = all)")
	fs.BoolVar(&c.NoRTP, "no-rtp", false, "skip RTP analysis (faster; no media quality)")
	fs.BoolVar(&c.Quiet, "quiet", false, "no summary line or warnings on stderr")
	Alias(fs, "quiet", "q")
}

// Finish validates the parsed flags and records the positional arguments.
func (c *Common) Finish(positional []string) error {
	c.Args = positional
	valid := c.formats
	if valid == nil {
		valid = report.Formats()
	}
	c.Format = strings.ToLower(strings.TrimSpace(c.Format))
	if !slices.Contains(valid, c.Format) {
		return Usagef("--format: unknown format %q (valid: %s)", c.Format, strings.Join(valid, ", "))
	}
	c.format, _ = report.ParseFormat(c.Format) // "" for command specific formats
	switch c.Color {
	case "auto", "always", "never":
	default:
		return Usagef("--color: %q is not auto, always or never", c.Color)
	}
	if c.Limit < 0 {
		return Usagef("--limit must not be negative")
	}
	return nil
}

// Query compiles --where and the sugar flags into one query, ANDed together.
// It returns nil (match everything) when no filter was given. Problems are
// UsageErrors; for a bad --where expression the message shows the expression
// with a caret under the offending token.
func (c *Common) Query() (*query.Query, error) {
	var qs []*query.Query
	if c.Where != "" {
		q, err := query.Parse(c.Where, query.Options{CaseSensitive: c.CaseSensitive})
		if err != nil {
			return nil, whereError("--where", err)
		}
		qs = append(qs, q)
	}
	for _, s := range []struct{ flag, field, val string }{
		{"from", "from", c.From}, {"to", "to", c.To}, {"callid", "callid", c.CallID}, {"uri", "uri", c.URI},
	} {
		if s.val != "" {
			qs = append(qs, query.Contains(s.field, s.val, c.CaseSensitive))
		}
	}
	for _, s := range []struct{ flag, field, val string }{{"method", "method", c.Method}, {"status", "status", c.Status}} {
		if s.val == "" {
			continue
		}
		q, err := query.Eq(s.field, s.val, c.CaseSensitive)
		if err != nil {
			return nil, Usagef("--%s: %v", s.flag, err)
		}
		qs = append(qs, q)
	}
	for _, s := range []struct{ flag, field, val string }{{"src-ip", "src", c.SrcIP}, {"dst-ip", "dst", c.DstIP}} {
		if s.val == "" {
			continue
		}
		q, err := query.InCIDR(s.field, s.val)
		if err != nil {
			return nil, Usagef("--%s: %v", s.flag, err)
		}
		qs = append(qs, q)
	}
	for _, s := range []struct{ flag, op, val string }{{"since", ">=", c.Since}, {"until", "<=", c.Until}} {
		if s.val == "" {
			continue
		}
		q, err := query.Parse("time "+s.op+" "+strconv.Quote(s.val), query.Options{})
		if err != nil {
			return nil, whereError("--"+s.flag, err)
		}
		qs = append(qs, q)
	}
	return query.And(qs...), nil
}

func whereError(what string, err error) error {
	var se *query.SyntaxError
	if errors.As(err, &se) {
		return Usagef("invalid %s expression:\n%s", what, se.Pretty())
	}
	return Usagef("invalid %s expression: %v", what, err)
}

// captureExts are the file name suffixes picked up when walking a directory.
var captureExts = []string{".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz"}

func isCaptureName(name string) bool {
	name = strings.ToLower(name)
	return slices.ContainsFunc(captureExts, func(e string) bool { return strings.HasSuffix(name, e) })
}

// Paths resolves the capture arguments: positionals and --file values, with
// directories walked recursively (*.pcap, *.pcapng, *.cap, *.pcap.gz,
// *.pcapng.gz, in lexical order), glob patterns expanded when no such file
// exists (Windows shells do not expand them) and "-" meaning stdin. Duplicates
// are dropped. No capture at all is a UsageError.
func (c *Common) Paths() ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, arg := range append(slices.Clone(c.Args), c.Files...) {
		if arg == "-" {
			add(arg)
			continue
		}
		st, err := os.Stat(arg)
		switch {
		case err == nil && st.IsDir():
			n := 0
			err := filepath.WalkDir(arg, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() && isCaptureName(d.Name()) {
					add(p)
					n++
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			if n == 0 {
				return nil, fmt.Errorf("%s: no capture files (*.pcap, *.pcapng, *.cap, *.pcap.gz, *.pcapng.gz) found", arg)
			}
		case err == nil:
			add(arg)
		case strings.ContainsAny(arg, "*?["):
			matches, gerr := filepath.Glob(arg)
			if gerr != nil || len(matches) == 0 {
				return nil, fmt.Errorf("%s: no files match", arg)
			}
			sort.Strings(matches)
			for _, m := range matches {
				add(m)
			}
		default:
			return nil, err // *PathError: "open x: no such file or directory"
		}
	}
	if len(out) == 0 {
		return nil, Usagef("no capture file given: pass FILE, DIRECTORY or - (stdin) as arguments, or use --file")
	}
	return out, nil
}

// Open loads the captures. It prints the capture warnings and a one-line
// summary on stderr unless --quiet. tweak functions adjust the engine options
// (e.g. force RTP on for a command that needs media); --no-rtp is applied
// before them.
func (c *Common) Open(ctx context.Context, env *Env, tweak ...func(*engine.Options)) (*engine.Dataset, error) {
	paths, err := c.Paths()
	if err != nil {
		return nil, err
	}
	opt := engine.DefaultOptions()
	opt.RTP = !c.NoRTP
	if f, ok := env.Stdin.(*os.File); !ok || f != os.Stdin {
		opt.Stdin = env.Stdin // not the real stdin: the engine spools it
	}
	for _, t := range tweak {
		t(&opt)
	}
	start := time.Now()
	ds, err := engine.Load(ctx, paths, opt)
	if err != nil {
		return nil, err
	}
	if !c.Quiet {
		for _, w := range ds.Warnings {
			env.Printf("warning: %s", w)
		}
		s := fmt.Sprintf("%s, %s, %s", plural(len(ds.Files), "file"), plural(ds.Packets, "packet"), plural(len(ds.Messages), "SIP message"))
		if opt.RTP {
			s += ", " + plural(len(ds.Streams), "RTP stream")
		}
		env.Printf("read %s in %s", s, report.FormatDuration(time.Since(start).Round(time.Millisecond)))
	}
	return ds, nil
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// Infof prints a note on stderr unless --quiet.
func (c *Common) Infof(env *Env, format string, args ...any) {
	if !c.Quiet {
		env.Printf(format, args...)
	}
}

// Select returns the indices into ds.Messages of the messages matching q, in
// order, stopping after limit matches when limit > 0. A nil q matches all.
// Queries that use call fields are evaluated with the message's call as
// context. It returns early with ctx's error when cancelled.
func Select(ctx context.Context, ds *engine.Dataset, q *query.Query, limit int) ([]int, error) {
	needCalls := q.NeedsCalls()
	var out []int
	for i := range ds.Messages {
		if i&0xfff == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		var cp *call.Call
		if needCalls {
			cp = ds.CallOf(ds.Messages[i].CallID)
		}
		if q.MatchMessage(ds.Messages[i], cp) {
			out = append(out, i)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// Out is the destination of a command's data: stdout or the --output file,
// buffered. Close flushes and must be called; its error is a write failure.
type Out struct {
	io.Writer      // buffered writer
	Color     bool // ANSI colour wanted (--color, never for files)
	Options   report.Options
	bw        *bufio.Writer
	f         *os.File
}

// OpenOutput prepares the destination selected by --output and --color.
func (c *Common) OpenOutput(env *Env) (*Out, error) {
	var dst io.Writer = env.Stdout
	o := &Out{}
	if c.Output != "" {
		f, err := os.Create(c.Output)
		if err != nil {
			return nil, err
		}
		o.f = f
		dst = f
	}
	switch c.Color {
	case "always":
		o.Color = true
	case "auto":
		o.Color = c.Output == "" && report.ShouldColor(env.Stdout)
	}
	o.bw = bufio.NewWriterSize(dst, 64<<10)
	o.Writer = o.bw
	o.Options = report.Options{Extra: c.Extra, UTC: c.UTC, Color: o.Color, HeaderRule: false}
	return o, nil
}

// Close flushes the buffer and closes the file, if any.
func (o *Out) Close() error {
	err := o.bw.Flush()
	if o.f != nil {
		if cerr := o.f.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// ReportFormat is the validated --format.
func (c *Common) ReportFormat() report.Format { return c.format }

// WriteTable renders t in the --format with --extra, --utc, --color, honouring
// --limit and --output.
func (c *Common) WriteTable(env *Env, t report.Table) error {
	if c.Limit > 0 && len(t.Rows) > c.Limit {
		c.Infof(env, "showing %d of %d rows (--limit)", c.Limit, len(t.Rows))
		t.Rows = t.Rows[:c.Limit]
	}
	return c.WriteWith(env, func(w io.Writer, f report.Format, o report.Options) error {
		return report.Write(w, f, t, o)
	})
}

// WriteSections is WriteTable for several titled tables.
func (c *Common) WriteSections(env *Env, secs []report.Section) error {
	return c.WriteWith(env, func(w io.Writer, f report.Format, o report.Options) error {
		return report.WriteSections(w, f, secs, o)
	})
}

// WriteWith opens the output, calls fn with the format and options derived from
// the flags, and closes it, returning the first error.
func (c *Common) WriteWith(env *Env, fn func(io.Writer, report.Format, report.Options) error) error {
	out, err := c.OpenOutput(env)
	if err != nil {
		return err
	}
	werr := fn(out, c.format, out.Options)
	if cerr := out.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

func isClosedPipe(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) ||
		strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "closed pipe")
}

// NewCommand builds a Command whose flags are the common set plus those bound
// by bind (may be nil). It parses the arguments (flags and positionals may be
// mixed; "--" ends flags), validates them, and calls run. -h/--help prints the
// command help and exits 0; a flag error exits 2.
func NewCommand[O any](base Command, bind func(*flag.FlagSet, *O), run func(ctx context.Context, env *Env, c *Common, o *O) int) Command {
	bindAll := func(fs *flag.FlagSet, c *Common, o *O) {
		c.formats = base.Formats
		c.Bind(fs)
		if bind != nil {
			bind(fs, o)
		}
	}
	base.Flags = func(fs *flag.FlagSet) { bindAll(fs, new(Common), new(O)) }
	base.Run = func(ctx context.Context, env *Env, args []string) int {
		c, o := new(Common), new(O)
		fs := flag.NewFlagSet(base.Name, flag.ContinueOnError)
		bindAll(fs, c, o)
		pos, err := ParseArgs(fs, args)
		if errors.Is(err, flag.ErrHelp) {
			printCommandUsage(env.Stdout, base)
			return ExitOK
		}
		if err == nil {
			err = c.Finish(pos)
		} else {
			err = Usagef("%v (see 'sipcurious help %s')", err, base.Name)
		}
		if err != nil {
			return env.Fail(err)
		}
		return run(ctx, env, c, o)
	}
	return base
}

// WriteString writes s to the buffered output.
func (o *Out) WriteString(s string) (int, error) { return o.bw.WriteString(s) }
