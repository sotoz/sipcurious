// Package engine turns capture files into a Dataset: every SIP message, every
// RTP stream and, on demand, the calls built from them. It is the one place
// that composes capture.Read with the sip and rtp handlers, so every command
// (messages, calls, diagnose, stats, ...) sees the same data.
//
// Load reads all files concurrently (capture does the work), merges the
// per-file results and sorts messages by capture time (stable: equal
// timestamps keep file order, then packet order). With Options.RTP off only
// the SIP handler is registered, which is the fast path for pure signalling
// questions: RTP datagrams are counted as skipped and never inspected.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/sotoz/sipcurious/internal/analysis"
	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/capture"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/sip"
	"github.com/sotoz/sipcurious/internal/stats"
	"github.com/sotoz/sipcurious/internal/trace"
)

// Options controls what Load extracts.
type Options struct {
	// RTP enables RTP/RTCP stream tracking. DefaultOptions turns it on;
	// without it Dataset.Streams is empty and calls carry no media quality.
	RTP bool
	// Bodies selects which SIP bodies are kept in Message.Raw (default: SDP only).
	Bodies sip.BodyMode
	// CorrelateHeaders lists headers (e.g. "X-CID") whose equal value links
	// the Call-IDs of B2BUA legs, see call.Options.
	CorrelateHeaders []string
	// Stdin, when non-nil, is the source of the path "-". The capture reader
	// can only read the process's real standard input, so any other reader is
	// spooled to a temporary file first (removed before Load returns); messages
	// and streams still report the file as "-". Leave nil to read os.Stdin.
	Stdin io.Reader
}

// DefaultOptions returns the options of a normal run: RTP on, SDP bodies kept.
func DefaultOptions() Options { return Options{RTP: true} }

// Dataset is everything found in a set of capture files.
type Dataset struct {
	Files    []string // input paths, in the order given
	Packets  int      // packets read
	Skipped  int      // packets no handler consumed
	Warnings []string // non-fatal problems (truncated captures, ...)

	Messages []trace.Message // all SIP messages sorted by Time (stable)
	Streams  []rtp.Stream    // all RTP streams sorted by Start

	opt   Options
	once  sync.Once
	calls []call.Call
	byID  map[string]int
}

// Load reads paths ("-" is stdin) and returns the Dataset. A file that cannot
// be read fails the whole call; a ctx cancellation returns ctx's error.
func Load(ctx context.Context, paths []string, opt Options) (*Dataset, error) {
	if opt.Stdin != nil && slices.Contains(paths, "-") {
		return loadSpooled(ctx, paths, opt)
	}
	factories := []capture.Factory{sip.NewHandler(sip.ParseOptions{Bodies: opt.Bodies})}
	if opt.RTP {
		factories = append(factories, rtp.NewHandler(rtp.HandlerOptions{}))
	}
	res, err := capture.Read(ctx, paths, capture.Options{Handlers: factories})
	if err != nil {
		return nil, err
	}
	d := &Dataset{
		Files:    append([]string(nil), paths...),
		Packets:  res.Packets,
		Skipped:  res.Skipped,
		Warnings: res.Warnings,
		opt:      opt,
	}

	sips := capture.HandlersOf[*sip.Handler](res)
	switch len(sips) {
	case 0:
	case 1:
		d.Messages = sips[0].Messages()
	default:
		n := 0
		for _, h := range sips {
			n += len(h.Messages())
		}
		d.Messages = make([]trace.Message, 0, n)
		for _, h := range sips {
			d.Messages = append(d.Messages, h.Messages()...)
		}
	}
	cmpTime := func(a, b trace.Message) int { return a.Time.Compare(b.Time) }
	if !slices.IsSortedFunc(d.Messages, cmpTime) {
		slices.SortStableFunc(d.Messages, cmpTime)
	}

	if opt.RTP {
		for _, h := range capture.HandlersOf[*rtp.Handler](res) {
			d.Streams = append(d.Streams, h.Streams()...)
		}
		slices.SortStableFunc(d.Streams, func(a, b rtp.Stream) int { return a.Start.Compare(b.Start) })
	}
	return d, nil
}

// Calls returns the calls built from the messages (ordered by start) with the
// RTP streams attached. It is computed once, on first use, and is safe for
// concurrent callers. The result is shared: do not modify it.
func (d *Dataset) Calls() []call.Call {
	d.once.Do(func() {
		d.calls = call.Build(d.Messages, call.Options{CorrelateHeaders: d.opt.CorrelateHeaders})
		if len(d.Streams) > 0 {
			call.Attach(d.calls, d.Streams)
		}
		d.byID = make(map[string]int, len(d.calls))
		for i := range d.calls {
			d.byID[d.calls[i].CallID] = i
		}
	})
	return d.calls
}

// AnalysisInput returns the input of analysis.Run for this dataset.
func (d *Dataset) AnalysisInput(cfg analysis.Config) *analysis.Input {
	return &analysis.Input{Messages: d.Messages, Calls: d.Calls(), Streams: d.Streams, Config: cfg}
}

// StatsInput returns the input of stats.Compute for this dataset.
func (d *Dataset) StatsInput() stats.Input {
	return stats.Input{
		Messages: d.Messages, Calls: d.Calls(), Streams: d.Streams,
		Packets: d.Packets, Skipped: d.Skipped, Files: d.Files,
	}
}

// CallOf returns the call with the given Call-ID, or nil.
func (d *Dataset) CallOf(callID string) *call.Call {
	calls := d.Calls()
	if i, ok := d.byID[callID]; ok {
		return &calls[i]
	}
	return nil
}

// loadSpooled copies opt.Stdin to a temp file, loads it in place of "-" and
// relabels the results so the temp path never leaks.
func loadSpooled(ctx context.Context, paths []string, opt Options) (*Dataset, error) {
	tmp, err := os.CreateTemp("", "sipcurious-stdin-*")
	if err != nil {
		return nil, fmt.Errorf("-: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, err = io.Copy(tmp, ctxReader{ctx, opt.Stdin})
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("-: %w", err)
	}
	real := slices.Clone(paths)
	for i, p := range real {
		if p == "-" {
			real[i] = name
		}
	}
	opt.Stdin = nil
	d, err := Load(ctx, real, opt)
	if err != nil {
		return nil, errors.New(strings.ReplaceAll(err.Error(), name, "-"))
	}
	d.Files = slices.Clone(paths)
	for i := range d.Messages {
		if d.Messages[i].File == name {
			d.Messages[i].File = "-"
		}
	}
	for i := range d.Streams {
		if d.Streams[i].File == name {
			d.Streams[i].File = "-"
		}
	}
	for i, w := range d.Warnings {
		d.Warnings[i] = strings.ReplaceAll(w, name, "-")
	}
	return d, nil
}

// ctxReader makes io.Copy stop when the context is cancelled.
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
