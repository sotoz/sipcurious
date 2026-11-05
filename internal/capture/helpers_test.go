package capture_test

import (
	"context"
	"slices"

	"github.com/sotoz/sipcurious/internal/capture"
	"github.com/sotoz/sipcurious/internal/sip"
	"github.com/sotoz/sipcurious/internal/trace"
)

// sipResult is what the tests of the old SIP-aware API looked at: the
// capture result plus every SIP message found.
type sipResult struct {
	capture.Result
	Messages    []trace.Message // without Raw, HeaderEnd and Via
	RawMessages []trace.Message // complete messages
}

// stripNew clears the v2-only fields (Raw, HeaderEnd, Via) so that the
// migrated v1 tests keep comparing exactly the fields they always did; the
// new fields are covered by the sip package tests and by rawMessages.
func stripNew(msgs []trace.Message) {
	for i := range msgs {
		msgs[i].Raw, msgs[i].HeaderEnd, msgs[i].Via = "", 0, ""
	}
}

// readFile reads one capture with the SIP handler registered.
func readFile(ctx context.Context, path string) (sipResult, error) {
	return readFiles(ctx, []string{path})
}

// readFiles reads several captures with the SIP handler registered. With more
// than one file the messages are merged by timestamp (stable: ties keep file
// order, then packet order), like the old ReadFiles did.
func readFiles(ctx context.Context, paths []string) (sipResult, error) {
	res, err := capture.Read(ctx, paths, capture.Options{Handlers: []capture.Factory{sip.NewHandler(sip.ParseOptions{})}})
	if err != nil {
		return sipResult{}, err
	}
	out := sipResult{Result: res}
	for _, h := range capture.HandlersOf[*sip.Handler](res) {
		out.Messages = append(out.Messages, h.Messages()...)
	}
	if len(paths) > 1 {
		slices.SortStableFunc(out.Messages, func(a, b trace.Message) int { return a.Time.Compare(b.Time) })
	}
	out.RawMessages = slices.Clone(out.Messages)
	stripNew(out.Messages)
	return out, nil
}
