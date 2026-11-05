package capture

import (
	"bufio"
	"context"
	"io"
)

// Hooks into the internals for the external test package.

// MaxSnaplen is the largest accepted record of a classic pcap.
const MaxSnaplen = maxSnaplen

// CtxCheckInterval is the number of packets between context checks.
const CtxCheckInterval = ctxCheckInterval

// TestReader reads raw records.
type TestReader interface {
	// Next returns the next record's data (valid until the next call), its
	// captured and original length, and the reader error.
	Next() (data []byte, capLen, origLen int, err error)
}

type testReader struct{ s packetSource }

func (t testReader) Next() ([]byte, int, int, error) {
	rp, err := t.s.next()
	return rp.data, rp.capLen, rp.origLen, err
}

// NewClassicReader opens the classic pcap reader directly (no gzip, no pcapng).
func NewClassicReader(r io.Reader) (TestReader, error) {
	c, err := newClassicReader(bufio.NewReader(r))
	if err != nil {
		return nil, err
	}
	return testReader{c}, nil
}

// NewSource opens the format-detecting reader behind Read.
func NewSource(r io.Reader) (TestReader, error) {
	s, err := newSource(r)
	if err != nil {
		return nil, err
	}
	return testReader{s}, nil
}

// ReadStream runs Read's per-file pipeline on an arbitrary reader.
func ReadStream(ctx context.Context, name string, r io.Reader, opt Options) (FileResult, error) {
	return readStream(ctx, name, r, opt)
}
