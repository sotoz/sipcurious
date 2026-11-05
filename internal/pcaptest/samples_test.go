package pcaptest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSamplesMatchCommitted regenerates every demo capture and requires the
// bytes to equal the committed file in testdata/samples (and a second build to
// equal the first), so a generator change cannot silently invalidate
// testdata/samples/README.md. Regenerate with:
//
//	go run ./internal/pcaptest/cmd/gensamples
func TestSamplesMatchCommitted(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "samples")
	for _, s := range Samples() {
		t.Run(s.File, func(t *testing.T) {
			render := func() []byte {
				b := s.Build()
				if strings.HasSuffix(s.File, ".pcapng") {
					return b.PCAPNG()
				}
				return b.PCAP()
			}
			got := render()
			if !bytes.Equal(got, render()) {
				t.Fatal("two builds differ")
			}
			want, err := os.ReadFile(filepath.Join(dir, s.File))
			if err != nil {
				t.Fatalf("read committed sample: %v (run gensamples)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs from the generator output; run: go run ./internal/pcaptest/cmd/gensamples", s.File)
			}
		})
	}
}

// TestSamplesDirComplete requires every file in testdata/samples (except the
// README) to be produced by Samples.
func TestSamplesDirComplete(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "samples")
	known := map[string]bool{"README.md": true}
	for _, s := range Samples() {
		known[s.File] = true
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !known[e.Name()] {
			t.Errorf("%s is not produced by Samples()", e.Name())
		}
	}
}
