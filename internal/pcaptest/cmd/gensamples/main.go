// Command gensamples regenerates the demo captures in testdata/samples.
//
// Usage (from the repository root):
//
//	go run ./internal/pcaptest/cmd/gensamples [dir]
//
// dir defaults to testdata/samples. The output is deterministic: running the
// command twice produces byte-identical files. Test support, not for production use.
package main

import (
	"fmt"
	"os"

	"github.com/sotoz/sipcurious/internal/pcaptest"
)

func main() {
	dir := "testdata/samples"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := pcaptest.WriteSamples(dir); err != nil {
		fmt.Fprintln(os.Stderr, "gensamples:", err)
		os.Exit(1)
	}
	for _, s := range pcaptest.Samples() {
		fmt.Println(s.File)
	}
}
