// Command sipcurious troubleshoots SIP/VoIP calls from pcap files. All logic
// lives in internal/cli; main only wires signals, the version and the exit code.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/sotoz/sipcurious/internal/cli"
)

// version is stamped at build time: go build -ldflags "-X main.version=v2.0.0".
var version = "dev"

// interruptGrace is how long a cancelled run may take to wind down before the
// process gives up (a read blocked on stdin cannot be cancelled).
const interruptGrace = 2 * time.Second

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	go func() {
		<-sigs
		cancel()
		// Restore the default disposition: a second Ctrl-C kills the process
		// immediately. If the run does not stop by itself, do it ourselves.
		signal.Stop(sigs)
		time.Sleep(interruptGrace)
		fmt.Fprintln(os.Stderr, "sipcurious: interrupted")
		os.Exit(cli.ExitSignal)
	}()
	code := cli.Main(ctx, &cli.Env{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, Version: version}, os.Args[1:])
	cancel()
	os.Exit(code)
}
