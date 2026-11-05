package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/pcaptest"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sipcurious-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "sipcurious")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	out, err := exec.Command("go", "build", "-ldflags", "-X main.version=v7.7.7-test", "-o", binary, ".").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func sample(name string) string {
	return filepath.Join("..", "..", "testdata", "samples", name)
}

// bigCapture writes a capture with many answered calls with RTP; it takes the
// binary a noticeable time to read.
func bigCapture(t *testing.T, calls int) string {
	t.Helper()
	b := pcaptest.New(pcaptest.SampleStart, 42)
	for i := range calls {
		b.Call(pcaptest.CallOptions{
			Start:    pcaptest.SampleStart.Add(time.Duration(i) * 50 * time.Millisecond),
			TalkTime: 20 * time.Second,
		})
	}
	path := filepath.Join(t.TempDir(), "big.pcap")
	if err := b.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBinaryVersionAndExit(t *testing.T) {
	out, err := exec.Command(binary, "version").Output()
	if err != nil || !strings.HasPrefix(string(out), "sipcurious v7.7.7-test\n") {
		t.Errorf("version: %q %v", out, err)
	}
	cmd := exec.Command(binary, "messages", "--count", "-q", sample("busy-and-reject.pcap"))
	out, err = cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "13" {
		t.Errorf("count: %q %v", out, err)
	}
	cmd = exec.Command(binary, "nope")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 || !strings.HasPrefix(stderr.String(), "sipcurious: unknown command") {
		t.Errorf("unknown command: %v %q", err, stderr.String())
	}
}

func TestBinaryStdin(t *testing.T) {
	f, err := os.Open(sample("busy-and-reject.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(binary, "messages", "--count", "-q", "-")
	cmd.Stdin = f
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "13" {
		t.Errorf("stdin: %q %v", out, err)
	}
}

func TestBinarySIGINT(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGINT delivery on Windows")
	}
	path := bigCapture(t, 600)
	// Time the full run to be sure the capture is big enough to interrupt.
	start := time.Now()
	if err := exec.Command(binary, "calls", "-q", "--limit", "1", path).Run(); err != nil {
		t.Fatal(err)
	}
	full := time.Since(start)

	cmd := exec.Command(binary, "calls", "-q", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = new(bytes.Buffer)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(min(full/4, 150*time.Millisecond))
	sent := time.Now()
	cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if time.Since(sent) > 2*time.Second {
			t.Errorf("took %v to stop after SIGINT", time.Since(sent))
		}
		if err == nil {
			t.Logf("finished (%v) before the signal landed; full run takes %v", time.Since(sent), full)
			return
		}
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 130 {
			t.Errorf("exit = %v, want 130; stderr %q", err, stderr.String())
		}
		if !strings.Contains(stderr.String(), "interrupted") || strings.Contains(stderr.String(), "panic") {
			t.Errorf("stderr = %q", stderr.String())
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("still running 10s after SIGINT; stderr %q", stderr.String())
	}
}

func TestBinarySIGINTWhileReadingStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGINT delivery on Windows")
	}
	cmd := exec.Command(binary, "messages", "-")
	pr, pw, err := os.Pipe() // never written to, never closed: a blocked read
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	cmd.Stdin = pr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	cmd.Process.Signal(syscall.SIGINT)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 130 {
			t.Errorf("exit = %v, want 130", err)
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("blocked stdin read was not interrupted")
	}
}

func TestBinaryClosedStdout(t *testing.T) {
	path := bigCapture(t, 200)
	for _, args := range [][]string{
		{"messages", "-q", "-F", "csv", "--extra", path},
		{"messages", "-q", path},
		{"show", "-q", path},
		{"calls", "-q", "-F", "ndjson", path},
	} {
		t.Run(args[0]+" "+args[2], func(t *testing.T) {
			cmd := exec.Command(binary, args...)
			pr, pw, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdout = pw
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pw.Close()
			pr.Close() // reader goes away before the first byte is written
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
				// Dying of SIGPIPE or exiting 1 are both fine, like `cmd | head`.
				if s := stderr.String(); strings.Contains(s, "panic") || strings.Contains(s, "goroutine ") {
					t.Errorf("panic on closed stdout: %s", s)
				}
			case <-time.After(15 * time.Second):
				cmd.Process.Kill()
				t.Fatal("hung on a closed stdout pipe")
			}
		})
	}
}

func TestBinaryHeadLikeConsumer(t *testing.T) {
	// A consumer that reads a little and closes the pipe, as `| head -1` does.
	path := bigCapture(t, 100)
	cmd := exec.Command(binary, "messages", "-q", "-F", "csv", path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := stdout.Read(buf); err != nil {
		t.Fatal(err)
	}
	stdout.Close()
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
		if strings.Contains(stderr.String(), "panic") {
			t.Errorf("stderr = %q", stderr.String())
		}
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		t.Fatal("hung after the consumer closed the pipe")
	}
}
