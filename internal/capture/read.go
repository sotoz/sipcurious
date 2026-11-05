// Package capture reads pcap and pcapng files and hands the decoded
// transport-layer packets to protocol Handlers (SIP, RTP, ...). It knows
// nothing about any protocol itself.
//
// Both capture formats are detected by their magic number, so the file
// extension does not matter, and gzip-compressed files are read
// transparently. The path "-" reads standard input. Everything is pure Go
// (no libpcap, no cgo). Ethernet, Linux cooked (SLL, SLL2), raw IP (101, 228,
// 229), BSD loopback, PPP, VLAN-tagged frames (802.1Q, Q-in-Q), IPv4 (with
// options), IPv6 (with extension headers), IP-in-IP/GRE tunnels, UDP, TCP and
// SCTP are understood; pcapng files with several interfaces of differing link
// types are supported. IPv4 and IPv6 fragments are reassembled. The endpoints
// of a Packet are those of the innermost IP header.
//
// The common cases (Ethernet/VLAN/SLL/SLL2/Null/Raw, IPv4/IPv6, UDP/TCP) are
// decoded by hand-written code without allocations; everything else falls
// back to gopacket.
package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// Read reads all paths concurrently (one goroutine per file, at most
// runtime.GOMAXPROCS at a time) and feeds every decoded packet of a file, in
// order, to the handlers created for that file by opt.Handlers. A factory is
// called once per file; it must not return nil.
//
// A file that ends or breaks mid-record is not an error: the packets before
// the damage are processed and a warning is recorded. A file that cannot be
// opened or is not a capture file fails the whole call with an error wrapping
// the path; the Result is then empty. A cancelled ctx stops the read promptly
// and returns ctx's error wrapped with a path.
//
// Handlers that implement Finisher are finished after the last packet of
// their file.
func Read(ctx context.Context, paths []string, opt Options) (Result, error) {
	if len(paths) == 1 { // no concurrency needed
		fr, err := readFile(ctx, paths[0], opt)
		if err != nil {
			return Result{}, err
		}
		return Result{Packets: fr.Packets, Skipped: fr.Skipped, Warnings: fr.Warnings, Files: []FileResult{fr}}, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	files := make([]FileResult, len(paths))
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		sem      = make(chan struct{}, runtime.GOMAXPROCS(0))
	)
	for i, p := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			fr, err := readFile(ctx, p, opt)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				mu.Unlock()
				return
			}
			files[i] = fr
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return Result{}, firstErr
	}
	// All goroutines succeeded unless the parent context was cancelled while
	// some were still waiting for a slot.
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	out := Result{Files: files}
	for _, f := range files {
		out.Packets += f.Packets
		out.Skipped += f.Skipped
		out.Warnings = append(out.Warnings, f.Warnings...)
	}
	return out, nil
}

// readFile decodes one capture file.
func readFile(ctx context.Context, path string, opt Options) (FileResult, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return FileResult{}, fmt.Errorf("%s: %w", path, err)
		}
		defer f.Close()
		r = f
	}
	return readStream(ctx, path, r, opt)
}

// readStream decodes the capture in r; path only labels packets and errors.
func readStream(ctx context.Context, path string, r io.Reader, opt Options) (FileResult, error) {
	src, err := newSource(r)
	if err != nil {
		return FileResult{}, fmt.Errorf("%s: %w", path, err)
	}

	res := FileResult{Path: path}
	d := newDecoder(path)
	for _, mk := range opt.Handlers {
		if h := mk(path); h != nil {
			d.handlers = append(d.handlers, h)
		}
	}
	res.Handlers = d.handlers

	for {
		if res.Packets%ctxCheckInterval == 0 {
			if err := ctx.Err(); err != nil {
				return FileResult{}, fmt.Errorf("%s: %w", path, err)
			}
		}
		rp, err := src.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A capture killed mid-write is common: keep what was read and
			// say so, like tcpdump does, instead of discarding the file.
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: capture ends abruptly at packet %d (%v); %d packets read", path, res.Packets+1, err, res.Packets))
			break
		}
		res.Packets++
		if !d.decode(&rp, res.Packets) {
			res.Skipped++
		}
	}
	for _, h := range d.handlers {
		if f, ok := h.(Finisher); ok {
			f.Finish()
		}
	}
	return res, nil
}
