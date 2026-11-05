package capture

import (
	"net/netip"
	"time"
)

// Packet is one decoded transport-layer datagram or segment handed to the
// registered Handlers. It is reused between calls: Payload (and the Packet
// itself) is only valid during Handle, copy what you keep.
type Packet struct {
	File  string    // path as given ("-" for stdin)
	Index int       // 1-based packet number inside File
	Time  time.Time // capture timestamp (UTC)

	Src, Dst         netip.Addr // innermost IP header (IPv4-mapped IPv6 already unmapped)
	SrcPort, DstPort uint16
	Transport        string // "UDP", "TCP" or "SCTP"

	// TCP only: sequence number of the first payload byte, and the SYN/FIN/RST flags,
	// so handlers can reassemble streams.
	TCPSeq                 uint32
	TCPSYN, TCPFIN, TCPRST bool

	Payload []byte // transport payload (IP fragments already reassembled)
	Partial bool   // the capture snaplen cut the payload short
}

// Handler consumes decoded packets of ONE file, in packet order, from one
// goroutine (no locking needed). Handlers are the extension point for new
// protocols: SIP and RTP are handlers, not special cases.
type Handler interface {
	// Handle inspects p and reports whether it recognised and consumed it.
	// Handlers are tried in registration order; the first one that returns
	// true wins and later handlers do not see the packet. Packets nobody
	// consumes are counted as skipped.
	Handle(p *Packet) bool
}

// Finisher is optionally implemented by handlers that need to flush state
// (e.g. half-assembled TCP messages) after the last packet of a file.
type Finisher interface{ Finish() }

// Factory creates a fresh Handler for one capture file. Files are read
// concurrently, so handlers must not share mutable state between files.
type Factory func(file string) Handler

// Options configures Read.
type Options struct {
	// Handlers are the per-file handler factories, in priority order.
	Handlers []Factory
}

// FileResult is what happened to one input file.
type FileResult struct {
	Path     string
	Packets  int       // packets read from the file
	Skipped  int       // packets no handler consumed
	Warnings []string  // non-fatal problems such as a capture cut off mid-record
	Handlers []Handler // the file's handler instances, same order as Options.Handlers, for result extraction
}

// Result is the outcome of reading one or more capture files.
type Result struct {
	Packets  int
	Skipped  int
	Warnings []string
	Files    []FileResult // same order as the input paths
}

// HandlersOf returns, in file order, every handler of concrete type T that
// took part in the read.
func HandlersOf[T Handler](r Result) []T {
	var out []T
	for _, f := range r.Files {
		for _, h := range f.Handlers {
			if t, ok := h.(T); ok {
				out = append(out, t)
			}
		}
	}
	return out
}
