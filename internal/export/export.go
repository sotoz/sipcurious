// Package export writes a new capture file that contains only selected
// packets of one or more input captures: the SIP messages of chosen calls and
// the RTP/RTCP flows correlated to them. It is the "hand the vendor a trimmed
// pcap of the one broken call" feature.
//
// Packets are copied byte for byte: frame bytes, capture timestamps (full
// nanosecond precision) and link types are those of the input, nothing is
// re-encoded or anonymised. Memory stays bounded: a first pass decodes every
// input (concurrently) only to find the records that belong to the selected
// flows, keeping one bit per record; a second pass streams the selected raw
// records into the output, merged across inputs by capture time.
//
// Because the inputs are read twice they must be regular files (plain or
// gzip): standard input ("-") and pipes cannot be exported, they have to be
// spooled to a temporary file by the caller first.
package export

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/capture"
	"github.com/sotoz/sipcurious/internal/rtp"
)

// snapLen is the snapshot length announced in the output, libpcap's maximum.
const snapLen = 262144

// Errors returned by Write.
var (
	// ErrNoPackets is returned, with nothing written, when the selection
	// matches no packet of the inputs.
	ErrNoPackets = errors.New("export: the selection matches no packet")
	// ErrNotSeekable is returned for standard input and other inputs that
	// cannot be read twice.
	ErrNotSeekable = errors.New("export: input cannot be read twice (standard input or pipe); spool it to a regular file first")
)

// Format is the output capture format.
type Format string

// Output formats.
const (
	// PCAPNG is the default: one interface description per input file and
	// link type, nanosecond timestamps, any mix of link types.
	PCAPNG Format = "pcapng"
	// PCAP is the classic format: a single link type, microsecond timestamps
	// (truncated) unless Options.Nanos is set.
	PCAP Format = "pcap"
)

// ParseFormat parses "pcap" or "pcapng" ("" means pcapng).
func ParseFormat(s string) (Format, error) {
	switch s {
	case "", "pcapng":
		return PCAPNG, nil
	case "pcap":
		return PCAP, nil
	}
	return "", fmt.Errorf("unknown capture format %q (want pcap or pcapng)", s)
}

// Ref names one record of an input capture: the path exactly as given to
// Write and the 1-based record number, the same numbering as
// trace.Message.Index.
type Ref struct {
	File  string
	Index int
}

// tcpTail is how long after the last SIP message of a TCP connection
// SelectCalls keeps exporting that connection, so the segments completing a
// message and its ACK are not cut off.
const tcpTail = time.Second

// Flow identifies one RTP flow to export (or, with TCP, one TCP connection): the UDP datagrams from Src to Dst
// inside the time window [From, To] (a zero bound is open), plus the matching
// RTCP, which is the datagrams between the endpoints with both ports plus one
// (RTCP over RTP port+1) and, with RTCP multiplexing, RTCP packets on Src/Dst
// themselves, each within the window widened by Slack.
//
// A TCP flow matches every TCP segment of the connection between Src and Dst
// in both directions (with or without payload) in [From, To+Slack]; there is
// no RTCP partner. Use it for SIP over TCP, where a message may span several
// segments that Selector.Packets does not name.
type Flow struct {
	TCP      bool   // the flow is a TCP connection instead of UDP media
	File     string // restricts the flow to one input; "" matches in every input
	Src, Dst netip.AddrPort
	From, To time.Time
	Slack    time.Duration // widens the window for RTCP only
}

// Selector says which packets are exported: the union of the listed records
// and everything that matches a flow. SIP messages that were reassembled from
// several TCP segments are selected through the record number of their first
// segment only (trace.Message.Index); later segments are not exported.
type Selector struct {
	// Packets are the records to export, typically the SIP messages.
	Packets map[Ref]struct{}
	// Flows are the media flows to export.
	Flows []Flow
	// AnyDirection makes every flow also match the datagrams travelling from
	// Dst to Src. It is what finds the RTCP receiver reports of one-way media.
	AnyDirection bool
}

// SelectCalls builds the selection of the given calls: every SIP message (for
// messages carried by TCP, the segments of the connection from the call's
// first to its last message on it, which may include other calls' messages on
// a shared connection) and, with includeMedia, every RTP stream correlated to
// them (call.Attach must have run) together with its RTCP, in both
// directions.
func SelectCalls(calls []call.Call, includeMedia bool) Selector {
	sel := Selector{Packets: map[Ref]struct{}{}, AnyDirection: true}
	for i := range calls {
		c := &calls[i]
		var tcp []Flow
		for _, m := range c.Messages {
			sel.Packets[Ref{m.File, m.Index}] = struct{}{}
			if m.Transport != "TCP" {
				continue
			}
			a, b := m.SrcAddr(), m.DstAddr()
			if b.Compare(a) < 0 {
				a, b = b, a
			}
			if k := slices.IndexFunc(tcp, func(f Flow) bool { return f.File == m.File && f.Src == a && f.Dst == b }); k >= 0 {
				tcp[k].From, tcp[k].To = minTime(tcp[k].From, m.Time), maxTime(tcp[k].To, m.Time)
			} else {
				tcp = append(tcp, Flow{TCP: true, File: m.File, Src: a, Dst: b, From: m.Time, To: m.Time, Slack: tcpTail})
			}
		}
		sel.Flows = append(sel.Flows, tcp...)
		if !includeMedia {
			continue
		}
		for _, s := range c.Streams {
			sel.Flows = append(sel.Flows, Flow{File: s.File, Src: s.Src, Dst: s.Dst, From: s.Start, To: s.End, Slack: call.AttachSlack})
		}
	}
	return sel
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// Options configures Write.
type Options struct {
	// Format is the output format; the zero value means PCAPNG.
	Format Format
	// Nanos makes PCAP output carry nanosecond timestamps (magic
	// 0xa1b23c4d) instead of truncating to microseconds. PCAPNG output always
	// has nanosecond resolution.
	Nanos bool
}

// Stats describes what Write did.
type Stats struct {
	Inputs     int       // input files
	Read       int       // records read in the copy pass (reading stops after the last selected one)
	Written    int       // records written
	SIP        int       // written because they were listed in Selector.Packets
	Flows      int       // written because they matched a flow
	Missing    int       // listed records that do not exist in their input
	Bytes      int64     // size of the output
	Interfaces int       // pcapng interface descriptions written (1 for pcap)
	First      time.Time // timestamp of the first written record
	Last       time.Time // timestamp of the last written record
	Warnings   []string  // non-fatal problems such as an input cut off mid-record
}

// Write copies the selected records of the inputs to w. Records are written
// in capture-time order: the inputs are merged by timestamp (each input's own
// record order is kept even if its timestamps are not monotonic), records of
// equal time keep input order. Lengths are preserved, except that a record whose captured length
// exceeds its original length (a defect of some producers) gets the captured
// length as original length. If no record is selected Write writes nothing
// and returns ErrNoPackets. PCAP output fails when the selected records do not
// share one link type, possibly after part of the output was written.
func Write(ctx context.Context, w io.Writer, inputs []string, sel Selector, opt Options) (Stats, error) {
	st := Stats{Inputs: len(inputs)}
	if opt.Format == "" {
		opt.Format = PCAPNG
	}
	if opt.Format != PCAP && opt.Format != PCAPNG {
		return st, fmt.Errorf("export: unknown format %q", opt.Format)
	}
	for _, p := range inputs {
		fi, err := os.Stat(p)
		if p == "-" || (err == nil && !fi.Mode().IsRegular()) {
			return st, fmt.Errorf("%s: %w", p, ErrNotSeekable)
		}
		if err != nil {
			return st, fmt.Errorf("%s: %w", p, err)
		}
	}

	files, warns, err := selectRecords(ctx, inputs, sel)
	if err != nil {
		return st, err
	}

	st.Warnings = warns
	out := &countWriter{w: w}
	ow := &outWriter{opt: opt, w: out}
	srcs := make([]*source, 0, len(files))
	for i := range files {
		if files[i].empty() {
			continue
		}
		s := &source{file: &files[i], idx: i}
		s.next, s.stop = iter.Pull(s.seq(ctx))
		defer s.stop()
		s.advance()
		srcs = append(srcs, s)
	}

	for {
		var best *source
		for _, s := range srcs {
			if s.ok && (best == nil || s.head.Time.Before(best.head.Time)) {
				best = s
			}
		}
		if best == nil {
			break
		}
		if err := ow.write(best); err != nil {
			return st, fmt.Errorf("export: %w", err)
		}
		best.advance()
	}
	for _, s := range srcs {
		if s.err != nil {
			if errors.Is(s.err, capture.ErrTruncated) {
				st.Warnings = append(st.Warnings, s.err.Error())
				continue
			}
			return st, s.err
		}
	}
	for i := range files {
		st.Read += files[i].nRead
		st.SIP += files[i].nSIP
		st.Flows += files[i].nFlows
		st.Missing += files[i].refs.count - files[i].nSIP
	}
	st.Written = st.SIP + st.Flows
	if st.Written == 0 {
		return st, ErrNoPackets
	}
	if err := ow.flush(); err != nil {
		return st, fmt.Errorf("export: %w", err)
	}
	st.Bytes, st.Interfaces, st.First, st.Last = out.n, ow.interfaces(), ow.first, ow.last
	return st, nil
}

// fileSel is what is selected from one input.
type fileSel struct {
	path        string
	refs, flows bitset // records selected by Packets and by Flows
	last        int    // highest selected record number

	nRead, nSIP, nFlows int // counters of the copy pass
}

func (f *fileSel) empty() bool { return f.last == 0 }

// selectRecords resolves the selector against the inputs: Packets by record
// number, Flows by decoding every input once.
func selectRecords(ctx context.Context, inputs []string, sel Selector) ([]fileSel, []string, error) {
	files := make([]fileSel, len(inputs))
	byPath := make(map[string]int, len(inputs))
	for i, p := range inputs {
		files[i].path = p
		if j, dup := byPath[filepath.Clean(p)]; dup {
			return nil, nil, fmt.Errorf("export: input %s listed twice (positions %d and %d)", p, j+1, i+1)
		}
		byPath[filepath.Clean(p)] = i
	}
	lookup := func(path string) (int, bool) {
		i, ok := byPath[filepath.Clean(path)]
		return i, ok
	}
	for r := range sel.Packets {
		i, ok := lookup(r.File)
		if !ok {
			return nil, nil, fmt.Errorf("export: selected record %s#%d is not in the inputs", r.File, r.Index)
		}
		if r.Index < 1 {
			return nil, nil, fmt.Errorf("export: invalid record number %d in %s", r.Index, r.File)
		}
		files[i].refs.set(r.Index)
	}
	for _, f := range sel.Flows {
		if f.File != "" {
			if _, ok := lookup(f.File); !ok {
				return nil, nil, fmt.Errorf("export: selected flow refers to %s which is not in the inputs", f.File)
			}
		}
	}

	var warns []string
	if len(sel.Flows) > 0 {
		res, err := capture.Read(ctx, inputs, capture.Options{Handlers: []capture.Factory{func(path string) capture.Handler {
			return newMatcher(path, sel, lookup)
		}}})
		if err != nil {
			return nil, nil, err
		}
		warns = res.Warnings
		for i, fr := range res.Files {
			files[i].flows = fr.Handlers[0].(*matcher).hits
		}
	}
	for i := range files {
		files[i].last = max(files[i].refs.max(), files[i].flows.max())
	}
	return files, warns, nil
}

// source is one input in the merge: a pull iterator over its selected
// records. head.Data stays valid until advance is called.
type source struct {
	file *fileSel
	idx  int
	next func() (capture.RawPacket, bool)
	stop func()
	head capture.RawPacket
	ok   bool
	err  error
}

func (s *source) advance() { s.head, s.ok = s.next() }

// seq yields the selected records of the file in file order.
func (s *source) seq(ctx context.Context) iter.Seq[capture.RawPacket] {
	return func(yield func(capture.RawPacket) bool) {
		f := s.file
		s.err = capture.ReadRaw(ctx, f.path, func(p capture.RawPacket) bool {
			f.nRead++
			ref := f.refs.has(p.Index)
			if !ref && !f.flows.has(p.Index) {
				return true
			}
			if ref {
				f.nSIP++
			} else {
				f.nFlows++
			}
			return yield(p) && p.Index < f.last
		})
	}
}

// outWriter writes records in either format, creating the container lazily
// from the first record.
type outWriter struct {
	opt   Options
	w     *countWriter
	buf   *bufio.Writer
	pcap  *pcapgo.Writer
	ng    *pcapgo.NgWriter
	lt    layers.LinkType
	ifs   map[ifKey]int
	first time.Time
	last  time.Time
}

type ifKey struct {
	file int
	lt   layers.LinkType
}

func (o *outWriter) interfaces() int {
	if o.ng != nil {
		return len(o.ifs)
	}
	return 1
}

func (o *outWriter) write(s *source) error {
	p := s.head
	ci := gopacket.CaptureInfo{Timestamp: p.Time, CaptureLength: len(p.Data), Length: max(p.OrigLen, len(p.Data))}
	if o.first.IsZero() {
		o.first = p.Time
	}
	o.last = p.Time
	if o.opt.Format == PCAP {
		if o.pcap == nil {
			o.buf = bufio.NewWriterSize(o.w, 1<<18)
			if o.opt.Nanos {
				o.pcap = pcapgo.NewWriterNanos(o.buf)
			} else {
				o.pcap = pcapgo.NewWriter(o.buf)
			}
			o.lt = p.LinkType
			if err := o.pcap.WriteFileHeader(snapLen, p.LinkType); err != nil {
				return err
			}
		} else if p.LinkType != o.lt {
			return fmt.Errorf("pcap output needs one link type, found %v and %v: use pcapng", o.lt, p.LinkType)
		}
		return o.pcap.WritePacket(ci, p.Data)
	}

	key := ifKey{s.idx, p.LinkType}
	intf := pcapgo.NgInterface{
		Name:                filepath.Base(s.file.path),
		Description:         p.LinkType.String(),
		LinkType:            p.LinkType,
		TimestampResolution: 9,
		SnapLength:          snapLen, // libpcap-based readers reject a record longer than snaplen 0
	}
	if o.ng == nil {
		ng, err := pcapgo.NewNgWriterInterface(o.w, intf, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: "sipcurious export", Comment: "trimmed copy; frames and timestamps are unmodified"}})
		if err != nil {
			return err
		}
		o.ng, o.ifs = ng, map[ifKey]int{key: 0}
	}
	id, ok := o.ifs[key]
	if !ok {
		var err error
		if id, err = o.ng.AddInterface(intf); err != nil {
			return err
		}
		o.ifs[key] = id
	}
	ci.InterfaceIndex = id
	return o.ng.WritePacket(ci, p.Data)
}

func (o *outWriter) flush() error {
	switch {
	case o.ng != nil:
		return o.ng.Flush()
	case o.buf != nil:
		return o.buf.Flush()
	}
	return nil
}

// countWriter counts the bytes passed to w.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// matcher is the capture.Handler of the first pass: it never consumes a
// packet, it only notes the records that belong to a flow.
type matcher struct {
	flows map[epPair][]window // UDP
	tcp   map[epPair][]window
	hits  bitset
}

type epPair struct{ src, dst netip.AddrPort }

// window is a time interval (zero bounds are open) in which a datagram on the
// key matches; rtcpOnly additionally requires an RTCP payload.
type window struct {
	from, to time.Time
	rtcpOnly bool
}

func (w window) contains(t time.Time) bool {
	return (w.from.IsZero() || !t.Before(w.from)) && (w.to.IsZero() || !t.After(w.to))
}

func newMatcher(path string, sel Selector, lookup func(string) (int, bool)) *matcher {
	m := &matcher{flows: map[epPair][]window{}, tcp: map[epPair][]window{}}
	self, _ := lookup(path)
	for _, f := range sel.Flows {
		if f.File != "" {
			if i, _ := lookup(f.File); i != self {
				continue
			}
		}
		if !f.Src.IsValid() || !f.Dst.IsValid() {
			continue
		}
		src := netip.AddrPortFrom(f.Src.Addr().Unmap(), f.Src.Port())
		dst := netip.AddrPortFrom(f.Dst.Addr().Unmap(), f.Dst.Port())
		strict := window{from: f.From, to: f.To}
		if f.TCP {
			if f.Slack > 0 && !f.To.IsZero() {
				strict.to = f.To.Add(f.Slack)
			}
			m.tcp[epPair{src, dst}] = append(m.tcp[epPair{src, dst}], strict)
			m.tcp[epPair{dst, src}] = append(m.tcp[epPair{dst, src}], strict)
			continue
		}
		wide := window{from: f.From, to: f.To, rtcpOnly: true}
		if f.Slack > 0 {
			if !f.From.IsZero() {
				wide.from = f.From.Add(-f.Slack)
			}
			if !f.To.IsZero() {
				wide.to = f.To.Add(f.Slack)
			}
		}
		add := func(a, b netip.AddrPort) {
			m.flows[epPair{a, b}] = append(m.flows[epPair{a, b}], strict)
			if f.Slack > 0 {
				m.flows[epPair{a, b}] = append(m.flows[epPair{a, b}], wide)
			}
			if a.Port() < 65535 && b.Port() < 65535 {
				pa, pb := netip.AddrPortFrom(a.Addr(), a.Port()+1), netip.AddrPortFrom(b.Addr(), b.Port()+1)
				m.flows[epPair{pa, pb}] = append(m.flows[epPair{pa, pb}], wide)
			}
		}
		add(src, dst)
		if sel.AnyDirection {
			add(dst, src)
		}
	}
	return m
}

// Handle implements capture.Handler.
func (m *matcher) Handle(p *capture.Packet) bool {
	var ws []window
	switch p.Transport {
	case "UDP":
		ws = m.flows[epPair{netip.AddrPortFrom(p.Src, p.SrcPort), netip.AddrPortFrom(p.Dst, p.DstPort)}]
	case "TCP":
		ws = m.tcp[epPair{netip.AddrPortFrom(p.Src, p.SrcPort), netip.AddrPortFrom(p.Dst, p.DstPort)}]
	default:
		return false
	}
	for _, w := range ws {
		if w.contains(p.Time) && (!w.rtcpOnly || rtp.IsRTCP(p.Payload)) {
			m.hits.set(p.Index)
			break
		}
	}
	return false
}

// bitset is a growable set of positive integers.
type bitset struct {
	w     []uint64
	count int
}

func (b *bitset) set(i int) {
	if i < 0 {
		return
	}
	if n := i/64 + 1; n > len(b.w) {
		b.w = append(b.w, make([]uint64, n-len(b.w))...)
	}
	if bit := uint64(1) << (i % 64); b.w[i/64]&bit == 0 {
		b.w[i/64] |= bit
		b.count++
	}
}

func (b *bitset) has(i int) bool {
	return i >= 0 && i/64 < len(b.w) && b.w[i/64]&(1<<(i%64)) != 0
}

// max returns the largest member, 0 if empty.
func (b *bitset) max() int {
	for k := len(b.w) - 1; k >= 0; k-- {
		if v := b.w[k]; v != 0 {
			for bit := 63; bit >= 0; bit-- {
				if v&(1<<bit) != 0 {
					return k*64 + bit
				}
			}
		}
	}
	return 0
}
