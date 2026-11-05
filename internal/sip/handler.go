package sip

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/sotoz/sipcurious/internal/capture"
	"github.com/sotoz/sipcurious/internal/trace"
)

// Limits that keep the memory of the TCP reassembly bounded.
const (
	// maxFlows is the number of TCP directions tracked at once; beyond it the
	// least recently used quarter is flushed and forgotten.
	maxFlows = 1024
	// maxOOOSegments and maxOOOBytes bound the out-of-order segments held per
	// flow while waiting for a gap to be filled.
	maxOOOSegments = 16
	maxOOOBytes    = 32 << 10
	// maxStartLine is the longest start line looked for in a stream.
	maxStartLine = 4096
	// retainBuf is the largest message buffer kept between messages.
	retainBuf = 8 << 10
)

// Handler is the capture.Handler that extracts SIP messages from the packets
// of one capture file.
//
// UDP and SCTP: one message per datagram or DATA chunk; payloads that do not
// start with a SIP start line (keep-alives, RTP, STUN, ...) are not consumed.
//
// TCP: the byte stream of every direction of every connection is
// reassembled. Messages are framed by Content-Length (compact form "l"; a
// missing header means no body), so several messages in one segment and
// messages split over many segments both work. Retransmitted bytes are
// dropped by sequence number, a modest number of out-of-order segments is
// reordered, and after loss or garbage the stream is re-synchronised on the
// next line that is a SIP start line. A stream is only followed once such a
// start line was seen, so TLS, HTTP and other TCP traffic costs no state and
// a capture that begins mid-message simply starts at the first full message.
// A message cut short by loss, FIN/RST, the end of the file or a snaplen cut
// is reported with whatever arrived (a cut header line is dropped, see
// TrimPartial). The streams are bounded: a message keeps at most
// MaxMessageSize bytes (the rest of its body is skipped), and the number of
// tracked connections is limited, the least recently used ones are flushed.
//
// Message.Index and Message.Time are those of the packet that carried the
// first byte of the message, so a message split over several packets is
// placed where it began; messages are returned ordered by that index.
type Handler struct {
	file  string
	opt   ParseOptions
	msgs  []trace.Message
	dirty bool // msgs may be out of Index order

	flows map[flowKey]*tcpFlow
	tick  uint64
}

// NewHandler returns the capture factory creating one SIP Handler per file.
// Get the messages back with capture.HandlersOf[*sip.Handler](result).
func NewHandler(opt ParseOptions) capture.Factory {
	return func(file string) capture.Handler { return &Handler{file: file, opt: opt} }
}

// Messages returns the SIP messages found so far, in packet order (by the
// index of the packet that started them). The slice is owned by the Handler.
func (h *Handler) Messages() []trace.Message {
	if h.dirty {
		slices.SortStableFunc(h.msgs, func(a, b trace.Message) int { return a.Index - b.Index })
		h.dirty = false
	}
	return h.msgs
}

// Handle implements capture.Handler.
func (h *Handler) Handle(p *capture.Packet) bool {
	switch p.Transport {
	case "UDP", "SCTP":
		payload := p.Payload
		if p.Partial {
			payload = TrimPartial(payload)
		}
		m, ok := Parse(payload, h.opt)
		if !ok {
			return false
		}
		m.File, m.Index, m.Time = p.File, p.Index, p.Time
		m.Src, m.Dst, m.SrcPort, m.DstPort, m.Transport = p.Src, p.Dst, p.SrcPort, p.DstPort, p.Transport
		h.add(m)
		return true
	case "TCP":
		return h.handleTCP(p)
	}
	return false
}

// Finish implements capture.Finisher: it flushes every half-assembled message.
func (h *Handler) Finish() {
	for _, fl := range h.sortedFlows() {
		h.closeFlow(fl)
	}
	clear(h.flows)
}

func (h *Handler) add(m trace.Message) {
	if n := len(h.msgs); n > 0 && h.msgs[n-1].Index > m.Index {
		h.dirty = true
	}
	h.msgs = append(h.msgs, m)
}

// origin is the packet a message started in.
type origin struct {
	index int
	time  time.Time
}

type flowKey struct {
	src, dst         netip.Addr
	srcPort, dstPort uint16
}

// oooSeg is a segment that arrived ahead of a gap.
type oooSeg struct {
	seq  uint32
	data []byte
	at   origin
}

// tcpFlow is the reassembly state of one direction of a TCP connection.
type tcpFlow struct {
	key    flowKey
	synced bool   // next is valid
	next   uint32 // sequence number of the next byte expected
	used   uint64 // LRU tick

	buf      []byte // bytes of the open (incomplete) message, starting at its start line
	at       origin // packet that carried the first byte of buf
	scan     int    // buf has no blank line before this offset
	skip     int    // body bytes of an oversized message still to discard
	boundary bool   // the stream is at the start of a line (a message boundary, or after a dropped garbage line)

	ooo      []oooSeg
	oooBytes int
}

func (h *Handler) handleTCP(p *capture.Packet) bool {
	key := flowKey{p.Src, p.Dst, p.SrcPort, p.DstPort}
	fl := h.flows[key]
	seq := p.TCPSeq
	if p.TCPSYN {
		seq++          // the SYN occupies one sequence number; fast-open data follows it
		if fl != nil { // a new connection reusing the 4-tuple
			h.closeFlow(fl)
			delete(h.flows, key)
			fl = nil
		}
	}
	data := p.Payload
	closing := p.TCPFIN || p.TCPRST

	if len(data) == 0 {
		if fl != nil && closing {
			h.closeFlow(fl)
			delete(h.flows, key)
		}
		return false
	}

	at := origin{p.Index, p.Time}
	if fl == nil || !fl.synced {
		// Not following this stream (yet): start at the first start line.
		off := findStart(data)
		if off < 0 {
			off = partialStart(data)
		}
		if off < 0 {
			return false
		}
		if fl == nil {
			fl = h.newFlow(key)
		}
		fl.synced, fl.next, fl.boundary = true, seq+uint32(off), true
		data, seq = data[off:], seq+uint32(off)
	}
	h.tick++
	fl.used = h.tick

	consumed := h.segment(fl, seq, data, at)
	if p.Partial {
		// The payload is cut short: the real sequence number of the next
		// segment is unknown, so give up this stream position.
		h.closeFlow(fl)
		fl.synced = false
	}
	if closing {
		h.closeFlow(fl)
		delete(h.flows, key)
	}
	return consumed
}

func (h *Handler) newFlow(key flowKey) *tcpFlow {
	if h.flows == nil {
		h.flows = make(map[flowKey]*tcpFlow)
	}
	if len(h.flows) >= maxFlows {
		h.evict()
	}
	fl := &tcpFlow{key: key}
	h.flows[key] = fl
	return fl
}

// evict flushes and forgets the least recently used quarter of the flows.
func (h *Handler) evict() {
	all := h.sortedFlows()
	slices.SortStableFunc(all, func(a, b *tcpFlow) int {
		switch {
		case a.used < b.used:
			return -1
		case a.used > b.used:
			return 1
		}
		return 0
	})
	for _, fl := range all[:max(1, len(all)/4)] {
		h.closeFlow(fl)
		delete(h.flows, fl.key)
	}
}

// sortedFlows returns the flows in a deterministic order (by the packet that
// began their open message, then by key bytes) so that output never depends
// on map iteration.
func (h *Handler) sortedFlows() []*tcpFlow {
	out := make([]*tcpFlow, 0, len(h.flows))
	for _, fl := range h.flows {
		out = append(out, fl)
	}
	slices.SortFunc(out, func(a, b *tcpFlow) int {
		if c := a.at.index - b.at.index; c != 0 {
			return c
		}
		if c := a.key.src.Compare(b.key.src); c != 0 {
			return c
		}
		if c := a.key.dst.Compare(b.key.dst); c != 0 {
			return c
		}
		if c := int(a.key.srcPort) - int(b.key.srcPort); c != 0 {
			return c
		}
		return int(a.key.dstPort) - int(b.key.dstPort)
	})
	return out
}

// closeFlow processes whatever is still waiting out of order, flushes the
// open message and resets the stream state.
func (h *Handler) closeFlow(fl *tcpFlow) {
	h.forceDrain(fl)
	h.flushPartial(fl)
	fl.boundary = false
}

// segment feeds one segment of an established flow and reports whether it
// belonged to the SIP stream.
func (h *Handler) segment(fl *tcpFlow, seq uint32, data []byte, at origin) bool {
	used := true
	switch back := fl.next - seq; {
	case back == 0:
		used = h.accept(fl, data, at)
	case back < 1<<31:
		if int(back) >= len(data) {
			return true // retransmission of bytes already seen
		}
		used = h.accept(fl, data[back:], at)
	default:
		// A gap: keep the segment until the missing bytes arrive.
		if len(fl.ooo) >= maxOOOSegments || fl.oooBytes+len(data) > maxOOOBytes {
			h.forceDrain(fl) // the missing bytes are not coming
		}
		if len(data) > maxOOOBytes { // larger than the whole reorder budget
			h.flushPartial(fl)
			fl.boundary = false
			fl.next = seq
			return h.accept(fl, data, at)
		}
		fl.ooo = append(fl.ooo, oooSeg{seq, bytes.Clone(data), at})
		fl.oooBytes += len(data)
		return true
	}
	h.drain(fl)
	return used
}

// drain feeds the stored segments that have become contiguous.
func (h *Handler) drain(fl *tcpFlow) {
	for len(fl.ooo) > 0 {
		i := fl.nearest()
		seg := fl.ooo[i]
		if int32(seg.seq-fl.next) > 0 {
			return
		}
		fl.removeOOO(i)
		if back := fl.next - seg.seq; int(back) < len(seg.data) {
			h.accept(fl, seg.data[back:], seg.at)
		}
	}
}

// forceDrain feeds every stored segment in sequence order, treating the
// remaining gaps as lost bytes (the message crossing a gap is flushed as it
// is and the stream re-synchronises behind it).
func (h *Handler) forceDrain(fl *tcpFlow) {
	for len(fl.ooo) > 0 {
		i := fl.nearest()
		seg := fl.ooo[i]
		fl.removeOOO(i)
		if int32(seg.seq-fl.next) > 0 {
			h.flushPartial(fl)
			fl.boundary = false
			fl.next = seg.seq
		}
		if back := fl.next - seg.seq; int(back) < len(seg.data) {
			h.accept(fl, seg.data[back:], seg.at)
		}
	}
}

// nearest returns the index of the stored segment closest to next.
func (fl *tcpFlow) nearest() int {
	best := 0
	for i := 1; i < len(fl.ooo); i++ {
		if int32(fl.ooo[i].seq-fl.next) < int32(fl.ooo[best].seq-fl.next) {
			best = i
		}
	}
	return best
}

func (fl *tcpFlow) removeOOO(i int) {
	fl.oooBytes -= len(fl.ooo[i].data)
	fl.ooo = slices.Delete(fl.ooo, i, i+1)
	if len(fl.ooo) == 0 {
		fl.ooo = nil
	}
}

// flushPartial reports the open message with what has arrived and clears it.
func (h *Handler) flushPartial(fl *tcpFlow) {
	if len(fl.buf) > 0 {
		raw := fl.buf
		if !hasBlank(raw, 0) {
			raw = TrimPartial(raw)
		}
		h.emit(fl, raw, fl.at)
	}
	fl.reset()
}

func (fl *tcpFlow) reset() {
	fl.buf = fl.buf[:0]
	if cap(fl.buf) > retainBuf {
		fl.buf = nil
	}
	fl.scan, fl.skip = 0, 0
}

// emit parses one framed message and records it.
func (h *Handler) emit(fl *tcpFlow, raw []byte, at origin) {
	m, ok := Parse(raw, h.opt)
	if !ok {
		return
	}
	m.Index, m.Time = at.index, at.time
	m.Src, m.Dst, m.SrcPort, m.DstPort = fl.key.src, fl.key.dst, fl.key.srcPort, fl.key.dstPort
	m.Transport = "TCP"
	m.File = h.file
	h.add(m)
}

type frameState int8

const (
	frameOK        frameState = iota // a complete message
	frameNeedStart                   // the start line is not complete yet
	frameNeedHdrs                    // valid start line, headers not complete
	frameNeedBody                    // headers complete, body not complete
	frameBad                         // not the start of a SIP message
)

// frame looks at the stream bytes win, which must begin at a message
// boundary. For frameOK, n is the number of bytes of the message to keep and
// skipAfter the number of body bytes beyond MaxMessageSize that follow them.
// from is an offset before which win is known to contain no blank line.
func frame(win []byte, from int) (n, skipAfter int, st frameState) {
	nl := bytes.IndexByte(win, '\n')
	if nl < 0 {
		if len(win) > maxStartLine {
			return 0, 0, frameBad
		}
		return 0, 0, frameNeedStart
	}
	if nl > maxStartLine || !startLine(win[:nl]) {
		return 0, 0, frameBad
	}
	if !hasBlank(win, from) {
		if len(win) >= MaxMessageSize {
			return 0, 0, frameBad
		}
		return 0, 0, frameNeedHdrs
	}
	hs := scanHeaders(win)
	if hs.end > MaxMessageSize {
		return 0, 0, frameBad
	}
	total := hs.end + hs.contentLength
	keep := min(total, MaxMessageSize)
	if len(win) < keep {
		return 0, 0, frameNeedBody
	}
	return keep, total - keep, frameOK
}

// accept appends in-order stream bytes to the flow and emits every message
// they complete.
func (h *Handler) accept(fl *tcpFlow, data []byte, at origin) (used bool) {
	fl.next += uint32(len(data))
	if fl.skip > 0 {
		n := min(fl.skip, len(data))
		fl.skip -= n
		data = data[n:]
		used = true
	}
	if len(data) == 0 {
		return used
	}
	win, curAt := data, at
	first := len(fl.buf) > 0 // win begins with the open message
	if first {
		fl.buf = append(fl.buf, data...)
		win, curAt = fl.buf, fl.at
	}

	if first {
		used = true
	}
	pos, keep := 0, false
	scan := 0
	if first {
		scan = fl.scan
	}
loop:
	for pos < len(win) {
		if fl.skip > 0 {
			n := min(fl.skip, len(win)-pos)
			fl.skip -= n
			pos += n
			used = true
			continue
		}
		if !first { // CR/LF between messages are keep-alives
			for pos < len(win) && (win[pos] == '\r' || win[pos] == '\n') {
				pos++
			}
			if pos == len(win) {
				break
			}
		}
		rest := win[pos:]
		n, skipAfter, st := frame(rest, scan)
		switch st {
		case frameOK:
			h.emit(fl, rest[:n], curAt)
			used = true
			pos += n
			fl.skip, fl.boundary = skipAfter, true
			first, curAt, scan = false, at, 0
		case frameNeedHdrs, frameNeedBody:
			keep, used = true, true
			if st == frameNeedHdrs {
				scan = max(0, len(rest)-3)
			} else {
				scan = 0
			}
			break loop
		case frameNeedStart:
			if first || fl.boundary {
				keep, used = true, true
				scan = 0
				break loop
			}
			pos = len(win) // garbage without a line end
		default: // frameBad: drop this line and look at the next one
			if j := bytes.IndexByte(rest, '\n'); j >= 0 {
				pos += j + 1
				fl.boundary = true
			} else {
				pos = len(win)
				fl.boundary = false
			}
			first, curAt, scan = false, at, 0
		}
	}

	if !keep {
		fl.reset()
		return used
	}
	left := win[pos:]
	startsNew := pos > 0 || !first
	if first {
		n := copy(fl.buf, left)
		fl.buf = fl.buf[:n]
	} else {
		fl.buf = append(fl.buf[:0], left...)
	}
	if startsNew {
		fl.at = at
	} else {
		fl.at = curAt
	}
	fl.scan = scan
	return used
}

// hasBlank reports whether b holds an empty line (the end of the headers) at
// or after offset from.
func hasBlank(b []byte, from int) bool {
	for i := from; i < len(b); {
		j := bytes.IndexByte(b[i:], '\n')
		if j < 0 {
			return false
		}
		i += j + 1
		if i < len(b) && (b[i] == '\n' || b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n') {
			return true
		}
	}
	return false
}

// findStart returns the offset of the first line of data that is a SIP start
// line, or -1.
func findStart(data []byte) int {
	for pos := 0; pos < len(data); {
		rest := data[pos:]
		nl := bytes.IndexByte(rest, '\n')
		line := rest
		if nl >= 0 {
			line = rest[:nl]
		}
		if len(line) > 0 && startLine(line) {
			return pos
		}
		if nl < 0 {
			return -1
		}
		pos += nl + 1
	}
	return -1
}

// sipMethods are the methods recognised when a start line is split over
// segments and only its beginning is visible (RFC 3261 and the common
// extensions). A full start line is accepted for any token method.
var sipMethods = []string{
	"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "INFO", "PRACK", "SUBSCRIBE",
	"NOTIFY", "PUBLISH", "REFER", "MESSAGE", "UPDATE", "SIP/2.0",
}

// partialStart returns the offset of an incomplete last line of data that is
// the beginning of a SIP start line of a well-known method (a message whose
// start line is split over segments), or -1. It is deliberately strict:
// HTTP and other text protocols must not make a stream look like SIP.
func partialStart(data []byte) int {
	off := bytes.LastIndexByte(data, '\n') + 1
	tail := data[off:]
	if len(tail) == 0 || len(tail) >= maxStartLine {
		return -1
	}
	for _, c := range tail {
		if c < 0x20 && c != '\t' || c >= 0x7f {
			return -1
		}
	}
	word, _, hasSpace := bytes.Cut(tail, []byte{' '})
	for _, m := range sipMethods {
		if hasSpace && string(word) == m || !hasSpace && strings.HasPrefix(m, string(word)) {
			return off
		}
	}
	return -1
}

// startLine reports whether line (without its LF) is a SIP start line.
func startLine(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	var m trace.Message
	return parseStartLine(unsafe.String(unsafe.SliceData(line), len(line)), &m)
}
