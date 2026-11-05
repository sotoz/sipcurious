package capture_test

// Shared builders for synthetic captures. Everything is assembled byte by
// byte (not through the gopacket decoder types) so tests control every header
// field, including deliberately odd ones, and the expected values in the tests
// are derived from the inputs rather than from what the tool prints.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/sotoz/sipcurious/internal/trace"
)

// ---------------------------------------------------------------- checksums

func pbSum(b []byte, sum uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func pbFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func pbPseudo(src, dst netip.Addr, proto byte, n int) []byte {
	p := append(src.AsSlice(), dst.AsSlice()...)
	if src.Is4() {
		return append(p, 0, proto, byte(n>>8), byte(n))
	}
	return append(p, 0, 0, byte(n>>8), byte(n), 0, 0, 0, proto)
}

// ---------------------------------------------------------------- transport

const (
	pbProtoTCP  = 6
	pbProtoUDP  = 17
	pbProtoSCTP = 132
)

// TCP flag bits.
const (
	pbFIN = 0x01
	pbSYN = 0x02
	pbRST = 0x04
	pbPSH = 0x08
	pbACK = 0x10
)

func pbUDP(src, dst netip.Addr, sp, dp uint16, payload []byte) []byte {
	n := 8 + len(payload)
	b := make([]byte, 8, n)
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	binary.BigEndian.PutUint16(b[4:], uint16(n))
	b = append(b, payload...)
	c := pbFold(pbSum(b, pbSum(pbPseudo(src, dst, pbProtoUDP, n), 0)))
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(b[6:], c)
	return b
}

func pbTCP(src, dst netip.Addr, sp, dp uint16, seq uint32, flags byte, payload []byte) []byte {
	n := 20 + len(payload)
	b := make([]byte, 20, n)
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], 1)
	b[12] = 5 << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:], 8192)
	b = append(b, payload...)
	binary.BigEndian.PutUint16(b[16:], pbFold(pbSum(b, pbSum(pbPseudo(src, dst, pbProtoTCP, n), 0))))
	return b
}

// pbSCTPChunk builds one SCTP chunk (padded to 4 bytes).
func pbSCTPChunk(typ, flags byte, body []byte) []byte {
	n := 4 + len(body)
	b := []byte{typ, flags, byte(n >> 8), byte(n)}
	b = append(b, body...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// pbSCTPData builds a DATA chunk (B and E flags set) carrying payload.
func pbSCTPData(tsn uint32, stream uint16, payload []byte) []byte {
	body := make([]byte, 12, 12+len(payload))
	binary.BigEndian.PutUint32(body[0:], tsn)
	binary.BigEndian.PutUint16(body[4:], stream)
	// ssn = 0, ppid = 0
	body = append(body, payload...)
	return pbSCTPChunk(0, 0x03, body)
}

// pbSCTP builds an SCTP packet from chunks, with a valid CRC32c.
func pbSCTP(sp, dp uint16, chunks ...[]byte) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	binary.BigEndian.PutUint32(b[4:], 0xdeadbeef) // verification tag
	for _, c := range chunks {
		b = append(b, c...)
	}
	binary.LittleEndian.PutUint32(b[8:], crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
	return b
}

// ------------------------------------------------------------------ network

type pbIP4Opts struct {
	id      uint16
	frag    uint16 // flags (3 bits) << 13 | fragment offset in 8-byte units
	options []byte // must be a multiple of 4 bytes
}

func pbIPv4(src, dst netip.Addr, proto byte, payload []byte, o pbIP4Opts) []byte {
	ihl := 5 + len(o.options)/4
	b := make([]byte, 20, ihl*4+len(payload))
	b[0] = 0x40 | byte(ihl)
	binary.BigEndian.PutUint16(b[2:], uint16(ihl*4+len(payload)))
	binary.BigEndian.PutUint16(b[4:], o.id)
	binary.BigEndian.PutUint16(b[6:], o.frag)
	b[8] = 64
	b[9] = proto
	copy(b[12:], src.AsSlice())
	copy(b[16:], dst.AsSlice())
	b = append(b, o.options...)
	binary.BigEndian.PutUint16(b[10:], pbFold(pbSum(b, 0)))
	return append(b, payload...)
}

// pbExt6 is an IPv6 extension header: kind is its protocol number and body is
// everything after the two leading (next header, length) bytes. 2+len(body)
// must be a multiple of 8.
type pbExt6 struct {
	kind byte
	body []byte
}

// pbPad6 returns n-2 bytes of PadN option filling an extension header body.
func pbPad6(n int) []byte {
	if n == 0 {
		return nil
	}
	if n == 1 {
		return []byte{0}
	}
	return append([]byte{1, byte(n - 2)}, make([]byte, n-2)...)
}

var (
	pbHopByHop = pbExt6{0, pbPad6(6)}
	pbRouting  = pbExt6{43, append([]byte{2, 1, 0, 0, 0, 0}, netip.MustParseAddr("2001:db8::99").AsSlice()...)} // type 2, 1 segment left
	pbDestOpts = pbExt6{60, pbPad6(14)}
)

func pbIPv6(src, dst netip.Addr, proto byte, payload []byte, exts ...pbExt6) []byte {
	chain := payload
	next := proto
	for i := len(exts) - 1; i >= 0; i-- {
		e := exts[i]
		h := append([]byte{next, byte((2+len(e.body))/8 - 1)}, e.body...)
		chain = append(h, chain...)
		next = e.kind
	}
	b := make([]byte, 40, 40+len(chain))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(chain)))
	b[6] = next
	b[7] = 64
	copy(b[8:], src.AsSlice())
	copy(b[24:], dst.AsSlice())
	return append(b, chain...)
}

// pbFragment6 builds an IPv6 fragment extension header body (kind 44).
func pbFragment6(offset uint16, more bool, id uint32) pbExt6 {
	b := make([]byte, 6)
	v := offset << 3
	if more {
		v |= 1
	}
	binary.BigEndian.PutUint16(b[0:], v)
	binary.BigEndian.PutUint32(b[2:], id)
	return pbExt6{44, b}
}

// --------------------------------------------------------------- link layers

func pbEth(etherType uint16, payload []byte) []byte {
	b := append([]byte{0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, byte(etherType >> 8), byte(etherType)}, payload...)
	return b
}

func pbEtherType(v6 bool) uint16 {
	if v6 {
		return 0x86dd
	}
	return 0x0800
}

// pbTag is one 802.1Q/802.1ad tag: vid then the EtherType of what follows.
func pbTag(vid, inner uint16) []byte {
	return []byte{byte(vid >> 8), byte(vid), byte(inner >> 8), byte(inner)}
}

func pbSLL(v6 bool, ip []byte) []byte {
	et := pbEtherType(v6)
	h := []byte{0, 0, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0, byte(et >> 8), byte(et)}
	return append(h, ip...)
}

func pbSLL2(v6 bool, ip []byte) []byte {
	et := pbEtherType(v6)
	h := []byte{byte(et >> 8), byte(et), 0, 0, 0, 0, 0, 3, 0, 1, 4, 6, 2, 0, 0, 0, 0, 1, 0, 0}
	return append(h, ip...)
}

// pbNull builds a BSD loopback header with the family in the given order.
func pbNull(family uint32, bigEndian bool, ip []byte) []byte {
	h := make([]byte, 4)
	if bigEndian {
		binary.BigEndian.PutUint32(h, family)
	} else {
		binary.LittleEndian.PutUint32(h, family)
	}
	return append(h, ip...)
}

// pbPPP builds a PPP-in-HDLC frame (address/control present) for IP.
func pbPPP(v6 bool, ip []byte) []byte {
	proto := uint16(0x0021)
	if v6 {
		proto = 0x0057
	}
	return append([]byte{0xff, 0x03, byte(proto >> 8), byte(proto)}, ip...)
}

// ---------------------------------------------------------------- pcap files

type pbRec struct {
	ts   time.Time
	data []byte
	orig int // original wire length; 0 means len(data)
}

type pbPcapOpts struct {
	bigEndian bool
	nanos     bool
	lt        layers.LinkType
	snaplen   uint32 // 0 means 65535
}

// pbPcap serialises a classic pcap file.
func pbPcap(o pbPcapOpts, recs ...pbRec) []byte {
	var order binary.AppendByteOrder = binary.LittleEndian
	if o.bigEndian {
		order = binary.BigEndian
	}
	magic := uint32(0xa1b2c3d4)
	if o.nanos {
		magic = 0xa1b23c4d
	}
	snap := o.snaplen
	if snap == 0 {
		snap = 65535
	}
	var b bytes.Buffer
	put32 := func(v uint32) { b.Write(order.AppendUint32(nil, v)) }
	put16 := func(v uint16) { b.Write(order.AppendUint16(nil, v)) }
	put32(magic)
	put16(2)
	put16(4)
	put32(0)
	put32(0)
	put32(snap)
	put32(uint32(o.lt))
	for _, r := range recs {
		sub := uint32(r.ts.Nanosecond())
		if !o.nanos {
			sub /= 1000
		}
		orig := r.orig
		if orig == 0 {
			orig = len(r.data)
		}
		put32(uint32(r.ts.Unix()))
		put32(sub)
		put32(uint32(len(r.data)))
		put32(uint32(orig))
		b.Write(r.data)
	}
	return b.Bytes()
}

// ------------------------------------------------------------- pcapng files

type pbOpt struct {
	code uint16
	val  []byte
}

// pcapng option codes used by the tests.
const (
	pbOptComment   = 1
	pbOptIfName    = 2
	pbOptIfTSResol = 9
	pbOptIfTSOff   = 14
)

// pbNG assembles a pcapng file block by block.
type pbNG struct {
	order binary.AppendByteOrder
	buf   []byte
}

func newPbNG(bigEndian bool) *pbNG {
	if bigEndian {
		return &pbNG{order: binary.BigEndian}
	}
	return &pbNG{order: binary.LittleEndian}
}

func (n *pbNG) u16(v uint16) []byte { return n.order.AppendUint16(nil, v) }
func (n *pbNG) u32(v uint32) []byte { return n.order.AppendUint32(nil, v) }

func (n *pbNG) options(opts []pbOpt) []byte {
	if len(opts) == 0 {
		return nil
	}
	var b []byte
	for _, o := range opts {
		b = append(b, n.u16(o.code)...)
		b = append(b, n.u16(uint16(len(o.val)))...)
		b = append(b, o.val...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	return append(b, 0, 0, 0, 0)
}

// block appends a block of the given type with body padded to 32 bits.
func (n *pbNG) block(typ uint32, body []byte) *pbNG {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	total := uint32(12 + len(body))
	n.buf = append(n.buf, n.u32(typ)...)
	n.buf = append(n.buf, n.u32(total)...)
	n.buf = append(n.buf, body...)
	n.buf = append(n.buf, n.u32(total)...)
	return n
}

func (n *pbNG) shb(opts ...pbOpt) *pbNG {
	body := n.u32(0x1a2b3c4d)
	body = append(body, n.u16(1)...)
	body = append(body, n.u16(0)...)
	body = append(body, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // unknown section length
	body = append(body, n.options(opts)...)
	return n.block(0x0a0d0d0a, body)
}

func (n *pbNG) idb(lt layers.LinkType, snaplen uint32, opts ...pbOpt) *pbNG {
	body := n.u16(uint16(lt))
	body = append(body, 0, 0)
	body = append(body, n.u32(snaplen)...)
	body = append(body, n.options(opts)...)
	return n.block(1, body)
}

// epb appends an Enhanced Packet Block with a raw 64-bit timestamp counted in
// the interface's own resolution.
func (n *pbNG) epb(iface uint32, rawTS uint64, data []byte, orig int, opts ...pbOpt) *pbNG {
	if orig == 0 {
		orig = len(data)
	}
	body := n.u32(iface)
	body = append(body, n.u32(uint32(rawTS>>32))...)
	body = append(body, n.u32(uint32(rawTS))...)
	body = append(body, n.u32(uint32(len(data)))...)
	body = append(body, n.u32(uint32(orig))...)
	body = append(body, data...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	body = append(body, n.options(opts)...)
	return n.block(6, body)
}

// spb appends a Simple Packet Block (no timestamp, always interface 0).
func (n *pbNG) spb(data []byte, orig int) *pbNG {
	if orig == 0 {
		orig = len(data)
	}
	body := n.u32(uint32(orig))
	body = append(body, data...)
	return n.block(3, body)
}

func (n *pbNG) bytes() []byte { return n.buf }

// ------------------------------------------------------------- test helpers

func pbAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// pbWriteFile writes data to a fresh file in a temp dir and returns its path.
func pbWriteFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// pbRead writes data to a temp file and runs ReadFile on it.
func pbRead(t *testing.T, name string, data []byte) (sipResult, string, error) {
	t.Helper()
	p := pbWriteFile(t, name, data)
	res, err := readFile(context.Background(), p)
	return res, p, err
}

// pbMustRead is pbRead that fails the test on error.
func pbMustRead(t *testing.T, name string, data []byte) (sipResult, string) {
	t.Helper()
	res, p, err := pbRead(t, name, data)
	if err != nil {
		t.Fatalf("readFile(%s): %v", name, err)
	}
	return res, p
}

// pbSIP builds a request with a fixed, fully populated header set.
func pbSIP(method, callID string, cseq int) string {
	return method + " sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK" + callID + "\r\n" +
		"From: Alice <sip:alice@example.com>;tag=f1\r\n" +
		"To: Bob <sip:bob@example.com>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: " + strconv.Itoa(cseq) + " " + method + "\r\n" +
		"Contact: <sip:alice@10.0.0.1>\r\n" +
		"Content-Length: 0\r\n\r\n"
}

// pbSIPResp builds the matching response to pbSIP.
func pbSIPResp(code int, reason, method, callID string, cseq int) string {
	return "SIP/2.0 " + strconv.Itoa(code) + " " + reason + "\r\n" +
		"From: Alice <sip:alice@example.com>;tag=f1\r\n" +
		"To: Bob <sip:bob@example.com>;tag=t1\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: " + strconv.Itoa(cseq) + " " + method + "\r\n" +
		"Contact: <sip:bob@10.0.0.2>\r\n" +
		"Content-Length: 0\r\n\r\n"
}

// pbWantReq is the Message expected from decoding pbSIP(method, callID, cseq)
// with the given transport details. File, Index and Time are filled in by the
// caller.
func pbWantReq(method, callID string, cseq int) trace.Message {
	return trace.Message{
		IsRequest: true, Method: method, RequestURI: "sip:bob@example.com",
		CallID: callID, From: "Alice <sip:alice@example.com>;tag=f1",
		To: "Bob <sip:bob@example.com>", Contact: "<sip:alice@10.0.0.1>",
		CSeq: strconv.Itoa(cseq) + " " + method,
	}
}

// pbWantResp is the Message expected from decoding pbSIPResp.
func pbWantResp(code int, reason, method, callID string, cseq int) trace.Message {
	return trace.Message{
		Method: method, StatusCode: code, Reason: reason,
		CallID: callID, From: "Alice <sip:alice@example.com>;tag=f1",
		To: "Bob <sip:bob@example.com>;tag=t1", Contact: "<sip:bob@10.0.0.2>",
		CSeq: strconv.Itoa(cseq) + " " + method,
	}
}

// pbEqual compares two Messages field by field, using Time.Equal for the
// timestamp (== on time.Time also compares the location pointer).
func pbEqual(a, b trace.Message) bool {
	if !a.Time.Equal(b.Time) {
		return false
	}
	a.Time, b.Time = time.Time{}, time.Time{}
	return a == b
}

// pbCheckMsgs fails the test unless got equals want element for element.
func pbCheckMsgs(t *testing.T, got, want []trace.Message) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d messages, want %d\n got: %+v\nwant: %+v", len(got), len(want), got, want)
	}
	for i := range got {
		if !pbEqual(got[i], want[i]) {
			t.Errorf("message %d:\n got %+v (time %s)\nwant %+v (time %s)", i, got[i], got[i].Time.Format(time.RFC3339Nano), want[i], want[i].Time.Format(time.RFC3339Nano))
		}
	}
}

func newGzip(w io.Writer) *gzip.Writer { return gzip.NewWriter(w) }

func errorsIs(err, target error) bool { return errors.Is(err, target) }
