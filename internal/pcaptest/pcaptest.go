// Package pcaptest generates deterministic SIP/RTP packet captures for tests
// and demos. It is test support, not for production use: nothing outside
// *_test.go files and the gensamples command should import it.
//
// A [Builder] collects logical events (SIP messages, RTP packets, raw UDP/TCP
// payloads) from scenario methods such as [Builder.Call], [Builder.Register]
// and [Builder.Options]. Only when the capture is rendered ([Builder.PCAP],
// [Builder.PCAPNG], [Builder.WriteFile]) are the events sorted by time and
// serialised with gopacket (Ethernet, 802.1Q, IPv4, IPv6, UDP, TCP, with valid
// checksums) or a hand built Linux cooked header. The same seed and the same
// sequence of calls always produce the same bytes; time.Now is never used.
//
// Example:
//
//	b := pcaptest.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), 1)
//	id := b.Call(pcaptest.CallOptions{
//		From: "alice", To: "bob",
//		Outcome: pcaptest.Answered,
//		TalkTime: 5 * time.Second,
//	})
//	_ = id // Call-ID of the caller leg
//	if err := b.WriteFile("/tmp/call.pcap"); err != nil {
//		log.Fatal(err)
//	}
//
// Scenario methods interleave freely: give each call its own CallOptions.Start
// and the renderer merges everything into one time ordered capture. Link
// layer variants are chosen with [Builder.SetLink].
package pcaptest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// LinkOptions selects the link layer and timestamp resolution of the output.
type LinkOptions struct {
	// VLAN, when non-zero, wraps every Ethernet frame in an 802.1Q tag with
	// this VLAN ID.
	VLAN uint16
	// QinQ, when non-zero together with VLAN, adds an outer 802.1ad S-tag.
	QinQ uint16
	// SLL writes Linux cooked capture (LINKTYPE_LINUX_SLL) instead of Ethernet.
	SLL bool
	// IPv6 makes the default endpoint addresses IPv6 (2001:db8::/32) instead
	// of IPv4. Explicit addresses in the options always win.
	IPv6 bool
	// Nanos writes nanosecond timestamps in classic pcap (pcapng is always
	// nanosecond resolution, as gopacket's writer fixes it).
	Nanos bool
}

type tcpFlags uint8

const (
	fSYN tcpFlags = 1 << iota
	fACK
	fFIN
	fPSH
	fRST
)

// event is one logical packet before rendering.
type event struct {
	at        time.Time
	id        int // insertion order, tie breaker
	src, dst  netip.AddrPort
	tcp       bool
	payload   []byte
	flags     tcpFlags
	seqOffset int64 // TCP only: explicit sequence offset override when hasSeq
	hasSeq    bool
	synthetic bool // handshake / ack frames generated for TCP flows
}

// Builder accumulates events and renders them as pcap or pcapng.
type Builder struct {
	start  time.Time
	seed   uint64
	rng    *rand.Rand
	link   LinkOptions
	events []event
	legs   map[string][]string // caller-leg Call-ID -> every leg Call-ID
}

// New returns a Builder whose default scenario start is start (converted to
// UTC) and whose randomness derives only from seed.
func New(start time.Time, seed uint64) *Builder {
	return &Builder{
		start: start.UTC(),
		seed:  seed,
		rng:   rand.New(rand.NewPCG(seed, 0x5eed51c0)),
		legs:  map[string][]string{},
	}
}

// SetLink selects the link layer variant used when the capture is rendered.
// It may be called at any time before rendering; it affects default
// endpoint addresses only for scenarios created after the call.
func (b *Builder) SetLink(l LinkOptions) { b.link = l }

// Len returns the number of logical packets collected so far, excluding the
// TCP handshake and ACK frames the renderer adds.
func (b *Builder) Len() int { return len(b.events) }

// LegCallIDs returns every Call-ID used by the call or registration whose
// caller-side Call-ID is id: one entry for Direct and Proxy topologies, two
// (caller leg first) for B2BUA. It returns nil for unknown ids.
func (b *Builder) LegCallIDs(id string) []string {
	return append([]string(nil), b.legs[id]...)
}

// Raw adds an arbitrary UDP or TCP payload (transport "UDP" or "TCP") sent
// from src to dst at the given time. TCP payloads become one segment each;
// the renderer adds the three way handshake before the first segment of a
// flow and a pure ACK after every data segment. The payload is not
// interpreted, so it may be malformed on purpose.
func (b *Builder) Raw(at time.Time, src, dst netip.AddrPort, transport string, payload []byte) {
	b.add(at, src, dst, transport == "TCP", payload)
}

func (b *Builder) add(at time.Time, src, dst netip.AddrPort, tcp bool, payload []byte) {
	b.events = append(b.events, event{
		at: at.UTC(), id: len(b.events), src: src, dst: dst, tcp: tcp,
		payload: append([]byte(nil), payload...),
	})
}

// ---------------------------------------------------------------- rendering

type flowKey struct{ src, dst netip.AddrPort }

type tcpState struct {
	next    uint32 // next sequence number this direction will send
	started bool
}

// expand adds the synthetic TCP frames and returns the events sorted by time.
func (b *Builder) expand(rng *rand.Rand) []event {
	out := make([]event, 0, len(b.events)+len(b.events)/2)
	for _, e := range b.events {
		if !b.link.Nanos {
			e.at = e.at.Truncate(time.Microsecond)
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })

	flows := map[flowKey]bool{}
	var extra []event
	for _, e := range out {
		if !e.tcp {
			continue
		}
		fk := flowKey{e.src, e.dst}
		rk := flowKey{e.dst, e.src}
		if !flows[fk] && !flows[rk] {
			flows[fk], flows[rk] = true, true
			t := e.at
			extra = append(extra,
				event{at: t.Add(-3 * time.Millisecond), src: e.src, dst: e.dst, tcp: true, flags: fSYN, synthetic: true},
				event{at: t.Add(-2 * time.Millisecond), src: e.dst, dst: e.src, tcp: true, flags: fSYN | fACK, synthetic: true},
				event{at: t.Add(-1 * time.Millisecond), src: e.src, dst: e.dst, tcp: true, flags: fACK, synthetic: true},
			)
		}
		if len(e.payload) > 0 {
			extra = append(extra, event{
				at: e.at.Add(250 * time.Microsecond), src: e.dst, dst: e.src, tcp: true, flags: fACK, synthetic: true,
			})
		}
	}
	out = append(out, extra...)
	for i := range out {
		if out[i].synthetic {
			out[i].id = len(b.events) + i
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].at.Equal(out[j].at) {
			return out[i].at.Before(out[j].at)
		}
		return out[i].id < out[j].id
	})
	_ = rng
	return out
}

func macFor(a netip.Addr) net.HardwareAddr {
	m := net.HardwareAddr{0x02, 0x00, 0, 0, 0, 0}
	s := a.AsSlice()
	copy(m[2:], s[len(s)-4:])
	return m
}

type frame struct {
	ts       time.Time
	data     []byte
	origLen  int
	linkType layers.LinkType
}

func (b *Builder) render() ([]frame, error) {
	rng := rand.New(rand.NewPCG(b.seed, 0xf4a3e5))
	evs := b.expand(rng)
	frames := make([]frame, 0, len(evs))
	ipid := map[netip.Addr]uint16{}
	tcp := map[flowKey]*tcpState{}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	lt := layers.LinkTypeEthernet
	if b.link.SLL {
		lt = layers.LinkTypeLinuxSLL
	}
	for _, e := range evs {
		var ls []gopacket.SerializableLayer
		src, dst := e.src.Addr(), e.dst.Addr()
		var ip4 *layers.IPv4
		var ip6 *layers.IPv6
		var proto layers.IPProtocol = layers.IPProtocolUDP
		if e.tcp {
			proto = layers.IPProtocolTCP
		}
		ethType := layers.EthernetTypeIPv4
		if src.Is4() {
			id, ok := ipid[src]
			if !ok {
				id = uint16(rng.Uint32())
			}
			ipid[src] = id + 1
			ip4 = &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Id: id, Protocol: proto,
				SrcIP: net.IP(src.AsSlice()), DstIP: net.IP(dst.AsSlice()), Flags: layers.IPv4DontFragment}
			if len(e.payload) > 0 && e.payload[0] == 0x80 {
				ip4.TOS = 0xb8 // EF for RTP, as a real phone would mark it
			}
		} else {
			ethType = layers.EthernetTypeIPv6
			ip6 = &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: proto,
				SrcIP: net.IP(src.AsSlice()), DstIP: net.IP(dst.AsSlice())}
		}
		var tl gopacket.SerializableLayer
		if e.tcp {
			fk := flowKey{e.src, e.dst}
			st := tcp[fk]
			if st == nil {
				st = &tcpState{next: rng.Uint32()}
				tcp[fk] = st
			}
			rt := tcp[flowKey{e.dst, e.src}]
			t := &layers.TCP{
				SrcPort: layers.TCPPort(e.src.Port()), DstPort: layers.TCPPort(e.dst.Port()),
				Seq: st.next, Window: 64240, DataOffset: 5,
			}
			t.SYN = e.flags&fSYN != 0
			t.FIN = e.flags&fFIN != 0
			t.RST = e.flags&fRST != 0
			t.ACK = e.flags&fACK != 0
			t.PSH = len(e.payload) > 0
			if t.SYN {
				t.Options = []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}}
				st.next++
			}
			if t.ACK {
				if rt != nil {
					t.Ack = rt.next
				}
			}
			st.next += uint32(len(e.payload))
			if t.FIN {
				st.next++
			}
			if ip4 != nil {
				_ = t.SetNetworkLayerForChecksum(ip4)
			} else {
				_ = t.SetNetworkLayerForChecksum(ip6)
			}
			tl = t
		} else {
			u := &layers.UDP{SrcPort: layers.UDPPort(e.src.Port()), DstPort: layers.UDPPort(e.dst.Port())}
			if ip4 != nil {
				_ = u.SetNetworkLayerForChecksum(ip4)
			} else {
				_ = u.SetNetworkLayerForChecksum(ip6)
			}
			tl = u
		}
		if b.link.SLL {
			ls = append(ls, gopacket.Payload(sllHeader(src, ethType)))
		} else {
			eth := &layers.Ethernet{SrcMAC: macFor(src), DstMAC: macFor(dst), EthernetType: ethType}
			ls = append(ls, eth)
			inner := ethType
			if b.link.VLAN != 0 {
				if b.link.QinQ != 0 {
					eth.EthernetType = layers.EthernetTypeQinQ
					ls = append(ls, &layers.Dot1Q{VLANIdentifier: b.link.QinQ, Type: layers.EthernetTypeDot1Q})
				} else {
					eth.EthernetType = layers.EthernetTypeDot1Q
				}
				ls = append(ls, &layers.Dot1Q{VLANIdentifier: b.link.VLAN, Priority: 5, Type: inner})
			}
		}
		if ip4 != nil {
			ls = append(ls, ip4)
		} else {
			ls = append(ls, ip6)
		}
		ls = append(ls, tl)
		if len(e.payload) > 0 {
			ls = append(ls, gopacket.Payload(e.payload))
		}
		if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
			return nil, fmt.Errorf("pcaptest: serialize packet at %s: %w", e.at.Format(time.RFC3339Nano), err)
		}
		data := append([]byte(nil), buf.Bytes()...)
		frames = append(frames, frame{ts: e.at, data: data, origLen: len(data), linkType: lt})
	}
	return frames, nil
}

// sllHeader builds a 16 byte LINKTYPE_LINUX_SLL header (packet type 0:
// incoming, ARPHRD_ETHER, 6 byte address derived from src).
func sllHeader(src netip.Addr, et layers.EthernetType) []byte {
	h := make([]byte, 16)
	binary.BigEndian.PutUint16(h[2:], 1)
	binary.BigEndian.PutUint16(h[4:], 6)
	copy(h[6:], macFor(src))
	binary.BigEndian.PutUint16(h[14:], uint16(et))
	return h
}

// PCAP renders the capture as classic pcap (little endian, microsecond
// resolution unless LinkOptions.Nanos). It panics only if serialisation of a
// generated packet fails, which indicates a bug in this package.
func (b *Builder) PCAP() []byte {
	frames, err := b.render()
	if err != nil {
		panic(err)
	}
	var out bytes.Buffer
	var w *pcapgo.Writer
	if b.link.Nanos {
		w = pcapgo.NewWriterNanos(&out)
	} else {
		w = pcapgo.NewWriter(&out)
	}
	lt := layers.LinkTypeEthernet
	if b.link.SLL {
		lt = layers.LinkTypeLinuxSLL
	}
	if err := w.WriteFileHeader(65535, lt); err != nil {
		panic(err)
	}
	for _, f := range frames {
		ci := gopacket.CaptureInfo{Timestamp: f.ts, CaptureLength: len(f.data), Length: f.origLen}
		if err := w.WritePacket(ci, f.data); err != nil {
			panic(err)
		}
	}
	return out.Bytes()
}

// PCAPNG renders the capture as pcapng (one section, one interface,
// nanosecond timestamps).
func (b *Builder) PCAPNG() []byte {
	frames, err := b.render()
	if err != nil {
		panic(err)
	}
	lt := layers.LinkTypeEthernet
	if b.link.SLL {
		lt = layers.LinkTypeLinuxSLL
	}
	var out bytes.Buffer
	intf := pcapgo.DefaultNgInterface
	intf.LinkType = lt
	intf.Name = "eth0"
	intf.OS = "linux"
	intf.SnapLength = 65535
	opt := pcapgo.DefaultNgWriterOptions
	opt.SectionInfo = pcapgo.NgSectionInfo{Application: "sipcurious pcaptest"}
	w, err := pcapgo.NewNgWriterInterface(&out, intf, opt)
	if err != nil {
		panic(err)
	}
	for _, f := range frames {
		ci := gopacket.CaptureInfo{Timestamp: f.ts, CaptureLength: len(f.data), Length: f.origLen}
		if err := w.WritePacket(ci, f.data); err != nil {
			panic(err)
		}
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

// WriteFile writes the capture to path: pcapng when the name ends in
// ".pcapng", classic pcap otherwise.
func (b *Builder) WriteFile(path string) error {
	data := b.PCAP()
	if n := len(path); n >= 7 && path[n-7:] == ".pcapng" {
		data = b.PCAPNG()
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("pcaptest: write %s: %w", path, err)
	}
	return nil
}
