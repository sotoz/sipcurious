package capture

import (
	"encoding/binary"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// maxTunnelDepth bounds nested encapsulation (IP-in-IP, GRE, reassembly).
const maxTunnelDepth = 4

// Well-known EtherTypes and IP protocol numbers handled by the fast path.
const (
	etIPv4  = 0x0800
	etIPv6  = 0x86dd
	etDot1Q = 0x8100
	etQinQ  = 0x88a8
	etARP   = 0x0806
	etTEB   = 0x6558 // transparent Ethernet bridging (GRE carrying Ethernet)

	protoTCP     = 6
	protoUDP     = 17
	protoSCTP    = 132
	protoIPIP    = 4
	protoIPv6    = 41
	protoGRE     = 47
	protoEtherIP = 97

	protoHopByHop = 0
	protoRouting  = 43
	protoFragment = 44
	protoAH       = 51
	protoDestOpts = 60
)

// l3kind says what follows the link layer.
type l3kind int8

const (
	kNone     l3kind = iota // nothing we can use (ARP, STP, ...)
	kV4                     // IPv4 packet
	kV6                     // IPv6 packet
	kFallback               // exotic encapsulation: let gopacket find the IP packet
)

// decoder turns raw records into Packets and runs the handlers. One decoder
// serves one file and is used from one goroutine only; everything it needs
// per packet lives in it, so the hot path allocates nothing.
type decoder struct {
	handlers []Handler
	frags    *reassembler
	pkt      Packet

	// per-record state
	consumed bool
	partial  bool
	src, dst netip.Addr
}

func newDecoder(file string) *decoder {
	return &decoder{frags: newReassembler(), pkt: Packet{File: file}}
}

// decode processes one record (index is 1-based) and reports whether a
// handler consumed it.
func (d *decoder) decode(rp *rawPacket, index int) bool {
	if len(d.handlers) == 0 {
		return false
	}
	d.pkt.Index = index
	d.pkt.Time = rp.ts
	d.consumed = false
	d.partial = rp.capLen < rp.origLen

	ip, kind := d.link(rp.lt, rp.data)
	if kind == kFallback {
		ip, kind = d.fallback(rp.lt, rp.data)
	}
	switch kind {
	case kV4:
		d.ipv4(ip, 0)
	case kV6:
		d.ipv6(ip, 0)
	}
	return d.consumed
}

// link finds the network layer behind the link layer of one record.
func (d *decoder) link(lt layers.LinkType, data []byte) ([]byte, l3kind) {
	switch lt {
	case layers.LinkTypeEthernet:
		return ethernet(data)
	case layers.LinkTypeRaw:
		if len(data) == 0 {
			return nil, kNone
		}
		switch data[0] >> 4 {
		case 4:
			return data, kV4
		case 6:
			return data, kV6
		}
		return nil, kNone
	case layers.LinkTypeIPv4:
		return data, kV4
	case layers.LinkTypeIPv6:
		return data, kV6
	case layers.LinkTypeLinuxSLL:
		if len(data) < 16 || binary.BigEndian.Uint16(data[4:6]) > 8 {
			return nil, kNone
		}
		return etherType(binary.BigEndian.Uint16(data[14:16]), data[16:])
	case layers.LinkTypeLinuxSLL2:
		if len(data) < 20 || data[11] > 8 {
			return nil, kNone
		}
		switch binary.BigEndian.Uint16(data[8:10]) { // ARPHRD_: FRAD, IPGRE, 802.11 radiotap
		case 770, 778, 803:
			return nil, kFallback
		}
		return etherType(binary.BigEndian.Uint16(data[0:2]), data[20:])
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		if len(data) < 4 {
			return nil, kNone
		}
		var fam uint32
		if data[0] == 0 && data[1] == 0 {
			fam = binary.BigEndian.Uint32(data)
		} else {
			fam = binary.LittleEndian.Uint32(data)
		}
		switch fam {
		case 2:
			return data[4:], kV4
		case 10, 24, 28, 30: // AF_INET6 on Linux, OpenBSD, FreeBSD, Darwin
			return data[4:], kV6
		}
		return nil, kNone
	}
	return nil, kFallback
}

// ethernet strips an Ethernet header (and any VLAN tags).
func ethernet(data []byte) ([]byte, l3kind) {
	if len(data) < 14 {
		return nil, kNone
	}
	return etherType(binary.BigEndian.Uint16(data[12:14]), data[14:])
}

// etherType dispatches on an EtherType, peeling 802.1Q/802.1ad tags.
func etherType(et uint16, p []byte) ([]byte, l3kind) {
	for range 8 {
		switch et {
		case etIPv4:
			return p, kV4
		case etIPv6:
			return p, kV6
		case etDot1Q, etQinQ:
			if len(p) < 4 {
				return nil, kNone
			}
			et, p = binary.BigEndian.Uint16(p[2:4]), p[4:]
			continue
		case etARP:
			return nil, kNone
		}
		if et < 0x0600 || et == 0x8863 || et == 0x8864 || et == 0x8847 || et == 0x8848 ||
			et == 0x880b || et == etTEB || et == 0x88be {
			// 802.3/LLC, PPPoE, MPLS, PPP, TEB, ERSPAN: rare, gopacket knows them.
			return nil, kFallback
		}
		return nil, kNone
	}
	return nil, kNone
}

// fallback lets gopacket decode the record and returns the IP packet that
// follows the link layers it understood.
func (d *decoder) fallback(lt layers.LinkType, data []byte) ([]byte, l3kind) {
	var first gopacket.Decoder = lt
	switch lt {
	case layers.LinkTypeIPv4:
		first = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		first = layers.LayerTypeIPv6
	}
	pkt := gopacket.NewPacket(data, first, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ls := pkt.Layers()
	for i, l := range ls {
		var kind l3kind
		switch l.(type) {
		case *layers.IPv4:
			kind = kV4
		case *layers.IPv6:
			kind = kV6
		default:
			continue
		}
		if i == 0 {
			return data, kind
		}
		return ls[i-1].LayerPayload(), kind
	}
	return nil, kNone
}

// ipv4 decodes the IPv4 packet in data.
func (d *decoder) ipv4(data []byte, depth int) {
	if len(data) < 20 {
		return
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	ihl := int(data[0]&0x0f) * 4
	if length == 0 { // TSO: the real length is what we have
		length = len(data)
	}
	if length < 20 || ihl < 20 || ihl > length {
		return
	}
	if len(data) > length {
		data = data[:length]
	} else if len(data) < length && ihl > len(data) {
		return
	}
	d.src = netip.AddrFrom4([4]byte(data[12:16]))
	d.dst = netip.AddrFrom4([4]byte(data[16:20]))
	proto := data[9]
	payload := data[ihl:]

	if ff := binary.BigEndian.Uint16(data[6:8]); ff&0x3fff != 0 { // MF or offset
		if d.partial {
			return // a cut-short fragment cannot be reassembled
		}
		k := fragKey{src: d.src, dst: d.dst, id: uint32(binary.BigEndian.Uint16(data[4:6])), proto: proto}
		whole, p, done := d.frags.add(k, int(ff&0x1fff)*8, ff&0x2000 != 0, payload, layers.IPProtocol(proto))
		if !done {
			return
		}
		payload, proto = whole, uint8(p)
		d.partial = false
	}
	d.transport(proto, payload, depth)
}

// ipv6 decodes the IPv6 packet in data, walking its extension headers.
func (d *decoder) ipv6(data []byte, depth int) {
	if len(data) < 40 {
		return
	}
	length := int(binary.BigEndian.Uint16(data[4:6]))
	next := data[6]
	payload := data[40:]
	if length == 0 {
		// Only a jumbogram (RFC 2675) may have a zero length.
		if next != protoHopByHop {
			return
		}
		n, ok := jumboLength(payload)
		if !ok {
			return
		}
		length = n
	}
	if length < len(payload) {
		payload = payload[:length]
	}
	d.src = netip.AddrFrom16([16]byte(data[8:24])).Unmap()
	d.dst = netip.AddrFrom16([16]byte(data[24:40])).Unmap()
	d.v6chain(next, payload, depth)
}

// jumboLength returns the payload length announced by the jumbo option of the
// hop-by-hop header at the start of p.
func jumboLength(p []byte) (int, bool) {
	if len(p) < 8 {
		return 0, false
	}
	n := (int(p[1]) + 1) * 8
	if n > len(p) {
		return 0, false
	}
	opts := p[2:n]
	for len(opts) > 0 {
		switch opts[0] {
		case 0: // Pad1
			opts = opts[1:]
		default:
			if len(opts) < 2 || int(opts[1])+2 > len(opts) {
				return 0, false
			}
			if opts[0] == 0xc2 && opts[1] == 4 {
				return int(binary.BigEndian.Uint32(opts[2:6])), true
			}
			opts = opts[2+int(opts[1]):]
		}
	}
	return 0, false
}

// v6chain skips the IPv6 extension headers in front of the upper-layer
// protocol and decodes it. gopacket stops at routing header types it does not
// know (Mobile IPv6, RPL, segment routing), so the chain is walked here.
func (d *decoder) v6chain(next uint8, payload []byte, depth int) {
	for range 16 { // bound the chain; real ones have at most a handful
		switch next {
		case protoHopByHop, protoRouting, protoDestOpts:
			if len(payload) < 8 {
				return
			}
			n := (int(payload[1]) + 1) * 8
			if n > len(payload) {
				return
			}
			next, payload = payload[0], payload[n:]
		case protoAH:
			if len(payload) < 12 {
				return
			}
			n := (int(payload[1]) + 2) * 4
			if n > len(payload) {
				return
			}
			next, payload = payload[0], payload[n:]
		case protoFragment:
			if len(payload) < 8 || d.partial {
				return
			}
			off := int(binary.BigEndian.Uint16(payload[2:4]) >> 3)
			more := payload[3]&1 != 0
			id := binary.BigEndian.Uint32(payload[4:8])
			proto := payload[0]
			if off == 0 && !more { // atomic fragment: nothing to reassemble
				next, payload = proto, payload[8:]
				continue
			}
			whole, first, done := d.frags.add(fragKey{src: d.src, dst: d.dst, id: id, v6: true}, off*8, more, payload[8:], layers.IPProtocol(proto))
			if !done {
				return
			}
			d.partial = false
			next, payload = uint8(first), whole
		default:
			d.transport(next, payload, depth)
			return
		}
	}
}

// transport decodes the layer-4 header (or tunnel) with IP protocol proto.
func (d *decoder) transport(proto uint8, p []byte, depth int) {
	switch proto {
	case protoUDP:
		if len(p) < 8 {
			return
		}
		sp, dp := binary.BigEndian.Uint16(p[0:2]), binary.BigEndian.Uint16(p[2:4])
		switch n := int(binary.BigEndian.Uint16(p[4:6])); {
		case n >= 8:
			if n > len(p) {
				n = len(p)
			}
			p = p[8:n]
		case n == 0: // jumbogram: the rest of the data
			p = p[8:]
		default:
			return
		}
		d.pkt.TCPSeq, d.pkt.TCPSYN, d.pkt.TCPFIN, d.pkt.TCPRST = 0, false, false, false
		d.deliver("UDP", sp, dp, p)
	case protoTCP:
		if len(p) < 20 {
			return
		}
		off := int(p[12]>>4) * 4
		if off < 20 || off > len(p) {
			return
		}
		d.pkt.TCPSeq = binary.BigEndian.Uint32(p[4:8])
		d.pkt.TCPFIN, d.pkt.TCPSYN, d.pkt.TCPRST = p[13]&1 != 0, p[13]&2 != 0, p[13]&4 != 0
		d.deliver("TCP", binary.BigEndian.Uint16(p[0:2]), binary.BigEndian.Uint16(p[2:4]), p[off:])
	case protoSCTP:
		d.sctp(p)
	case protoIPIP:
		if depth < maxTunnelDepth {
			d.ipv4(p, depth+1)
		}
	case protoIPv6:
		if depth < maxTunnelDepth {
			d.ipv6(p, depth+1)
		}
	case protoGRE:
		if depth < maxTunnelDepth {
			d.gre(p, depth+1)
		}
	case protoEtherIP:
		if depth < maxTunnelDepth && len(p) >= 2+14 {
			if ip, kind := ethernet(p[2:]); kind == kV4 {
				d.ipv4(ip, depth+1)
			} else if kind == kV6 {
				d.ipv6(ip, depth+1)
			}
		}
	}
}

// gre decodes a GRE header (RFC 2784/2890) and the IP packet behind it.
func (d *decoder) gre(p []byte, depth int) {
	if len(p) < 4 {
		return
	}
	off := 4
	if p[0]&0xc0 != 0 { // checksum or routing present
		off += 4
	}
	if p[0]&0x20 != 0 { // key
		off += 4
	}
	if p[0]&0x10 != 0 { // sequence
		off += 4
	}
	if p[0]&0x40 != 0 { // source route entries
		for {
			if off+4 > len(p) {
				return
			}
			n := int(p[off+3])
			af := binary.BigEndian.Uint16(p[off : off+2])
			off += 4 + n
			if off > len(p) {
				return
			}
			if af == 0 && n == 0 {
				break
			}
		}
	}
	if p[1]&0x80 != 0 { // acknowledgement
		off += 4
	}
	if off > len(p) {
		return
	}
	var ip []byte
	var kind l3kind
	switch proto := binary.BigEndian.Uint16(p[2:4]); proto {
	case etTEB:
		ip, kind = ethernet(p[off:])
	default:
		ip, kind = etherType(proto, p[off:])
	}
	switch kind {
	case kV4:
		d.ipv4(ip, depth)
	case kV6:
		d.ipv6(ip, depth)
	}
}

// sctp hands every DATA chunk of an SCTP packet to the handlers.
func (d *decoder) sctp(p []byte) {
	if len(p) < 12 {
		return
	}
	sp, dp := binary.BigEndian.Uint16(p[0:2]), binary.BigEndian.Uint16(p[2:4])
	d.pkt.TCPSeq, d.pkt.TCPSYN, d.pkt.TCPFIN, d.pkt.TCPRST = 0, false, false, false
	for rest := p[12:]; len(rest) >= 4; {
		length := int(binary.BigEndian.Uint16(rest[2:4]))
		if length < 4 || rest[0] == 0 && length < 16 {
			return
		}
		actual := (length + 3) &^ 3
		if actual > len(rest) {
			if length > len(rest) {
				return
			}
			actual = len(rest) // last chunk without its padding
		}
		if rest[0] == 0 { // DATA
			d.deliver("SCTP", sp, dp, rest[16:length])
		}
		rest = rest[actual:]
	}
}

// deliver runs the handlers on the packet described by the per-record state.
func (d *decoder) deliver(transport string, sp, dp uint16, payload []byte) {
	pk := &d.pkt
	pk.Src, pk.Dst = d.src, d.dst
	pk.SrcPort, pk.DstPort = sp, dp
	pk.Transport = transport
	pk.Payload = payload
	pk.Partial = d.partial
	for _, h := range d.handlers {
		if h.Handle(pk) {
			d.consumed = true
			return
		}
	}
}
