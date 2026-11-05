package rtp

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/capture"
)

// readUDP decodes a classic pcap file (Ethernet with optional VLAN tags, or
// Linux cooked v1; IPv4 or IPv6; UDP) into capture.Packets and feeds them to
// h. It is a deliberately tiny reader so that these tests do not depend on the
// capture package's file readers. It returns the number of UDP packets fed
// and the number consumed by h.
func readUDP(tb testing.TB, path string, h *Handler) (fed, consumed int) {
	tb.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	if len(data) < 24 {
		tb.Fatalf("%s: short file", path)
	}
	var bo binary.ByteOrder = binary.LittleEndian
	nano := false
	switch binary.LittleEndian.Uint32(data) {
	case 0xa1b2c3d4:
	case 0xa1b23c4d:
		nano = true
	case 0xd4c3b2a1:
		bo = binary.BigEndian
	case 0x4d3cb2a1:
		bo, nano = binary.BigEndian, true
	default:
		tb.Fatalf("%s: not a classic pcap", path)
	}
	link := bo.Uint32(data[20:])
	off := 24
	var p capture.Packet
	for idx := 1; off+16 <= len(data); idx++ {
		sec, frac, caplen := bo.Uint32(data[off:]), bo.Uint32(data[off+4:]), int(bo.Uint32(data[off+8:]))
		off += 16
		if off+caplen > len(data) {
			break
		}
		fr := data[off : off+caplen]
		off += caplen
		ns := int64(frac)
		if !nano {
			ns *= 1000
		}
		var l3 []byte
		var etype uint16
		switch link {
		case 1:
			if len(fr) < 14 {
				continue
			}
			etype, l3 = binary.BigEndian.Uint16(fr[12:]), fr[14:]
			for etype == 0x8100 && len(l3) >= 4 {
				etype, l3 = binary.BigEndian.Uint16(l3[2:]), l3[4:]
			}
		case 0: // BSD loopback: 4-byte address family (host order of the capturing machine)
			if len(fr) < 4 {
				continue
			}
			if fam := binary.LittleEndian.Uint32(fr); fam == 2 {
				etype = 0x0800
			} else {
				etype = 0x86dd
			}
			l3 = fr[4:]
		case 113:
			if len(fr) < 16 {
				continue
			}
			etype, l3 = binary.BigEndian.Uint16(fr[14:]), fr[16:]
		default:
			tb.Fatalf("%s: link type %d unsupported by the test reader", path, link)
		}
		var proto byte
		var l4 []byte
		switch {
		case etype == 0x0800 && len(l3) >= 20:
			ihl := int(l3[0]&15) * 4
			if ihl < 20 || len(l3) < ihl || binary.BigEndian.Uint16(l3[6:])&0x3fff != 0 {
				continue
			}
			p.Src, _ = netip.AddrFromSlice(l3[12:16])
			p.Dst, _ = netip.AddrFromSlice(l3[16:20])
			proto, l4 = l3[9], l3[ihl:]
		case etype == 0x86dd && len(l3) >= 40:
			p.Src, _ = netip.AddrFromSlice(l3[8:24])
			p.Dst, _ = netip.AddrFromSlice(l3[24:40])
			proto, l4 = l3[6], l3[40:]
		default:
			continue
		}
		if proto != 17 || len(l4) < 8 {
			continue
		}
		p.File, p.Index = path, idx
		p.Time = time.Unix(int64(sec), ns).UTC()
		p.SrcPort, p.DstPort = binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
		p.Transport = "UDP"
		n := min(int(binary.BigEndian.Uint16(l4[4:]))-8, len(l4)-8)
		p.Payload = l4[8 : 8+max(n, 0)]
		fed++
		if h.Handle(&p) {
			consumed++
		}
	}
	return fed, consumed
}
