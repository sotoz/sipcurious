package rtp

import (
	"encoding/binary"
	"net/netip"

	"github.com/sotoz/sipcurious/internal/capture"
)

// RTCP packet types handled (RFC 3550 section 6.4).
const (
	rtcpSR = 200
	rtcpRR = 201
)

// rtcpObs aggregates the RTCP seen for one SSRC from one sender address.
// sender=true: the SSRC's own sender reports (from == the media sender);
// sender=false: reception report blocks about the SSRC written by from (the
// media receiver).
type rtcpObs struct {
	from     netip.Addr
	sender   bool
	reports  int
	maxFrac  float64 // percent
	maxJit   uint32  // RTP timestamp units of the reported stream
	lastLost int64
}

// obs finds or creates the aggregate for (ssrc, from, sender). It returns nil
// once maxRTCPObs aggregates exist (hostile input must not grow memory).
func (h *Handler) obs(ssrc uint32, from netip.Addr, sender bool) *rtcpObs {
	l := h.rtcp[ssrc]
	for _, o := range l {
		if o.from == from && o.sender == sender {
			return o
		}
	}
	if h.rtcpObsN >= maxRTCPObs {
		return nil
	}
	h.rtcpObsN++
	o := &rtcpObs{from: from, sender: sender}
	h.rtcp[ssrc] = append(l, o)
	return o
}

// handleRTCP walks a (compound) RTCP packet, already validated by IsRTCP,
// and records SR/RR content. Malformed trailing packets end the walk; what
// was parsed before is kept. SRTCP encrypts everything after the first 8
// bytes: the SSRC of its leading SR/RR stays readable (counted), the report
// blocks are garbage that does not match the SSRC of any stream and is
// therefore never attributed to one.
func (h *Handler) handleRTCP(p *capture.Packet) {
	b := p.Payload
	for len(b) >= 8 && b[0]>>6 == 2 && b[1]-192 < 32 {
		n := (int(binary.BigEndian.Uint16(b[2:])) + 1) * 4
		if n > len(b) {
			return
		}
		pkt := b[:n]
		b = b[n:]
		rc := int(pkt[0] & 0x1f)
		var blocks []byte
		switch pkt[1] {
		case rtcpSR:
			if len(pkt) < 28 {
				return
			}
			if o := h.obs(binary.BigEndian.Uint32(pkt[4:]), p.Src, true); o != nil {
				o.reports++
			}
			blocks = pkt[28:]
		case rtcpRR:
			if len(pkt) < 8 {
				return
			}
			blocks = pkt[8:]
		default:
			continue
		}
		for i := 0; i < rc && len(blocks) >= 24; i++ {
			h.block(p.Src, blocks[:24])
			blocks = blocks[24:]
		}
	}
}

// block records one reception report block (RFC 3550 6.4.1) written by from.
func (h *Handler) block(from netip.Addr, b []byte) {
	o := h.obs(binary.BigEndian.Uint32(b), from, false)
	if o == nil {
		return
	}
	o.reports++
	o.maxFrac = max(o.maxFrac, float64(b[4])*100/256)
	lost := int32(binary.BigEndian.Uint32(b[4:])<<8) >> 8 // signed 24 bit
	o.lastLost = int64(lost)
	o.maxJit = max(o.maxJit, binary.BigEndian.Uint32(b[12:]))
}
