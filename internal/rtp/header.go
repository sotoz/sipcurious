package rtp

import "encoding/binary"

// Header is a parsed RTP fixed header (RFC 3550 section 5.1) with the lengths
// the stream tracker needs.
type Header struct {
	Version, CSRCCount uint8
	Padding, Extension bool
	Marker             bool
	PayloadType        uint8
	Seq                uint16
	Timestamp, SSRC    uint32

	// HeaderLen is the size of the fixed header, CSRC list and header
	// extension together: the payload starts at b[HeaderLen].
	HeaderLen int
	// PayloadLen is len(b) - HeaderLen minus the padding octets when the
	// padding bit is set and the pad count in the last octet is plausible.
	// With SRTP the last octet is part of the (encrypted) payload or the
	// authentication tag, so an implausible pad count is ignored, not an error.
	PayloadLen int
}

// ParseHeader decodes the RTP header at the start of b. It reports false when
// b cannot be an RTP packet: shorter than 12 bytes, version not 2, or the CSRC
// list or header extension running past the end of b. It never panics and
// does not allocate. ParseHeader does not judge the payload type: RTCP
// versus RTP separation by payload type is done by [IsRTCP] and the Handler.
func ParseHeader(b []byte) (Header, bool) {
	if len(b) < 12 || b[0]>>6 != 2 {
		return Header{}, false
	}
	h := Header{
		Version:     2,
		CSRCCount:   b[0] & 0x0f,
		Padding:     b[0]&0x20 != 0,
		Extension:   b[0]&0x10 != 0,
		Marker:      b[1]&0x80 != 0,
		PayloadType: b[1] & 0x7f,
		Seq:         binary.BigEndian.Uint16(b[2:]),
		Timestamp:   binary.BigEndian.Uint32(b[4:]),
		SSRC:        binary.BigEndian.Uint32(b[8:]),
	}
	hl := 12 + 4*int(h.CSRCCount)
	if h.Extension {
		if len(b) < hl+4 {
			return Header{}, false
		}
		hl += 4 + 4*int(binary.BigEndian.Uint16(b[hl+2:]))
	}
	if hl > len(b) {
		return Header{}, false
	}
	h.HeaderLen = hl
	h.PayloadLen = len(b) - hl
	if h.Padding && h.PayloadLen > 0 {
		if n := int(b[len(b)-1]); n >= 1 && n <= h.PayloadLen {
			h.PayloadLen -= n
		}
	}
	return h, true
}

// IsRTCP reports whether b looks like an RTCP packet or compound packet
// (RFC 3550 section 6, RFC 5761 section 4): version 2, at least a header and
// SSRC (8 bytes), packet type in 192..223 (the second byte; that range is
// what the RTP payload types 64..95 with the marker bit set would collide
// with, which is why RFC 5761 reserves them) and a first packet whose length
// field fits into b.
//
// It is therefore also the test that separates RTCP from RTP when both share
// one port (rtcp-mux).
func IsRTCP(b []byte) bool {
	if len(b) < 8 || b[0]>>6 != 2 || b[1] < 192 || b[1] > 223 {
		return false
	}
	return (int(binary.BigEndian.Uint16(b[2:]))+1)*4 <= len(b)
}

// plausiblePT reports whether pt is a payload type real RTP uses: the static
// audio and video assignments of RFC 3551 (0..18 except none, 25..34) and the
// dynamic range 96..127. 19 (reserved), 20..24 and 35..95 are unassigned or
// reserved (72..76 specifically to keep RTCP apart) and rejecting them removes
// most accidental matches of other UDP protocols.
func plausiblePT(pt uint8) bool {
	return pt <= 18 || (pt >= 25 && pt <= 34) || (pt >= 96 && pt <= 127)
}
