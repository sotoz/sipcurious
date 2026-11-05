package rtp

import (
	"bytes"
	"testing"
)

// rtpBytes builds an RTP packet: header with the given fields and n zero payload bytes.
func rtpBytes(first byte, pt byte, seq uint16, ts, ssrc uint32, extra []byte, n int) []byte {
	b := []byte{first, pt, byte(seq >> 8), byte(seq), byte(ts >> 24), byte(ts >> 16), byte(ts >> 8), byte(ts),
		byte(ssrc >> 24), byte(ssrc >> 16), byte(ssrc >> 8), byte(ssrc)}
	b = append(b, extra...)
	return append(b, make([]byte, n)...)
}

func TestParseHeader(t *testing.T) {
	ext := []byte{0xbe, 0xde, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8} // one extension header, 2 words
	csrc2 := make([]byte, 8)
	tests := []struct {
		name string
		in   []byte
		ok   bool
		want Header
	}{
		{"plain", rtpBytes(0x80, 0x88, 65535, 0xdeadbeef, 0x01020304, nil, 160), true,
			Header{Version: 2, Marker: true, PayloadType: 8, Seq: 65535, Timestamp: 0xdeadbeef, SSRC: 0x01020304, HeaderLen: 12, PayloadLen: 160}},
		{"header only", rtpBytes(0x80, 0, 1, 2, 3, nil, 0), true,
			Header{Version: 2, Seq: 1, Timestamp: 2, SSRC: 3, HeaderLen: 12}},
		{"csrc", rtpBytes(0x82, 0, 1, 2, 3, csrc2, 10), true,
			Header{Version: 2, CSRCCount: 2, Seq: 1, Timestamp: 2, SSRC: 3, HeaderLen: 20, PayloadLen: 10}},
		{"extension", rtpBytes(0x90, 96, 1, 2, 3, ext, 5), true,
			Header{Version: 2, Extension: true, PayloadType: 96, Seq: 1, Timestamp: 2, SSRC: 3, HeaderLen: 12 + 12, PayloadLen: 5}},
		{"csrc and extension", rtpBytes(0x91, 96, 1, 2, 3, append(make([]byte, 4), ext...), 5), true,
			Header{Version: 2, CSRCCount: 1, Extension: true, PayloadType: 96, Seq: 1, Timestamp: 2, SSRC: 3, HeaderLen: 12 + 4 + 12, PayloadLen: 5}},
		{"padding", append(rtpBytes(0xa0, 0, 1, 2, 3, nil, 6), 4), true,
			Header{Version: 2, Padding: true, Seq: 1, Timestamp: 2, SSRC: 3, HeaderLen: 12, PayloadLen: 3}},
		{"implausible padding is payload (SRTP)", append(rtpBytes(0xa0, 0, 1, 2, 3, nil, 6), 200), true,
			Header{Version: 2, Padding: true, Seq: 1, Timestamp: 2, SSRC: 3, HeaderLen: 12, PayloadLen: 7}},
		{"empty", nil, false, Header{}},
		{"short", make([]byte, 11), false, Header{}},
		{"version 0", rtpBytes(0x00, 0, 1, 2, 3, nil, 20), false, Header{}},
		{"version 1", rtpBytes(0x40, 0, 1, 2, 3, nil, 20), false, Header{}},
		{"version 3", rtpBytes(0xc0, 0, 1, 2, 3, nil, 20), false, Header{}},
		{"csrc beyond end", rtpBytes(0x8f, 0, 1, 2, 3, nil, 20), false, Header{}},
		{"extension header missing", rtpBytes(0x90, 0, 1, 2, 3, nil, 2), false, Header{}},
		{"extension beyond end", rtpBytes(0x90, 0, 1, 2, 3, []byte{0xbe, 0xde, 0xff, 0xff}, 8), false, Header{}},
	}
	for _, tc := range tests {
		got, ok := ParseHeader(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: ParseHeader = %+v, %v; want %+v, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIsRTCP(t *testing.T) {
	sr := []byte{0x80, 200, 0, 6, 1, 2, 3, 4}
	sr = append(sr, make([]byte, 20)...)
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"sender report", sr, true},
		{"receiver report empty", []byte{0x80, 201, 0, 1, 1, 2, 3, 4}, true},
		{"sdes", []byte{0x81, 202, 0, 1, 1, 2, 3, 4}, true},
		{"bye", []byte{0x81, 203, 0, 1, 1, 2, 3, 4}, true},
		{"pt 192 (FIR)", []byte{0x80, 192, 0, 1, 1, 2, 3, 4}, true},
		{"pt 223", []byte{0x80, 223, 0, 1, 1, 2, 3, 4}, true},
		{"pt 191", []byte{0x80, 191, 0, 1, 1, 2, 3, 4}, false},
		{"pt 224", []byte{0x80, 224, 0, 1, 1, 2, 3, 4}, false},
		{"rtp pcmu", rtpBytes(0x80, 0, 1, 2, 3, nil, 160), false},
		{"length beyond end", []byte{0x80, 201, 0, 9, 1, 2, 3, 4}, false},
		{"version 1", []byte{0x40, 201, 0, 1, 1, 2, 3, 4}, false},
		{"short", []byte{0x80, 201, 0, 1}, false},
		{"nil", nil, false},
	}
	for _, tc := range tests {
		if got := IsRTCP(tc.in); got != tc.want {
			t.Errorf("%s: IsRTCP = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCodecName(t *testing.T) {
	tests := []struct {
		pt   uint8
		name string
		rate int
	}{
		{0, "PCMU", 8000}, {8, "PCMA", 8000}, {9, "G722", 8000}, {18, "G729", 8000}, {13, "CN", 8000},
		{3, "GSM", 8000}, {4, "G723", 8000}, {34, "H263", 90000}, {26, "JPEG", 90000},
		{1, "", 0}, {96, "", 0}, {101, "", 0}, {127, "", 0}, {200, "", 0},
	}
	for _, tc := range tests {
		if n, r := CodecName(tc.pt); n != tc.name || r != tc.rate {
			t.Errorf("CodecName(%d) = %q, %d; want %q, %d", tc.pt, n, r, tc.name, tc.rate)
		}
	}
}

func FuzzParseHeader(f *testing.F) {
	f.Add(rtpBytes(0x80, 0, 1, 2, 3, nil, 160))
	f.Add(rtpBytes(0x93, 96, 1, 2, 3, bytes.Repeat([]byte{0xbe, 0xde, 0, 1}, 4), 5))
	f.Add([]byte{0x80, 200, 0, 1, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, ok := ParseHeader(b)
		_ = IsRTCP(b)
		if !ok {
			if h != (Header{}) {
				t.Fatalf("non-zero header with ok=false: %+v", h)
			}
			return
		}
		if h.Version != 2 || h.HeaderLen < 12 || h.HeaderLen > len(b) || h.PayloadLen < 0 || h.HeaderLen+h.PayloadLen > len(b) {
			t.Fatalf("inconsistent header %+v for len %d", h, len(b))
		}
	})
}
