package sip

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/sotoz/sipcurious/internal/trace"
)

const sdpBody = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"

func inviteWith(ctype, body string) string {
	h := "INVITE sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKa\r\nFrom: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n"
	if ctype != "" {
		h += "Content-Type: " + ctype + "\r\n"
	}
	return h + "Content-Length: " + "0" + "\r\n\r\n" + body
}

func TestParseBodyModes(t *testing.T) {
	const jsonBody = `{"a":1}`
	tests := []struct {
		name        string
		payload     string
		mode        BodyMode
		wantBody    string
		wantHeaders bool // HeaderEnd must be the end of the header block
	}{
		{"sdp kept by default", inviteWith("application/sdp", sdpBody), BodySDP, sdpBody, true},
		{"sdp compact content type", strings.Replace(inviteWith("", sdpBody), "Content-Length", "c: Application/SDP\r\nContent-Length", 1), BodySDP, sdpBody, true},
		{"multipart kept by default", inviteWith("multipart/mixed;boundary=x", "--x\r\n"+sdpBody+"--x--\r\n"), BodySDP, "--x\r\n" + sdpBody + "--x--\r\n", true},
		{"other body dropped by default", inviteWith("application/json", jsonBody), BodySDP, "", true},
		{"no content type body dropped by default", inviteWith("", jsonBody), BodySDP, "", true},
		{"sdp dropped with none", inviteWith("application/sdp", sdpBody), BodyNone, "", true},
		{"other kept with all", inviteWith("application/json", jsonBody), BodyAll, jsonBody, true},
		{"no content type kept with all", inviteWith("", jsonBody), BodyAll, jsonBody, true},
		{"no body", inviteWith("", ""), BodyAll, "", true},
		{"bare LF", strings.ReplaceAll(inviteWith("application/sdp", sdpBody), "\r\n", "\n"), BodySDP, strings.ReplaceAll(sdpBody, "\r\n", "\n"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := Parse([]byte(tc.payload), ParseOptions{Bodies: tc.mode})
			if !ok {
				t.Fatal("not parsed")
			}
			if got := m.Body(); got != tc.wantBody {
				t.Errorf("Body() = %q, want %q", got, tc.wantBody)
			}
			if !strings.HasSuffix(m.Raw[:m.HeaderEnd], "\n\n") && !strings.HasSuffix(m.Raw[:m.HeaderEnd], "\r\n\r\n") {
				t.Errorf("Raw[:HeaderEnd] does not end with a blank line: %q", m.Raw[:m.HeaderEnd])
			}
			if tc.wantBody == "" && m.HeaderEnd != len(m.Raw) {
				t.Errorf("HeaderEnd = %d, len(Raw) = %d: bodyless message must end at HeaderEnd", m.HeaderEnd, len(m.Raw))
			}
			if m.Via != "SIP/2.0/UDP h;branch=z9hG4bKa" || m.Branch() != "z9hG4bKa" {
				t.Errorf("Via = %q, Branch = %q", m.Via, m.Branch())
			}
			if m.Header("call-id") != "c1" {
				t.Errorf("Header(call-id) = %q", m.Header("call-id"))
			}
		})
	}
}

func TestParseRawIsOneString(t *testing.T) {
	payload := []byte(inviteWith("application/sdp", sdpBody))
	m, ok := Parse(payload, ParseOptions{})
	if !ok {
		t.Fatal("not parsed")
	}
	// Mutating the input must not change the message (Raw is a copy) ...
	payload[0] = 'X'
	if !strings.HasPrefix(m.Raw, "INVITE ") {
		t.Fatalf("Raw aliases the payload: %q", m.Raw[:10])
	}
	// ... and the core fields must point into Raw.
	for name, f := range map[string]string{"CallID": m.CallID, "From": m.From, "To": m.To, "CSeq": m.CSeq, "Via": m.Via, "RequestURI": m.RequestURI, "Method": m.Method} {
		if f == "" {
			t.Errorf("%s empty", name)
			continue
		}
		base, end := uintptr(unsafe.Pointer(unsafe.StringData(m.Raw))), uintptr(unsafe.Pointer(unsafe.StringData(m.Raw)))+uintptr(len(m.Raw))
		p := uintptr(unsafe.Pointer(unsafe.StringData(f)))
		if p < base || p >= end {
			t.Errorf("%s is not a substring of Raw", name)
		}
	}
}

func TestParseAllocs(t *testing.T) {
	payload := []byte(inviteWith("application/sdp", sdpBody))
	var m trace.Message
	n := testing.AllocsPerRun(100, func() { m, _ = Parse(payload, ParseOptions{}) })
	if n != 1 {
		t.Errorf("allocs per Parse = %v, want 1", n)
	}
	_ = m
	junk := []byte(strings.Repeat("\x00\x01 junk ", 40))
	if n := testing.AllocsPerRun(100, func() { Parse(junk, ParseOptions{}) }); n != 0 {
		t.Errorf("allocs for non-SIP = %v, want 0", n)
	}
}

func TestParseSizeCap(t *testing.T) {
	big := inviteWith("application/sdp", strings.Repeat("a=x\r\n", 100000))
	m, ok := Parse([]byte(big), ParseOptions{})
	if !ok || len(m.Raw) != MaxMessageSize {
		t.Fatalf("ok=%v len(Raw)=%d, want %d", ok, len(m.Raw), MaxMessageSize)
	}
}

func TestParseFoldedKeepsRawVerbatim(t *testing.T) {
	m, _ := Parse([]byte("INVITE sip:s SIP/2.0\r\nFrom: Alice\r\n <sip:a@h>\r\nCall-ID: f\r\n\r\n"), ParseOptions{})
	if m.From != "Alice <sip:a@h>" {
		t.Fatalf("From = %q", m.From)
	}
	if !strings.Contains(m.Raw, "From: Alice\r\n <sip:a@h>") {
		t.Fatalf("Raw altered: %q", m.Raw)
	}
	if got := m.Header("from"); got != "Alice <sip:a@h>" {
		t.Fatalf("Header(from) = %q", got)
	}
}

func BenchmarkParse(b *testing.B) {
	payload := []byte(inviteWith("application/sdp", sdpBody))
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		Parse(payload, ParseOptions{})
	}
}

func BenchmarkParseNonSIP(b *testing.B) {
	payload := make([]byte, 172)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	b.ReportAllocs()
	for b.Loop() {
		Parse(payload, ParseOptions{})
	}
}
