package trace

import (
	"reflect"
	"testing"
)

func msg(raw string) Message {
	end := len(raw)
	for _, sep := range []string{"\r\n\r\n", "\n\n"} {
		for i := 0; i+len(sep) <= len(raw); i++ {
			if raw[i:i+len(sep)] == sep {
				end = i + len(sep)
				goto done
			}
		}
	}
done:
	return Message{
		Raw: raw, HeaderEnd: end,
		From: "\"Alice\" <sip:alice@example.com;user=phone>;tag=abc", To: "<tel:+15551234>;tag=def",
		Via:  "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK77;rport",
		CSeq: "42 INVITE",
	}
}

const inviteRaw = "INVITE sip:bob@example.com SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK77;rport\r\n" +
	"v: SIP/2.0/UDP 10.0.0.2\r\n" +
	"User-Agent: Test/1.0\r\n" +
	"Subject: a folded\r\n   subject\r\n" +
	"Content-Type: application/sdp\r\n" +
	"\r\n" +
	"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n"

func TestHeaderLookup(t *testing.T) {
	m := msg(inviteRaw)
	tests := []struct{ name, want string }{
		{"User-Agent", "Test/1.0"},
		{"user-agent", "Test/1.0"},
		{"Subject", "a folded subject"},
		{"s", "a folded subject"},
		{"Content-Type", "application/sdp"},
		{"X-Missing", ""},
	}
	for _, tt := range tests {
		if got := m.Header(tt.name); got != tt.want {
			t.Errorf("Header(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
	if got, want := m.Headers("Via"), []string{"SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK77;rport", "SIP/2.0/UDP 10.0.0.2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Headers(Via) = %q, want %q (compact form v must count)", got, want)
	}
	if got := m.Header("v=0"); got != "" {
		t.Errorf("body line leaked into headers: %q", got)
	}
}

func TestBodyAndSDP(t *testing.T) {
	m := msg(inviteRaw)
	if got := m.Body(); got != "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n" {
		t.Errorf("Body = %q", got)
	}
	if got := m.SDP(); got != m.Body() {
		t.Errorf("SDP = %q", got)
	}
	if got := msg("OPTIONS sip:x SIP/2.0\r\nCall-ID: a\r\n\r\n").Body(); got != "" {
		t.Errorf("empty body = %q", got)
	}

	multi := msg("INVITE sip:x SIP/2.0\r\nContent-Type: multipart/mixed;boundary=\"b1\"\r\n\r\n" +
		"--b1\r\nContent-Type: application/isup\r\n\r\nIAM\r\n--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\ns=-\r\n--b1--\r\n")
	if got := multi.SDP(); got != "v=0\r\ns=-\r\n" {
		t.Errorf("multipart SDP = %q", got)
	}
	if got := msg("INVITE sip:x SIP/2.0\r\nContent-Type: text/plain\r\n\r\nv=0\r\n").SDP(); got != "" {
		t.Errorf("non-SDP body reported as SDP: %q", got)
	}
}

func TestDerivedFields(t *testing.T) {
	m := msg(inviteRaw)
	checks := []struct{ name, got, want string }{
		{"Branch", m.Branch(), "z9hG4bK77"},
		{"FromTag", m.FromTag(), "abc"},
		{"ToTag", m.ToTag(), "def"},
		{"FromUser", m.FromUser(), "alice"},
		{"ToUser", m.ToUser(), "+15551234"},
		{"ContentType", m.ContentType(), "application/sdp"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if m.CSeqNumber() != 42 {
		t.Errorf("CSeqNumber = %d", m.CSeqNumber())
	}
}

func TestURIUser(t *testing.T) {
	tests := []struct{ in, want string }{
		{`"Doe, John" <sip:john@x.com>;tag=1`, "john"},
		{`<sips:bob@x.com:5061>`, "bob"},
		{`sip:carol@x.com;tag=9`, "carol"},
		{`<sip:+1555;phone-context=x@x.com>`, "+1555"},
		{`<sip:proxy.example.com>`, ""},
		{`<tel:+4912345>`, "+4912345"},
		{``, ""},
	}
	for _, tt := range tests {
		if got := URIUser(tt.in); got != tt.want {
			t.Errorf("URIUser(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
