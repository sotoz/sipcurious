package sip

import (
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/trace"
)

// TestParseEdgeCases covers odd-but-seen-in-the-wild and hostile SIP text.
// Expectations come from RFC 3261 (section 7: message syntax, 7.3: header
// fields, 25: ABNF), not from the parser's behaviour.
func TestParseEdgeCases(t *testing.T) {
	req := func(m trace.Message) trace.Message { m.IsRequest = true; return m }
	inv := func(m trace.Message) trace.Message { m.Method, m.RequestURI = "INVITE", "sip:b@x"; return req(m) }
	const start = "INVITE sip:b@x SIP/2.0\r\n"

	tests := []struct {
		name    string
		payload string
		ok      bool
		want    trace.Message
	}{
		// header names and values
		{"lowercase names", start + "call-id: c\r\nfrom: <sip:a@x>\r\nto: <sip:b@x>\r\ncseq: 1 INVITE\r\ncontact: <sip:a@h>\r\n\r\n", true,
			inv(trace.Message{CallID: "c", From: "<sip:a@x>", To: "<sip:b@x>", CSeq: "1 INVITE", Contact: "<sip:a@h>"})},
		{"mixed case names", start + "CaLl-Id: c\r\nFROM: f\r\nTo: t\r\ncSeQ: 1 INVITE\r\nCONTACT: m\r\n\r\n", true,
			inv(trace.Message{CallID: "c", From: "f", To: "t", CSeq: "1 INVITE", Contact: "m"})},
		{"no space after colon", start + "Call-ID:c\r\nFrom:<sip:a@x>\r\n\r\n", true, inv(trace.Message{CallID: "c", From: "<sip:a@x>"})},
		{"tab after colon", start + "Call-ID:\tc\r\nFrom:\t\t<sip:a@x>\r\n\r\n", true, inv(trace.Message{CallID: "c", From: "<sip:a@x>"})},
		{"space before colon (LWS allowed by RFC)", start + "Call-ID : c\r\nTo\t: t\r\n\r\n", true, inv(trace.Message{CallID: "c", To: "t"})},
		{"trailing whitespace trimmed", start + "Call-ID: c \t \r\n\r\n", true, inv(trace.Message{CallID: "c"})},
		{"empty header value", start + "Call-ID:\r\nFrom: f\r\n\r\n", true, inv(trace.Message{From: "f"})},
		{"whitespace-only header value", start + "Call-ID:   \r\n\r\n", true, inv(trace.Message{})},
		{"empty Call-ID then real one: first non-empty? (empty does not shadow)", start + "Call-ID:\r\nCall-ID: real\r\n\r\n", true, inv(trace.Message{CallID: "real"})},
		{"duplicate Call-ID: first wins", start + "Call-ID: one\r\nCall-ID: two\r\n\r\n", true, inv(trace.Message{CallID: "one"})},
		{"long and compact Call-ID: first wins", start + "i: short\r\nCall-ID: long\r\n\r\n", true, inv(trace.Message{CallID: "short"})},
		{"compact forms", start + "i: c\r\nf: f\r\nt: t\r\nm: m\r\n\r\n", true, inv(trace.Message{CallID: "c", From: "f", To: "t", Contact: "m"})},
		{"upper-case compact forms", start + "I: c\r\nF: f\r\nT: t\r\nM: m\r\n\r\n", true, inv(trace.Message{CallID: "c", From: "f", To: "t", Contact: "m"})},
		{"compact c is Content-Type, not Call-ID", start + "c: application/sdp\r\nCall-ID: real\r\n\r\n", true, inv(trace.Message{CallID: "real"})},
		{"similar names are not matched", start + "X-Call-ID: bad\r\nCall-IDs: bad\r\nFromage: bad\r\nContact-Info: bad\r\nCSeqs: bad\r\nCall-ID: good\r\n\r\n", true, inv(trace.Message{CallID: "good"})},
		{"header value with colons kept whole", start + "From: <sip:a@x:5060>;tag=1;x=a:b\r\n\r\n", true, inv(trace.Message{From: "<sip:a@x:5060>;tag=1;x=a:b"})},
		{"call-id with at sign and ipv6", start + "Call-ID: abc@[2001:db8::1]\r\n\r\n", true, inv(trace.Message{CallID: "abc@[2001:db8::1]"})},
		{"multi-value To (comma separated) kept as is", start + "To: <sip:a@x>, <sip:b@x>\r\n\r\n", true, inv(trace.Message{To: "<sip:a@x>, <sip:b@x>"})},
		{"quoted display name with colon and comma", start + "From: \"A: B, C\" <sip:a@x>;tag=1\r\n\r\n", true, inv(trace.Message{From: "\"A: B, C\" <sip:a@x>;tag=1"})},
		{"non-UTF8 bytes in values are preserved", start + "From: \xff\xfe<sip:a@x>\r\nCall-ID: c\xc3\r\n\r\n", true, inv(trace.Message{From: "\xff\xfe<sip:a@x>", CallID: "c\xc3"})},
		{"UTF-8 display name", start + "From: \"Zoë 日本\" <sip:a@x>\r\n\r\n", true, inv(trace.Message{From: "\"Zoë 日本\" <sip:a@x>"})},
		{"NUL inside a header value", start + "Call-ID: a\x00b\r\nFrom: f\r\n\r\n", true, inv(trace.Message{CallID: "a\x00b", From: "f"})},
		{"NUL as header name", start + "\x00: v\r\nCall-ID: c\r\n\r\n", true, inv(trace.Message{CallID: "c"})},
		{"header line without colon between headers", start + "Call-ID: c\r\ngarbage line\r\nFrom: f\r\n\r\n", true, inv(trace.Message{CallID: "c", From: "f"})},

		// line endings
		{"LF only", strings.ReplaceAll(start+"Call-ID: c\r\nFrom: f\r\n\r\nbody", "\r\n", "\n"), true, inv(trace.Message{CallID: "c", From: "f"})},
		{"mixed CRLF and LF", "INVITE sip:b@x SIP/2.0\nCall-ID: c\r\nFrom: f\nTo: t\r\n\r\n", true, inv(trace.Message{CallID: "c", From: "f", To: "t"})},
		{"bare CR is not a line ending", "INVITE sip:b@x SIP/2.0\rCall-ID: c\r\n\r\n", false, trace.Message{}},
		{"CR inside value kept", start + "Call-ID: a\rb\r\n\r\n", true, inv(trace.Message{CallID: "a\rb"})},
		{"blank line then headers is end of headers", start + "\r\nCall-ID: c\r\n", true, inv(trace.Message{})},
		{"LF LF end of headers", "INVITE sip:b@x SIP/2.0\nCall-ID: c\n\nFrom: body\n", true, inv(trace.Message{CallID: "c"})},

		// folding
		{"continuation on first header", start + "Call-ID: abc\r\n def\r\nFrom: f\r\n\r\n", true, inv(trace.Message{CallID: "abc def", From: "f"})},
		{"continuation with tab and many spaces", start + "From: a\r\n\t\t  b\r\n   c\r\n\r\n", true, inv(trace.Message{From: "a b c"})},
		{"continuation of empty value", start + "Call-ID:\r\n  abc\r\n\r\n", true, inv(trace.Message{CallID: "abc"})},
		{"continuation of unrecorded header does not leak", start + "X-Unrecorded: a\r\n b\r\nCall-ID: c\r\n\r\n", true, inv(trace.Message{CallID: "c"})},
		{"continuation right after start line is ignored", start + " stray\r\nCall-ID: c\r\n\r\n", true, inv(trace.Message{CallID: "c"})},
		{"continuation after a garbage line is ignored", start + "Call-ID: c\r\nnot a header\r\n x\r\n\r\n", true, inv(trace.Message{CallID: "c"})},
		{"whitespace-only continuation adds nothing", start + "Call-ID: c\r\n \r\n\r\n", true, inv(trace.Message{CallID: "c"})},
		{"whitespace-only line is not end of headers", start + "Call-ID: c\r\n   \r\nFrom: f\r\n\r\n", true, inv(trace.Message{CallID: "c", From: "f"})},

		// body
		{"body looks like start line", start + "Call-ID: c\r\n\r\nINVITE sip:evil@x SIP/2.0\r\nCall-ID: evil\r\n\r\n", true, inv(trace.Message{CallID: "c"})},
		{"body looks like response", start + "Call-ID: c\r\n\r\nSIP/2.0 200 OK\r\nCall-ID: evil\r\n", true, inv(trace.Message{CallID: "c"})},
		{"Content-Length larger than body", start + "Call-ID: c\r\nContent-Length: 99999\r\n\r\nshort", true, inv(trace.Message{CallID: "c"})},
		{"Content-Length smaller than body", start + "Call-ID: c\r\nContent-Length: 1\r\n\r\nlong body here", true, inv(trace.Message{CallID: "c"})},
		{"Content-Length garbage", start + "Call-ID: c\r\nContent-Length: abc\r\n\r\n", true, inv(trace.Message{CallID: "c"})},
		{"binary body", start + "Call-ID: c\r\n\r\n\x00\x01\x02\xff", true, inv(trace.Message{CallID: "c"})},
		{"headers after missing blank line (truncated message)", start + "Call-ID: c\r\nFrom: f", true, inv(trace.Message{CallID: "c", From: "f"})},

		// start lines: requests
		{"extension method", "X-CUSTOM.method_1 sip:b@x SIP/2.0\r\nCall-ID: c\r\n\r\n", true, req(trace.Message{Method: "X-CUSTOM.method_1", RequestURI: "sip:b@x", CallID: "c"})},
		{"lowercase method", "invite sip:b@x SIP/2.0\r\n\r\n", true, req(trace.Message{Method: "invite", RequestURI: "sip:b@x"})},
		{"known extension methods", "PUBLISH sip:b@x SIP/2.0\r\n\r\n", true, req(trace.Message{Method: "PUBLISH", RequestURI: "sip:b@x"})},
		{"digits-only method token", "123 sip:b@x SIP/2.0\r\n\r\n", true, req(trace.Message{Method: "123", RequestURI: "sip:b@x"})},
		{"tel URI", "INVITE tel:+15551234567 SIP/2.0\r\n\r\n", true, req(trace.Message{Method: "INVITE", RequestURI: "tel:+15551234567"})},
		{"asterisk request URI", "OPTIONS * SIP/2.0\r\n\r\n", true, req(trace.Message{Method: "OPTIONS", RequestURI: "*"})},
		{"ipv6 request URI", "INVITE sip:u@[2001:db8::1]:5060 SIP/2.0\r\n\r\n", true, req(trace.Message{Method: "INVITE", RequestURI: "sip:u@[2001:db8::1]:5060"})},
		{"request URI with params and escapes", "INVITE sip:a%20b@x;transport=tcp?h=v SIP/2.0\r\n\r\n", true, req(trace.Message{Method: "INVITE", RequestURI: "sip:a%20b@x;transport=tcp?h=v"})},
		{"trailing space after version", "INVITE sip:b@x SIP/2.0 \r\n\r\n", true, inv(trace.Message{})},
		{"lowercase sip version", "INVITE sip:b@x sip/2.0\r\n\r\n", true, inv(trace.Message{})},
		{"very long request URI", "INVITE sip:" + strings.Repeat("a", 60000) + "@x SIP/2.0\r\n\r\n", true, req(trace.Message{Method: "INVITE", RequestURI: "sip:" + strings.Repeat("a", 60000) + "@x"})},
		{"very long method", strings.Repeat("M", 60000) + " sip:b@x SIP/2.0\r\n\r\n", true, req(trace.Message{Method: strings.Repeat("M", 60000), RequestURI: "sip:b@x"})},

		{"SIP/1.0", "INVITE sip:b@x SIP/1.0\r\n\r\n", false, trace.Message{}},
		{"SIP/2.1", "INVITE sip:b@x SIP/2.1\r\n\r\n", false, trace.Message{}},
		{"SIP/3.0 response", "SIP/3.0 200 OK\r\n\r\n", false, trace.Message{}},
		{"no version", "INVITE sip:b@x\r\n\r\n", false, trace.Message{}},
		{"tab separators", "INVITE\tsip:b@x\tSIP/2.0\r\n\r\n", false, trace.Message{}},
		{"two spaces between method and URI", "INVITE  sip:b@x SIP/2.0\r\n\r\n", false, trace.Message{}},
		{"two spaces before version is tolerated (lenient, unlike the RFC)", "INVITE sip:b@x  SIP/2.0\r\n\r\n", true, inv(trace.Message{})},
		{"leading space", " INVITE sip:b@x SIP/2.0\r\n\r\n", false, trace.Message{}},
		{"URI containing space", "INVITE sip:b @x SIP/2.0\r\n\r\n", false, trace.Message{}},
		{"method with slash (HTTP-ish)", "GET /a/b SIP/2.0\r\n\r\n", true, req(trace.Message{Method: "GET", RequestURI: "/a/b"})},
		{"method is SIP/2.0 itself", "SIP/2.0 sip:b@x SIP/2.0\r\n\r\n", false, trace.Message{}},
		{"NUL in start line", "INVITE sip:b\x00@x SIP/2.0\r\n\r\n", false, trace.Message{}},
		{"NUL-prefixed message", "\x00INVITE sip:b@x SIP/2.0\r\n\r\n", false, trace.Message{}},
		{"UTF-8 BOM prefix", "\xef\xbb\xbfINVITE sip:b@x SIP/2.0\r\n\r\n", false, trace.Message{}},
		{"start line only whitespace separated tokens", "INVITE SIP/2.0 SIP/2.0\r\n", true, req(trace.Message{Method: "INVITE", RequestURI: "SIP/2.0"})},
		{"extremely long start line without version", strings.Repeat("A", 1<<20), false, trace.Message{}},

		// start lines: responses
		{"response no reason, trailing space", "SIP/2.0 200 \r\nCSeq: 1 BYE\r\n\r\n", true, trace.Message{StatusCode: 200, Method: "BYE", CSeq: "1 BYE"}},
		{"response no reason, no trailing space", "SIP/2.0 200\r\nCSeq: 1 BYE\r\n\r\n", true, trace.Message{StatusCode: 200, Method: "BYE", CSeq: "1 BYE"}},
		{"response reason with extra spaces", "SIP/2.0 404   Not   Found  \r\n\r\n", true, trace.Message{StatusCode: 404, Reason: "Not   Found"}},
		{"response reason is a very long string", "SIP/2.0 486 " + strings.Repeat("r", 60000) + "\r\n\r\n", true, trace.Message{StatusCode: 486, Reason: strings.Repeat("r", 60000)}},
		{"response 100 lower bound", "SIP/2.0 100 Trying\r\n\r\n", true, trace.Message{StatusCode: 100, Reason: "Trying"}},
		{"response 699 upper bound", "SIP/2.0 699 Global Decline\r\n\r\n", true, trace.Message{StatusCode: 699, Reason: "Global Decline"}},
		{"response CSeq method case preserved", "SIP/2.0 200 OK\r\nCSeq: 1 invite\r\n\r\n", true, trace.Message{StatusCode: 200, Reason: "OK", Method: "invite", CSeq: "1 invite"}},
		{"response CSeq without method", "SIP/2.0 200 OK\r\nCSeq: 1\r\n\r\n", true, trace.Message{StatusCode: 200, Reason: "OK", CSeq: "1"}},
		{"response CSeq with extra spaces", "SIP/2.0 200 OK\r\nCSeq:   42    REGISTER  \r\n\r\n", true, trace.Message{StatusCode: 200, Reason: "OK", Method: "REGISTER", CSeq: "42    REGISTER"}},
		{"response lowercase version", "sip/2.0 200 OK\r\n\r\n", true, trace.Message{StatusCode: 200, Reason: "OK"}},
		{"response status 99", "SIP/2.0 99 Low\r\n\r\n", false, trace.Message{}},
		{"response status 099", "SIP/2.0 099 Low\r\n\r\n", false, trace.Message{}},
		{"response status 700", "SIP/2.0 700 High\r\n\r\n", false, trace.Message{}},
		{"response status 1000", "SIP/2.0 1000 High\r\n\r\n", false, trace.Message{}},
		{"response status abc", "SIP/2.0 abc OK\r\n\r\n", false, trace.Message{}},
		{"response status +20", "SIP/2.0 +20 OK\r\n\r\n", false, trace.Message{}},
		{"response status -20", "SIP/2.0 -20 OK\r\n\r\n", false, trace.Message{}},
		{"response status 2 0 0", "SIP/2.0 2 0 OK\r\n\r\n", false, trace.Message{}},
		{"response status with trailing letters", "SIP/2.0 200OK\r\n\r\n", false, trace.Message{}},
		{"response two spaces before status", "SIP/2.0  200 OK\r\n\r\n", false, trace.Message{}},
		{"response status unicode digits", "SIP/2.0 ٢٠٠ OK\r\n\r\n", false, trace.Message{}},
		{"response with SIP/2.0 only", "SIP/2.0\r\n\r\n", false, trace.Message{}},
		{"response with SIP/2.0 and a space", "SIP/2.0 \r\n\r\n", false, trace.Message{}},
		{"response with control char in reason", "SIP/2.0 200 O\x01K\r\n\r\n", false, trace.Message{}},
		{"response with DEL in reason", "SIP/2.0 200 O\x7fK\r\n\r\n", false, trace.Message{}},
		{"HTTP-ish response", "HTTP/1.1 200 OK\r\n\r\n", false, trace.Message{}},
		{"RTSP request", "DESCRIBE rtsp://x/y RTSP/1.0\r\nCSeq: 1\r\n\r\n", false, trace.Message{}},
		{"SDP body without SIP", "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\n", false, trace.Message{}},
		{"STUN-ish binary", "\x00\x01\x00\x00\x21\x12\xa4\x42" + strings.Repeat("\x00", 12), false, trace.Message{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := trace.Message{Method: "sentinel"}
			ok := parse([]byte(tc.payload), &got)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.ok, got)
			}
			if !ok {
				if got.Method != "sentinel" {
					t.Fatalf("message modified on failure: %+v", got)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("got\n %+v\nwant\n %+v", got, tc.want)
			}
		})
	}
}

// TestParseOverwritesPreviousFields guards against stale data when the same
// Message value is reused: fields absent from the new message must be cleared.
func TestParseOverwritesPreviousFields(t *testing.T) {
	m := trace.Message{CallID: "old", From: "old", To: "old", Contact: "old", CSeq: "old", Reason: "old", RequestURI: "old", StatusCode: 200}
	if !parse([]byte("INVITE sip:b@x SIP/2.0\r\n\r\n"), &m) {
		t.Fatal("not parsed")
	}
	want := trace.Message{IsRequest: true, Method: "INVITE", RequestURI: "sip:b@x"}
	if m != want {
		t.Fatalf("got %+v, want %+v", m, want)
	}
}

func TestParseHostileSizes(t *testing.T) {
	const start = "INVITE sip:b@x SIP/2.0\r\n"
	t.Run("60 KB header value (the message cap is 64 KiB)", func(t *testing.T) {
		v := strings.Repeat("v", 60000)
		var m trace.Message
		if !parse([]byte(start+"Call-ID: "+v+"\r\nFrom: f\r\n\r\n"), &m) || m.CallID != v || m.From != "f" {
			t.Fatalf("CallID len = %d, From = %q", len(m.CallID), m.From)
		}
	})
	t.Run("60 KB header name", func(t *testing.T) {
		var m trace.Message
		if !parse([]byte(start+strings.Repeat("N", 60000)+": x\r\nCall-ID: c\r\n\r\n"), &m) || m.CallID != "c" {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("1 MB line without colon or newline (cut at the cap)", func(t *testing.T) {
		var m trace.Message
		if !parse([]byte(start+strings.Repeat("x", 1<<20)), &m) {
			t.Fatal("not parsed")
		}
	})
	t.Run("5k unrelated headers then Call-ID", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(start)
		for i := 0; i < 5000; i++ {
			b.WriteString("X-H" + strings.Repeat("a", i%7) + ": v\r\n")
		}
		b.WriteString("Call-ID: found\r\n\r\n")
		var m trace.Message
		if !parse([]byte(b.String()), &m) || m.CallID != "found" {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("1.5k Via headers, headers of interest at the end", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(start)
		b.WriteString(strings.Repeat("Via: SIP/2.0/UDP h;branch=z9hG4bKx\r\n", 1500))
		b.WriteString("From: f\r\nTo: t\r\n\r\n")
		var m trace.Message
		if !parse([]byte(b.String()), &m) || m.From != "f" || m.To != "t" {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("4k duplicate Call-IDs", func(t *testing.T) {
		var m trace.Message
		p := start + strings.Repeat("Call-ID: first\r\n", 4000) + "\r\n"
		if !parse([]byte(p), &m) || m.CallID != "first" {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("16k continuation lines complete quickly and join correctly", func(t *testing.T) {
		const n = 16000 // 64000 bytes: just under the cap
		p := start + "Call-ID: a\r\n" + strings.Repeat(" b\r\n", n) + "From: f\r\n\r\n"
		began := time.Now()
		var m trace.Message
		if !parse([]byte(p), &m) {
			t.Fatal("not parsed")
		}
		if want := "a" + strings.Repeat(" b", n); m.CallID != want || m.From != "f" {
			t.Fatalf("CallID len = %d (want %d), From = %q", len(m.CallID), len(want), m.From)
		}
		if d := time.Since(began); d > 2*time.Second {
			t.Fatalf("took %v: folding is not linear", d)
		}
	})
	t.Run("only newlines then a message", func(t *testing.T) {
		var m trace.Message
		if !parse([]byte(strings.Repeat("\r\n", 100000)+"OPTIONS sip:x SIP/2.0\r\n\r\n"), &m) || m.Method != "OPTIONS" {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("only newlines", func(t *testing.T) {
		var m trace.Message
		if parse([]byte(strings.Repeat("\r\n", 100000)), &m) {
			t.Fatal("parsed")
		}
	})
}

// TestPartialSIPLines pins what is reported when the payload ends in the
// middle of a line (snaplen cut, TCP segment boundary) and the caller trims
// the cut line with TrimPartial.
func TestPartialSIPLines(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		partial bool
		want    trace.Message
	}{
		{"complete, partial flag set", "OPTIONS sip:x SIP/2.0\r\nCall-ID: abc\r\n\r\n", true, trace.Message{IsRequest: true, Method: "OPTIONS", RequestURI: "sip:x", CallID: "abc"}},
		{"cut mid value", "OPTIONS sip:x SIP/2.0\r\nFrom: f\r\nCall-ID: ab", true, trace.Message{IsRequest: true, Method: "OPTIONS", RequestURI: "sip:x", From: "f"}},
		{"cut mid name", "OPTIONS sip:x SIP/2.0\r\nFrom: f\r\nCall-", true, trace.Message{IsRequest: true, Method: "OPTIONS", RequestURI: "sip:x", From: "f"}},
		{"cut after CR", "OPTIONS sip:x SIP/2.0\r\nCall-ID: abc\r", true, trace.Message{IsRequest: true, Method: "OPTIONS", RequestURI: "sip:x"}},
		{"cut after LF keeps line", "OPTIONS sip:x SIP/2.0\r\nCall-ID: abc\r\n", true, trace.Message{IsRequest: true, Method: "OPTIONS", RequestURI: "sip:x", CallID: "abc"}},
		{"only start line, no newline, kept", "OPTIONS sip:x SIP/2.0", true, trace.Message{IsRequest: true, Method: "OPTIONS", RequestURI: "sip:x"}},
		{"not partial: exact bytes parsed", "OPTIONS sip:x SIP/2.0\r\nCall-ID: ab", false, trace.Message{IsRequest: true, Method: "OPTIONS", RequestURI: "sip:x", CallID: "ab"}},
		{"folded header cut inside continuation", "OPTIONS sip:x SIP/2.0\r\nFrom: a\r\n b\r\n c", true, trace.Message{IsRequest: true, Method: "OPTIONS", RequestURI: "sip:x", From: "a b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(tc.payload)
			if tc.partial {
				payload = TrimPartial(payload)
			}
			var got trace.Message
			if !parse(payload, &got) {
				t.Fatal("not parsed")
			}
			if got != tc.want {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}
