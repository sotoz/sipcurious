package sip

import (
	"strings"
	"testing"

	"github.com/sotoz/sipcurious/internal/trace"
)

func TestParse(t *testing.T) {
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

	const invite = `INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds
From: Alice <sip:alice@example.com>;tag=1928301774
To: Bob <sip:bob@example.com>
Call-ID: a84b4c76e66710@pc33.example.com
CSeq: 314159 INVITE
Contact: <sip:alice@pc33.example.com>
Content-Length: 4

body`

	tests := []struct {
		name    string
		payload string
		ok      bool
		want    trace.Message // only SIP fields are compared
	}{
		{
			name: "request CRLF", payload: crlf(invite), ok: true,
			want: trace.Message{
				IsRequest: true, Method: "INVITE", RequestURI: "sip:bob@example.com",
				CallID: "a84b4c76e66710@pc33.example.com",
				From:   "Alice <sip:alice@example.com>;tag=1928301774",
				To:     "Bob <sip:bob@example.com>", Contact: "<sip:alice@pc33.example.com>",
				CSeq: "314159 INVITE", Via: "SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds",
			},
		},
		{
			name: "request bare LF", payload: invite, ok: true,
			want: trace.Message{
				IsRequest: true, Method: "INVITE", RequestURI: "sip:bob@example.com",
				CallID: "a84b4c76e66710@pc33.example.com",
				From:   "Alice <sip:alice@example.com>;tag=1928301774",
				To:     "Bob <sip:bob@example.com>", Contact: "<sip:alice@pc33.example.com>",
				CSeq: "314159 INVITE", Via: "SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds",
			},
		},
		{
			name:    "response takes method from CSeq",
			payload: crlf("SIP/2.0 180 Ringing\nCall-ID: c1\nCSeq: 7 INVITE\nFrom: <sip:a@x>\nTo: <sip:b@x>;tag=9\n\n"),
			ok:      true,
			want: trace.Message{
				Method: "INVITE", StatusCode: 180, Reason: "Ringing", CallID: "c1",
				CSeq: "7 INVITE", From: "<sip:a@x>", To: "<sip:b@x>;tag=9",
			},
		},
		{
			name:    "response with multi-word reason",
			payload: "SIP/2.0 401 nonce has changed\nCSeq: 4 REGISTER\n\n", ok: true,
			want: trace.Message{Method: "REGISTER", StatusCode: 401, Reason: "nonce has changed", CSeq: "4 REGISTER"},
		},
		{
			name:    "response without reason",
			payload: "SIP/2.0 200\nCSeq: 1 BYE\n\n", ok: true,
			want: trace.Message{Method: "BYE", StatusCode: 200, CSeq: "1 BYE"},
		},
		{
			name:    "response without CSeq has empty method",
			payload: "SIP/2.0 200 OK\nCall-ID: x\n\n", ok: true,
			want: trace.Message{StatusCode: 200, Reason: "OK", CallID: "x"},
		},
		{
			name:    "compact header forms",
			payload: "OPTIONS sip:s SIP/2.0\ni: cid@h\nf: <sip:a@h>;tag=1\nt: <sip:b@h>\nm: <sip:a@1.2.3.4>\nCSeq: 1 OPTIONS\n\n",
			ok:      true,
			want: trace.Message{
				IsRequest: true, Method: "OPTIONS", RequestURI: "sip:s", CallID: "cid@h",
				From: "<sip:a@h>;tag=1", To: "<sip:b@h>", Contact: "<sip:a@1.2.3.4>", CSeq: "1 OPTIONS",
			},
		},
		{
			name:    "upper and lower case header names",
			payload: "BYE sip:s SIP/2.0\nCALL-ID: up\nfrom: <sip:f@h>\nTO : <sip:t@h>\ncseq:  2 BYE \n\n",
			ok:      true,
			want: trace.Message{
				IsRequest: true, Method: "BYE", RequestURI: "sip:s", CallID: "up",
				From: "<sip:f@h>", To: "<sip:t@h>", CSeq: "2 BYE",
			},
		},
		{
			name:    "folded headers",
			payload: crlf("INVITE sip:s SIP/2.0\nFrom: Alice\n <sip:a@h>\n\t;tag=1\nCall-ID: folded\nTo: <sip:b@h>\n\n"),
			ok:      true,
			want: trace.Message{
				IsRequest: true, Method: "INVITE", RequestURI: "sip:s", CallID: "folded",
				From: "Alice <sip:a@h> ;tag=1", To: "<sip:b@h>",
			},
		},
		{
			name:    "body is ignored",
			payload: "INVITE sip:s SIP/2.0\nCall-ID: real\n\nCall-ID: fake\nFrom: <sip:body@h>\n",
			ok:      true,
			want:    trace.Message{IsRequest: true, Method: "INVITE", RequestURI: "sip:s", CallID: "real"},
		},
		{
			name:    "first duplicate header wins, continuation of ignored dup is dropped",
			payload: "INVITE sip:s SIP/2.0\nCall-ID: one\nCall-ID: two\n three\n\n",
			ok:      true,
			want:    trace.Message{IsRequest: true, Method: "INVITE", RequestURI: "sip:s", CallID: "one"},
		},
		{
			name:    "malformed header lines are skipped",
			payload: "INVITE sip:s SIP/2.0\nthis is not a header\n: empty name\nCall-ID: ok\n",
			ok:      true,
			want:    trace.Message{IsRequest: true, Method: "INVITE", RequestURI: "sip:s", CallID: "ok"},
		},
		{
			name:    "start line only, no terminator",
			payload: "ACK sip:s SIP/2.0", ok: true,
			want: trace.Message{IsRequest: true, Method: "ACK", RequestURI: "sip:s"},
		},
		{
			name:    "truncated in the middle of a header",
			payload: "INVITE sip:s SIP/2.0\r\nCall-ID: abc\r\nFrom: <sip:a",
			ok:      true,
			want:    trace.Message{IsRequest: true, Method: "INVITE", RequestURI: "sip:s", CallID: "abc", From: "<sip:a"},
		},
		{
			name:    "leading keep-alive CRLF",
			payload: "\r\n\r\nOPTIONS sip:s SIP/2.0\r\nCall-ID: ka\r\n\r\n", ok: true,
			want: trace.Message{IsRequest: true, Method: "OPTIONS", RequestURI: "sip:s", CallID: "ka"},
		},
		{
			name:    "non-ASCII reason phrase",
			payload: "SIP/2.0 486 Occupé\nCSeq: 1 INVITE\n", ok: true,
			want: trace.Message{Method: "INVITE", StatusCode: 486, Reason: "Occupé", CSeq: "1 INVITE"},
		},
		{name: "empty", payload: ""},
		{name: "only newlines", payload: "\r\n\r\n"},
		{name: "truncated start line", payload: "INVITE sip:bob@exa"},
		{name: "truncated version", payload: "INVITE sip:bob@example.com SIP/"},
		{name: "wrong version", payload: "INVITE sip:bob@example.com SIP/3.0\r\n"},
		{name: "HTTP request", payload: "GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"},
		{name: "HTTP response", payload: "HTTP/1.1 200 OK\r\n\r\n"},
		{name: "status code not numeric", payload: "SIP/2.0 2xx OK\r\n"},
		{name: "status code too short", payload: "SIP/2.0 20 OK\r\n"},
		{name: "status code out of range", payload: "SIP/2.0 999 Nope\r\n"},
		{name: "status code too long", payload: "SIP/2.0 2000 OK\r\n"},
		{name: "method with illegal chars", payload: "IN(VITE sip:s SIP/2.0\r\n"},
		{name: "URI missing", payload: "INVITE  SIP/2.0\r\n"},
		{name: "extra token in request line", payload: "INVITE sip:s extra SIP/2.0\r\n"},
		{name: "binary garbage", payload: "\x00\x01\x02\xff\xfe\x80INVITE sip:x SIP/2.0\r\n"},
		{name: "DNS-like payload", payload: "\xb3\xc0\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04_sip\x04_udp"},
		{name: "single NUL keep-alive", payload: "\x00"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := trace.Message{Method: "sentinel"}
			ok := parse([]byte(tc.payload), &got)
			if ok != tc.ok {
				t.Fatalf("parse ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				if got.Method != "sentinel" {
					t.Fatalf("message modified on failure: %+v", got)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("parse =\n %+v\nwant\n %+v", got, tc.want)
			}
		})
	}
}

func TestParseCaseInsensitiveVersion(t *testing.T) {
	var m trace.Message
	if !parse([]byte("INVITE sip:s sip/2.0\r\n"), &m) || m.Method != "INVITE" {
		t.Fatalf("lower-case version rejected: %+v", m)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: a\r\nFrom: <sip:a@h>\r\n b\r\nCSeq: 1 INVITE\r\n\r\nbody",
		"SIP/2.0 200 OK\nCSeq: 1 BYE\ni: x\n\n",
		"SIP/2.0 100",
		"OPTIONS sip:x SIP/2.0\r\nm:\r\n\r\n",
		"\r\n\r\nACK sip:x SIP/2.0",
		"",
		"\x00\xff",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var m trace.Message
		if !parse(data, &m) {
			if m != (trace.Message{}) {
				t.Fatalf("message modified on failure: %+v", m)
			}
			return
		}
		if m.IsRequest && (m.Method == "" || m.RequestURI == "") {
			t.Fatalf("request without method/URI: %+v", m)
		}
		if !m.IsRequest && (m.StatusCode < 100 || m.StatusCode > 699) {
			t.Fatalf("response with bad code: %+v", m)
		}
		_ = m.Info()
	})
}
