package sip_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sotoz/sipcurious/internal/capture"
	"github.com/sotoz/sipcurious/internal/sip"
	"github.com/sotoz/sipcurious/internal/trace"
)

func readSIP(t *testing.T, path string, opt sip.ParseOptions) []trace.Message {
	t.Helper()
	res, err := capture.Read(context.Background(), []string{path}, capture.Options{Handlers: []capture.Factory{sip.NewHandler(opt)}})
	if err != nil {
		t.Fatal(err)
	}
	var out []trace.Message
	for _, h := range capture.HandlersOf[*sip.Handler](res) {
		out = append(out, h.Messages()...)
	}
	return out
}

// Expectations come from `tshark -r FILE -Y sip` and `-Y tcp.len>0` (frame
// numbers, TCP sequence numbers and lengths, Call-IDs, methods/status codes).
// tshark reports a reassembled message at the frame that completes it; the
// handler reports it at the frame that carried its first byte (documented on
// Handler), derived here from the TCP sequence numbers tshark prints.
func TestRealWorldTCP(t *testing.T) {
	const dir = "../../testdata/"
	tests := []struct {
		file string
		want []string // "firstFrame:info:rawLength"
	}{
		// INVITE = 218 + 575 payload bytes over frames 4 and 6; 100/180 share frame 8.
		{"samples/tcp-sip.pcap", []string{
			"4:INVITE:793", "8:100 Trying:286", "8:180 Ringing:351", "10:200 OK:719", "12:ACK:403",
			"214:BYE:351", "216:200 OK:294", "221:OPTIONS:436", "223:200 OK:419", "225:OPTIONS:436", "227:200 OK:419",
		}},
		// REGISTER over frames 4 (400 bytes) and 6 (185 bytes) with a 2-byte-shorter... see tshark: seq 1 and 401.
		{"realworld/suricata-sip-tcp-register.pcap", []string{"4:REGISTER:585", "8:200 OK:491"}},
		{"realworld/suricata-sip-tcp-port5062.pcap", []string{"4:REGISTER:467", "6:401 Unauthorized:492"}},
		// One message per segment, IP-in-IP encapsulated.
		{"realworld/sngrep-ipip-tcp.pcap", []string{"1:INVITE:1103", "2:183 Ringing:621", "3:200 OK:616", "4:BYE:409"}},
		// TLS: nothing visible.
		{"realworld/wireshark-sip-tls13-caplen-gt-origlen.pcap", nil},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			var got []string
			for _, m := range readSIP(t, dir+tc.file, sip.ParseOptions{Bodies: sip.BodyAll}) {
				got = append(got, fmt.Sprintf("%d:%s:%d", m.Index, m.Info(), len(m.Raw)))
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("got\n %s\nwant\n %s", strings.Join(got, "\n "), strings.Join(tc.want, "\n "))
			}
		})
	}
}

// The 65 KB-bodied INVITE of the suricata capture spans six TCP segments
// (tshark: seq 1, 16333, 32665, 48997, 65329 and the 207-byte 100 Trying).
// The message is kept up to MaxMessageSize, the response behind it is found.
func TestRealWorldLargeTCPBody(t *testing.T) {
	ms := readSIP(t, "../../testdata/realworld/suricata-sip-body-large-tcp-loopback.pcap", sip.ParseOptions{Bodies: sip.BodyAll})
	if len(ms) != 2 {
		t.Fatalf("messages = %d, want 2", len(ms))
	}
	inv, trying := ms[0], ms[1]
	if inv.Index != 5 || inv.Method != "INVITE" || inv.CallID != "test123@attacker.com" || len(inv.Raw) != sip.MaxMessageSize {
		t.Errorf("INVITE: index %d, %s, %q, len(Raw) %d", inv.Index, inv.Method, inv.CallID, len(inv.Raw))
	}
	if trying.Index != 11 || trying.StatusCode != 100 || trying.Method != "INVITE" || trying.SrcPort != 5060 {
		t.Errorf("100 Trying: %+v", trying)
	}
	// Content-Type is application/sdp (tshark), so the default mode keeps the
	// body and BodyNone drops it.
	const file = "../../testdata/realworld/suricata-sip-body-large-tcp-loopback.pcap"
	if def := readSIP(t, file, sip.ParseOptions{}); len(def[0].Raw) != sip.MaxMessageSize {
		t.Errorf("default mode: len(Raw) = %d, want the SDP body kept up to %d", len(def[0].Raw), sip.MaxMessageSize)
	}
	if none := readSIP(t, file, sip.ParseOptions{Bodies: sip.BodyNone}); none[0].Body() != "" || len(none[0].Raw) != none[0].HeaderEnd || none[1].CallID != "test123@attacker.com" {
		t.Errorf("BodyNone: len(Raw) %d HeaderEnd %d", len(none[0].Raw), none[0].HeaderEnd)
	}
}
