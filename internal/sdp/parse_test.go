package sdp

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

const basic = "v=0\r\n" +
	"o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n" +
	"s=Call\r\n" +
	"c=IN IP4 10.0.0.1\r\n" +
	"t=0 0\r\n" +
	"m=audio 49170 RTP/AVP 0 8 101\r\n" +
	"a=rtpmap:101 telephone-event/8000\r\n" +
	"a=fmtp:101 0-16\r\n" +
	"a=ptime:20\r\n" +
	"a=sendrecv\r\n"

func TestParseBasic(t *testing.T) {
	s, err := Parse(basic)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if s.Origin != "alice 2890844526 2890844526 IN IP4 10.0.0.1" || s.Name != "Call" {
		t.Errorf("origin/name = %q / %q", s.Origin, s.Name)
	}
	if s.Addr != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("Addr = %v", s.Addr)
	}
	if len(s.Media) != 1 {
		t.Fatalf("media = %d", len(s.Media))
	}
	m := s.Media[0]
	if m.Type != "audio" || m.Port != 49170 || m.Proto != "RTP/AVP" || m.PTime != 20 || m.Direction != "sendrecv" {
		t.Errorf("media = %+v", m)
	}
	want := []Format{
		{PT: 0, Name: "PCMU", ClockRate: 8000, Channels: 1},
		{PT: 8, Name: "PCMA", ClockRate: 8000, Channels: 1},
		{PT: 101, Name: "telephone-event", ClockRate: 8000, Channels: 1, Fmtp: "0-16"},
	}
	if !reflect.DeepEqual(m.Formats, want) {
		t.Errorf("formats = %+v\nwant     %+v", m.Formats, want)
	}
	if ep, ok := m.Endpoint(); !ok || ep != netip.MustParseAddrPort("10.0.0.1:49170") {
		t.Errorf("endpoint = %v %v", ep, ok)
	}
	if ep, ok := m.RTCPEndpoint(); !ok || ep.Port() != 49171 {
		t.Errorf("rtcp endpoint = %v %v", ep, ok)
	}
	if got := m.Codecs(); !reflect.DeepEqual(got, []string{"PCMU", "PCMA", "telephone-event"}) {
		t.Errorf("Codecs = %v", got)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		check func(t *testing.T, s Session)
	}{
		{"lf only", "v=0\no=- 1 1 IN IP4 1.1.1.1\ns=-\nc=IN IP4 1.1.1.1\nm=audio 4000 RTP/AVP 8\n",
			func(t *testing.T, s Session) {
				if len(s.Media) != 1 || s.Media[0].Port != 4000 || s.Media[0].Formats[0].Name != "PCMA" {
					t.Errorf("%+v", s)
				}
			}},
		{"ipv6", "v=0\r\nc=IN IP6 2001:db8::1\r\nm=audio 4000 RTP/AVP 0\r\n",
			func(t *testing.T, s Session) {
				if s.Media[0].Addr != netip.MustParseAddr("2001:db8::1") {
					t.Errorf("addr = %v", s.Media[0].Addr)
				}
			}},
		{"ipv6 zone-less multicast ttl", "v=0\r\nc=IN IP4 224.2.1.1/127/3\r\nm=audio 4000 RTP/AVP 0\r\n",
			func(t *testing.T, s Session) {
				if s.Addr != netip.MustParseAddr("224.2.1.1") {
					t.Errorf("addr = %v", s.Addr)
				}
			}},
		{"hostname invalid addr", "v=0\r\nc=IN IP4 media.example.com\r\nm=audio 4000 RTP/AVP 0\r\n",
			func(t *testing.T, s Session) {
				if s.Addr.IsValid() || s.Media[0].Addr.IsValid() {
					t.Errorf("hostname must give invalid Addr: %v", s.Media[0].Addr)
				}
				if _, ok := s.Media[0].Endpoint(); ok {
					t.Error("Endpoint ok for hostname")
				}
			}},
		{"ipv4-mapped unmapped", "v=0\r\nc=IN IP6 ::ffff:10.1.2.3\r\nm=audio 4000 RTP/AVP 0\r\n",
			func(t *testing.T, s Session) {
				if s.Addr != netip.MustParseAddr("10.1.2.3") {
					t.Errorf("addr = %v", s.Addr)
				}
			}},
		{"media level c overrides", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\nc=IN IP4 2.2.2.2\r\nm=video 4002 RTP/AVP 96\r\n",
			func(t *testing.T, s Session) {
				if s.Media[0].Addr.String() != "2.2.2.2" || s.Media[1].Addr.String() != "1.1.1.1" {
					t.Errorf("addrs = %v %v", s.Media[0].Addr, s.Media[1].Addr)
				}
			}},
		{"multiple m lines + port count", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000/2 RTP/AVP 0\r\nm=video 0 RTP/AVP 96\r\n",
			func(t *testing.T, s Session) {
				if len(s.Media) != 2 || s.Media[0].Port != 4000 || s.Media[1].Port != 0 {
					t.Errorf("%+v", s.Media)
				}
				if _, ok := s.Media[1].Endpoint(); ok {
					t.Error("disabled media has endpoint")
				}
			}},
		{"direction session level inherited", "v=0\r\nc=IN IP4 1.1.1.1\r\na=sendonly\r\nm=audio 4000 RTP/AVP 0\r\nm=audio 4002 RTP/AVP 0\r\na=recvonly\r\n",
			func(t *testing.T, s Session) {
				if s.Media[0].Direction != "sendonly" || s.Media[1].Direction != "recvonly" {
					t.Errorf("dirs = %q %q", s.Media[0].Direction, s.Media[1].Direction)
				}
			}},
		{"default direction", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\n",
			func(t *testing.T, s Session) {
				if s.Media[0].Direction != "sendrecv" {
					t.Errorf("dir = %q", s.Media[0].Direction)
				}
			}},
		{"rtcp attr and mux", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\na=rtcp:5005 IN IP4 1.1.1.2\r\nm=audio 4002 RTP/AVP 0\r\na=rtcp-mux\r\n",
			func(t *testing.T, s Session) {
				if ep, _ := s.Media[0].RTCPEndpoint(); ep.Port() != 5005 {
					t.Errorf("rtcp = %v", ep)
				}
				if ep, _ := s.Media[1].RTCPEndpoint(); ep.Port() != 4002 || !s.Media[1].RTCPMux {
					t.Errorf("rtcp-mux = %v", ep)
				}
			}},
		{"secure crypto", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc\r\n",
			func(t *testing.T, s Session) {
				if !s.Media[0].Secure {
					t.Error("not secure")
				}
			}},
		{"secure crypto on AVP", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc\r\n",
			func(t *testing.T, s Session) {
				if !s.Media[0].Secure {
					t.Error("not secure")
				}
			}},
		{"secure dtls", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 AA:BB\r\na=rtpmap:111 OPUS/48000/2\r\n",
			func(t *testing.T, s Session) {
				m := s.Media[0]
				if !m.Secure {
					t.Error("not secure")
				}
				if f := m.Formats[0]; f.Name != "opus" || f.ClockRate != 48000 || f.Channels != 2 {
					t.Errorf("format = %+v", f)
				}
			}},
		{"session level fingerprint", "v=0\r\nc=IN IP4 1.1.1.1\r\na=fingerprint:sha-256 AA\r\nm=audio 4000 RTP/AVP 0\r\n",
			func(t *testing.T, s Session) {
				if !s.Media[0].Secure {
					t.Error("session fingerprint not inherited")
				}
			}},
		{"dynamic PT without rtpmap", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 96 0\r\n",
			func(t *testing.T, s Session) {
				f := s.Media[0].Formats[0]
				if f.PT != 96 || f.Name != "" || f.String() != "PT96" {
					t.Errorf("format = %+v", f)
				}
				if got := s.Media[0].Codecs(); got[0] != "PT96" || got[1] != "PCMU" {
					t.Errorf("codecs = %v", got)
				}
			}},
		{"static table", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0 3 4 8 9 13 18\r\n",
			func(t *testing.T, s Session) {
				var names []string
				for _, f := range s.Media[0].Formats {
					names = append(names, f.Name)
				}
				if !reflect.DeepEqual(names, []string{"PCMU", "GSM", "G723", "PCMA", "G722", "CN", "G729"}) {
					t.Errorf("names = %v", names)
				}
			}},
		{"rtpmap for unlisted pt ignored", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\na=rtpmap:101 telephone-event/8000\r\n",
			func(t *testing.T, s Session) {
				if len(s.Media[0].Formats) != 1 {
					t.Errorf("formats = %+v", s.Media[0].Formats)
				}
			}},
		{"rtpmap overrides static", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\na=rtpmap:0 pcmu/8000\r\n",
			func(t *testing.T, s Session) {
				if s.Media[0].Formats[0].Name != "PCMU" {
					t.Errorf("name = %q", s.Media[0].Formats[0].Name)
				}
			}},
		{"junk tolerated", "garbage\r\n\x00\x01\r\nv=0\r\n=x\r\nz=foo\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\nm=\r\nm=audio notaport RTP/AVP 0\r\na=ptime:20\r\n",
			func(t *testing.T, s Session) {
				if len(s.Media) != 1 || s.Media[0].PTime != 0 {
					t.Errorf("media = %+v (attributes of a dropped m-line must not leak)", s.Media)
				}
			}},
		{"non numeric format", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=image 4000 udptl t38\r\n",
			func(t *testing.T, s Session) {
				f := s.Media[0].Formats[0]
				if f.PT != -1 || f.Name != "t38" {
					t.Errorf("format = %+v", f)
				}
			}},
		{"bad ptime", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\na=ptime:-5\r\na=ptime:abc\r\n",
			func(t *testing.T, s Session) {
				if s.Media[0].PTime != 0 {
					t.Errorf("ptime = %d", s.Media[0].PTime)
				}
			}},
		{"tabs and spaces", "v=0\r\nc=IN   IP4\t1.1.1.1 \r\nm=audio   4000  RTP/AVP  0   8 \r\n",
			func(t *testing.T, s Session) {
				if s.Addr.String() != "1.1.1.1" || len(s.Media[0].Formats) != 2 {
					t.Errorf("%+v", s)
				}
			}},
		{"first c wins", "v=0\r\nc=IN IP4 1.1.1.1\r\nc=IN IP4 2.2.2.2\r\nm=audio 4000 RTP/AVP 0\r\n",
			func(t *testing.T, s Session) {
				if s.Addr.String() != "1.1.1.1" {
					t.Errorf("addr = %v", s.Addr)
				}
			}},
		{"no connection", "v=0\r\nm=audio 4000 RTP/AVP 0\r\n",
			func(t *testing.T, s Session) {
				if s.Media[0].Addr.IsValid() {
					t.Error("addr valid")
				}
			}},
		{"attribute case", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\na=SendOnly\r\n",
			func(t *testing.T, s Session) {
				if s.Media[0].Direction != "sendonly" {
					t.Errorf("dir = %q", s.Media[0].Direction)
				}
			}},
		{"fmtp keeps first", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\na=fmtp:96 minptime=10;useinbandfec=1\r\n",
			func(t *testing.T, s Session) {
				if f := s.Media[0].Formats[0]; f.Fmtp != "minptime=10;useinbandfec=1" {
					t.Errorf("fmtp = %q", f.Fmtp)
				}
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			tt.check(t, s)
		})
	}
}

func TestParseNotSDP(t *testing.T) {
	for _, in := range []string{"", "hello world", "\r\n\r\n", "no equals here\r\nat all", "ab\r\n", "x=1\r\n"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) returned no error", in)
		}
	}
}

func TestOnHold(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"active", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\n", false},
		{"sendonly", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\na=sendonly\r\n", true},
		{"inactive", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\na=inactive\r\n", true},
		{"recvonly is not hold", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\na=recvonly\r\n", false},
		{"0.0.0.0", "v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 4000 RTP/AVP 0\r\n", true},
		{"::", "v=0\r\nc=IN IP6 ::\r\nm=audio 4000 RTP/AVP 0\r\n", true},
		{"media-level 0.0.0.0", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\nc=IN IP4 0.0.0.0\r\n", true},
		{"port 0 is disabled not hold", "v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 0 RTP/AVP 0\r\n", false},
		{"hostname", "v=0\r\nc=IN IP4 host.example\r\nm=audio 4000 RTP/AVP 0\r\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Parse(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Media[0].OnHold(); got != tt.want {
				t.Errorf("OnHold = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("v=0\r\nc=IN IP4 1.1.1.1\r\n")
	for range 1000 {
		b.WriteString("m=audio 4000 RTP/AVP 0\r\n")
		for range 1000 {
			b.WriteString("a=x:y\r\n")
		}
	}
	s, err := Parse(b.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Media) > maxMedia {
		t.Errorf("media = %d", len(s.Media))
	}
	for _, m := range s.Media {
		if len(m.Attributes) > maxAttrs {
			t.Errorf("attrs = %d", len(m.Attributes))
		}
	}
	// A huge format list is capped.
	var f strings.Builder
	f.WriteString("v=0\r\nm=audio 4000 RTP/AVP")
	for range 5000 {
		f.WriteString(" 96")
	}
	s, _ = Parse(f.String())
	if n := len(s.Media[0].Formats); n != maxFormats {
		t.Errorf("formats = %d", n)
	}
}

func TestStaticPayload(t *testing.T) {
	if n, c, ch, ok := StaticPayload(8); !ok || n != "PCMA" || c != 8000 || ch != 1 {
		t.Errorf("8 = %v %v %v %v", n, c, ch, ok)
	}
	for _, pt := range []int{-1, 1, 2, 96, 101, 127, 1000} {
		if _, _, _, ok := StaticPayload(pt); ok {
			t.Errorf("PT %d should not be static", pt)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(basic)
	f.Add("v=0\nc=IN IP6 ::1\nm=audio 0 RTP/AVP\na=rtpmap:\na=fmtp\n")
	f.Add("m=audio 99999 RTP/AVP 999\r\nc=IN IP4 1.2.3/4/5\r\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		s, err := Parse(in)
		if err != nil {
			return
		}
		for _, m := range s.Media {
			m.Endpoint()
			m.RTCPEndpoint()
			m.OnHold()
			m.Codecs()
			if m.Direction == "" {
				t.Fatalf("empty direction for %q", in)
			}
		}
	})
}

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := Parse(basic); err != nil {
			b.Fatal(err)
		}
	}
}
