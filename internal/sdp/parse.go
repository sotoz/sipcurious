package sdp

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// Limits that keep Parse bounded on hostile input. They are far above
// anything a real SIP SDP body reaches.
const (
	maxInput   = 1 << 20 // bytes of text looked at
	maxMedia   = 64      // m= sections kept
	maxAttrs   = 512     // a= lines kept per section
	maxFormats = 256     // payload types kept per m= section
)

// ErrNotSDP is returned by Parse when the text contains no SDP line at all.
var ErrNotSDP = errors.New("sdp: no SDP lines found")

// The four direction attributes of RFC 4566 section 6.
const (
	DirSendRecv = "sendrecv"
	DirSendOnly = "sendonly"
	DirRecvOnly = "recvonly"
	DirInactive = "inactive"
)

// static is the RFC 3551 table of static audio/video payload types.
var static = [...]struct {
	name     string
	clock    int
	channels int
}{
	0: {"PCMU", 8000, 1}, 3: {"GSM", 8000, 1}, 4: {"G723", 8000, 1},
	5: {"DVI4", 8000, 1}, 6: {"DVI4", 16000, 1}, 7: {"LPC", 8000, 1},
	8: {"PCMA", 8000, 1}, 9: {"G722", 8000, 1}, // G722 clock is 8000 by RFC 3551 erratum
	10: {"L16", 44100, 2}, 11: {"L16", 44100, 1}, 12: {"QCELP", 8000, 1},
	13: {"CN", 8000, 1}, 14: {"MPA", 90000, 0}, 15: {"G728", 8000, 1},
	16: {"DVI4", 11025, 1}, 17: {"DVI4", 22050, 1}, 18: {"G729", 8000, 1},
	25: {"CelB", 90000, 0}, 26: {"JPEG", 90000, 0}, 28: {"nv", 90000, 0},
	31: {"H261", 90000, 0}, 32: {"MPV", 90000, 0}, 33: {"MP2T", 90000, 0},
	34: {"H263", 90000, 0},
}

// StaticPayload returns the encoding name, clock rate and channel count of a
// static payload type (RFC 3551). ok is false for unassigned and dynamic
// payload types.
func StaticPayload(pt int) (name string, clock, channels int, ok bool) {
	if pt < 0 || pt >= len(static) || static[pt].name == "" {
		return "", 0, 0, false
	}
	s := static[pt]
	return s.name, s.clock, s.channels, true
}

// canonNames are encoding names whose case is normalised, so that "pcmu",
// "Opus" and "TELEPHONE-EVENT" compare equal to what the RTP side reports.
var canonNames = [...]string{
	"PCMU", "PCMA", "G722", "G729", "G723", "G726-32", "G728", "GSM", "GSM-EFR",
	"iLBC", "opus", "speex", "AMR", "AMR-WB", "EVS", "CN", "telephone-event",
	"red", "ulpfec", "H264", "H265", "VP8", "VP9", "AV1", "t38",
}

func canonName(name string) string {
	for _, c := range canonNames {
		if len(c) == len(name) && strings.EqualFold(c, name) {
			return c
		}
	}
	return name
}

// Parse parses an SDP body. Lines may end in CRLF or LF; lines that are not
// "<letter>=<value>" and unknown line types are ignored. It never panics and
// returns whatever it could parse; the error is ErrNotSDP only when no
// v=, o=, s=, c= or m= line was found. Input beyond 1 MiB, more than 64
// m-lines, 512 a-lines per section or 256 formats per m-line is dropped.
//
// Conventions:
//   - Media.Addr is the media-level c= if present, else the session-level one;
//     it is invalid for host names and other non-IP values. IPv4-mapped IPv6
//     addresses are unmapped and a multicast "/ttl[/n]" suffix is dropped.
//   - Media.Direction defaults to the session-level direction, then "sendrecv".
//   - Formats carry the static payload type table, overridden by a=rtpmap. A
//     dynamic payload type without a=rtpmap has Name "". Non-numeric formats
//     (e.g. "t38", "webrtc-datachannel") are kept with PT -1 and the token as Name.
//   - Media.Port is the first port only ("49170/2" -> 49170); an m-line with an
//     unparsable port is dropped together with its attributes.
func Parse(text string) (Session, error) {
	var (
		s        Session
		cur      = -1   // index of the m-section being filled, -1 = session level
		skipping bool   // inside an m-section that was dropped
		seen     bool   // any SDP-like line found
		sessDir  string // session-level direction
		sessSec  bool   // session-level crypto/fingerprint
		sessC    bool   // session-level c= seen
		hasC     [maxMedia]bool
	)
	if len(text) > maxInput {
		text = text[:maxInput]
	}
	for len(text) > 0 {
		line := text
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			text = ""
		}
		line = strings.TrimSpace(line)
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		val := strings.TrimSpace(line[2:])
		switch line[0] {
		case 'v':
			seen = true
		case 'o':
			seen = true
			if s.Origin == "" {
				s.Origin = val
			}
		case 's':
			seen = true
			if s.Name == "" {
				s.Name = val
			}
		case 'c':
			seen = true
			switch {
			case skipping:
			case cur >= 0:
				if !hasC[cur] {
					hasC[cur] = true
					s.Media[cur].Addr = parseConn(val)
				}
			case !sessC:
				sessC = true
				s.Addr = parseConn(val)
			}
		case 'm':
			seen = true
			if len(s.Media) >= maxMedia {
				cur, skipping = -1, true
				continue
			}
			m, ok := parseMediaLine(val)
			if !ok {
				cur, skipping = -1, true
				continue
			}
			skipping = false
			s.Media = append(s.Media, m)
			cur = len(s.Media) - 1
		case 'a':
			seen = true
			if skipping {
				continue
			}
			name, value, _ := strings.Cut(val, ":")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if name == "" {
				continue
			}
			lname := name
			if hasUpper(name) {
				lname = strings.ToLower(name)
			}
			if cur < 0 {
				if len(s.Attributes) < maxAttrs {
					s.Attributes = append(s.Attributes, Attribute{name, value})
				}
				switch lname {
				case DirSendRecv, DirSendOnly, DirRecvOnly, DirInactive:
					sessDir = lname
				case "crypto", "fingerprint":
					sessSec = true
				}
				continue
			}
			m := &s.Media[cur]
			if len(m.Attributes) < maxAttrs {
				m.Attributes = append(m.Attributes, Attribute{name, value})
			}
			switch lname {
			case DirSendRecv, DirSendOnly, DirRecvOnly, DirInactive:
				m.Direction = lname
			case "rtcp-mux":
				m.RTCPMux = true
			case "crypto", "fingerprint":
				m.Secure = true
			case "ptime":
				if n, ok := atoi(value); ok && n > 0 && n <= 1<<20 {
					m.PTime = n
				}
			case "rtpmap":
				applyRtpmap(m, value)
			case "fmtp":
				applyFmtp(m, value)
			}
		}
	}
	if !seen {
		return Session{}, ErrNotSDP
	}
	for i := range s.Media {
		m := &s.Media[i]
		if !hasC[i] {
			m.Addr = s.Addr
		}
		if m.Direction == "" {
			m.Direction = sessDir
			if m.Direction == "" {
				m.Direction = DirSendRecv
			}
		}
		if sessSec || strings.Contains(m.Proto, "SAVP") || strings.Contains(m.Proto, "DTLS") {
			m.Secure = true
		}
	}
	return s, nil
}

func hasUpper(s string) bool {
	for i := range len(s) {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// cutField splits off the first whitespace-delimited field of s.
func cutField(s string) (field, rest string) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// parseConn parses the value of a c= line ("IN IP4 224.2.1.1/127"). The result
// is invalid for anything that is not an IP literal.
func parseConn(v string) netip.Addr {
	_, rest := cutField(v)   // network type
	_, rest = cutField(rest) // address type
	addr, _ := cutField(rest)
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// parseMediaLine parses "audio 49170/2 RTP/AVP 0 8 101".
func parseMediaLine(v string) (Media, bool) {
	typ, rest := cutField(v)
	portStr, rest := cutField(rest)
	proto, rest := cutField(rest)
	if typ == "" || portStr == "" {
		return Media{}, false
	}
	if i := strings.IndexByte(portStr, '/'); i >= 0 {
		portStr = portStr[:i]
	}
	port, ok := atoi(portStr)
	if !ok || port > 65535 {
		return Media{}, false
	}
	m := Media{Type: typ, Port: uint16(port), Proto: proto}
	audio := typ == "audio"
	for len(m.Formats) < maxFormats {
		var tok string
		tok, rest = cutField(rest)
		if tok == "" {
			break
		}
		pt, ok := atoi(tok)
		if !ok || pt > 127 {
			m.Formats = append(m.Formats, Format{PT: -1, Name: tok})
			continue
		}
		f := Format{PT: pt}
		if name, clock, ch, ok := StaticPayload(pt); ok {
			f.Name, f.ClockRate, f.Channels = name, clock, ch
			if !audio && ch == 1 {
				f.Channels = 0
			}
		}
		m.Formats = append(m.Formats, f)
	}
	return m, true
}

func findFormat(m *Media, pt int) *Format {
	for i := range m.Formats {
		if m.Formats[i].PT == pt {
			return &m.Formats[i]
		}
	}
	return nil
}

// atoi parses a non-negative decimal integer without allocating on failure
// (strconv.Atoi allocates its error). It accepts at most 9 digits.
func atoi(s string) (int, bool) {
	if s == "" || len(s) > 9 {
		return 0, false
	}
	n := 0
	for i := range len(s) {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// applyRtpmap handles "a=rtpmap:<pt> <name>/<clock>[/<channels>]".
func applyRtpmap(m *Media, v string) {
	ptStr, enc := cutField(v)
	pt, ok := atoi(ptStr)
	if !ok {
		return
	}
	f := findFormat(m, pt)
	if f == nil {
		return
	}
	enc, _ = cutField(enc)
	name, rest, _ := strings.Cut(enc, "/")
	if name == "" {
		return
	}
	f.Name = canonName(name)
	f.ClockRate, f.Channels = 0, 0
	clock, ch, _ := strings.Cut(rest, "/")
	if n, ok := atoi(clock); ok && n > 0 {
		f.ClockRate = n
	}
	if n, ok := atoi(ch); ok && n > 0 {
		f.Channels = n
	} else if m.Type == "audio" {
		f.Channels = 1
	}
}

// applyFmtp handles "a=fmtp:<pt> <params>".
func applyFmtp(m *Media, v string) {
	ptStr, params := cutField(v)
	pt, ok := atoi(ptStr)
	if !ok {
		return
	}
	if f := findFormat(m, pt); f != nil && f.Fmtp == "" {
		f.Fmtp = strings.TrimSpace(params)
	}
}

// OnHold reports whether the section signals "on hold" in either of the two
// ways RFC 6337 describes: a=sendonly or a=inactive, or the legacy
// unspecified connection address (c=IN IP4 0.0.0.0). A disabled section
// (port 0) is not on hold.
func (m Media) OnHold() bool {
	if m.Port == 0 {
		return false
	}
	return m.Direction == DirSendOnly || m.Direction == DirInactive ||
		(m.Addr.IsValid() && m.Addr.IsUnspecified())
}

// Codecs returns the encoding names of the formats in m-line order. Unknown
// dynamic payload types are named "PT<n>" and non-numeric formats keep their token.
func (m Media) Codecs() []string {
	if len(m.Formats) == 0 {
		return nil
	}
	out := make([]string, len(m.Formats))
	for i, f := range m.Formats {
		out[i] = f.String()
	}
	return out
}

// String returns the encoding name of the format, "PT<n>" if it is an unknown
// dynamic payload type.
func (f Format) String() string {
	if f.Name != "" {
		return f.Name
	}
	return "PT" + strconv.Itoa(f.PT)
}
