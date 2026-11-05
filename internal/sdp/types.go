// Package sdp parses Session Description Protocol bodies (RFC 4566/8866) as
// found in SIP messages, as far as VoIP troubleshooting needs it.
package sdp

import "net/netip"

// Session is a parsed SDP body.
type Session struct {
	Origin     string     // o= line value
	Name       string     // s= line value
	Addr       netip.Addr // session-level c= address (invalid if absent or not an IP literal)
	Media      []Media
	Attributes []Attribute // session-level a= lines
}

// Media is one m= section.
type Media struct {
	Type       string // "audio", "video", "application", ...
	Port       uint16 // 0 means the stream is rejected/disabled
	Proto      string // "RTP/AVP", "RTP/SAVP", "UDP/TLS/RTP/SAVPF", ...
	Formats    []Format
	Addr       netip.Addr // effective connection address: media-level c= if present, else session-level; invalid if neither or not an IP literal
	Direction  string     // "sendrecv" (default), "sendonly", "recvonly", "inactive"
	PTime      int        // a=ptime in ms, 0 if absent
	RTCPMux    bool
	Secure     bool // a=crypto or a=fingerprint present, or SAVP/DTLS profile
	Attributes []Attribute
}

// Format is one payload type of a media section with its rtpmap/fmtp info.
type Format struct {
	PT        int    // payload type number
	Name      string // encoding name, e.g. "PCMU", "opus", "telephone-event" ("" if unknown dynamic PT)
	ClockRate int
	Channels  int
	Fmtp      string
}

// Attribute is an a= line: a=name or a=name:value.
type Attribute struct{ Name, Value string }

// Endpoint returns the RTP address:port announced by the media section
// (ok=false if the address is not an IP literal or the stream is disabled).
func (m Media) Endpoint() (netip.AddrPort, bool) {
	if !m.Addr.IsValid() || m.Port == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(m.Addr, m.Port), true
}

// RTCPEndpoint returns the RTCP address:port: a=rtcp if present, RTP port when
// rtcp-mux is on, else RTP port + 1.
func (m Media) RTCPEndpoint() (netip.AddrPort, bool) {
	ep, ok := m.Endpoint()
	if !ok {
		return netip.AddrPort{}, false
	}
	for _, a := range m.Attributes {
		if a.Name == "rtcp" {
			// "a=rtcp:<port> [IN IP4 <addr>]": the port is the first field.
			var port uint16
			for _, c := range a.Value {
				if c < '0' || c > '9' {
					break
				}
				port = port*10 + uint16(c-'0')
			}
			if port != 0 {
				return netip.AddrPortFrom(ep.Addr(), port), true
			}
		}
	}
	if m.RTCPMux {
		return ep, true
	}
	return netip.AddrPortFrom(ep.Addr(), ep.Port()+1), true
}
