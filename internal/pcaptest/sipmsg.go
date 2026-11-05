package pcaptest

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// msg is a SIP message under construction.
type msg struct {
	start string
	hdr   [][2]string
	body  string

	// scenario metadata (never serialised)
	method string // request method, or method of the CSeq for responses
	code   int    // response status, 0 for requests
	cseq   int
	branch string // top Via branch
}

func (m *msg) add(name, value string) *msg {
	m.hdr = append(m.hdr, [2]string{name, value})
	return m
}

func (m *msg) get(name string) string {
	for _, h := range m.hdr {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// bytes renders the message with a correct Content-Length.
func (m *msg) bytes() []byte {
	var sb strings.Builder
	sb.Grow(512 + len(m.body))
	sb.WriteString(m.start)
	sb.WriteString("\r\n")
	for _, h := range m.hdr {
		sb.WriteString(h[0])
		sb.WriteString(": ")
		sb.WriteString(h[1])
		sb.WriteString("\r\n")
	}
	sb.WriteString("Content-Length: ")
	sb.WriteString(strconv.Itoa(len(m.body)))
	sb.WriteString("\r\n\r\n")
	sb.WriteString(m.body)
	return []byte(sb.String())
}

const (
	alnum = "abcdefghijklmnopqrstuvwxyz0123456789"
	hexch = "0123456789abcdef"
)

func (b *Builder) token(n int, alphabet string) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = alphabet[b.rng.IntN(len(alphabet))]
	}
	return string(buf)
}

func (b *Builder) newBranch() string { return "z9hG4bK" + b.token(12, alnum) }
func (b *Builder) newTag() string    { return b.token(10, alnum) }
func (b *Builder) newCallID(host string) string {
	return b.token(16, alnum) + "@" + host
}

func hostPort(ap netip.AddrPort) string {
	if ap.Addr().Is6() {
		return "[" + ap.Addr().String() + "]:" + strconv.Itoa(int(ap.Port()))
	}
	return ap.String()
}

func hostOnly(a netip.Addr) string {
	if a.Is6() {
		return "[" + a.String() + "]"
	}
	return a.String()
}

// reasonPhrase returns the standard reason phrase for code.
func reasonPhrase(code int) string {
	switch code {
	case 100:
		return "Trying"
	case 180:
		return "Ringing"
	case 181:
		return "Call Is Being Forwarded"
	case 183:
		return "Session Progress"
	case 200:
		return "OK"
	case 202:
		return "Accepted"
	case 302:
		return "Moved Temporarily"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 407:
		return "Proxy Authentication Required"
	case 408:
		return "Request Timeout"
	case 480:
		return "Temporarily Unavailable"
	case 481:
		return "Call/Transaction Does Not Exist"
	case 486:
		return "Busy Here"
	case 487:
		return "Request Terminated"
	case 488:
		return "Not Acceptable Here"
	case 500:
		return "Server Internal Error"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Server Time-out"
	case 600:
		return "Busy Everywhere"
	case 603:
		return "Decline"
	case 604:
		return "Does Not Exist Anywhere"
	}
	return "Unknown"
}

// ntpTime converts t to a 64 bit NTP timestamp (seconds since 1900).
func ntpTime(t time.Time) uint64 {
	const ntpEpochOffset = 2208988800
	sec := uint64(t.Unix()) + ntpEpochOffset
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	return sec<<32 | frac
}

func digestResponse(b *Builder) string { return b.token(32, hexch) }

func quoted(s string) string { return fmt.Sprintf("%q", s) }
