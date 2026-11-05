// Package call groups SIP messages into calls/transactions by Call-ID,
// derives the call state and timing metrics, and correlates RTP streams.
package call

import (
	"net/netip"
	"time"

	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// Kind classifies a Call-ID by the method that opened it.
type Kind string

const (
	KindCall         Kind = "call"         // INVITE
	KindRegistration Kind = "registration" // REGISTER
	KindSubscription Kind = "subscription" // SUBSCRIBE / NOTIFY / REFER
	KindMessage      Kind = "message"      // MESSAGE
	KindOptions      Kind = "options"      // OPTIONS (keep-alives, health checks)
	KindOther        Kind = "other"
)

// State is where a call ended up as far as the capture shows.
type State string

const (
	StateInSetup    State = "in-setup"    // only provisional responses seen, capture ended
	StateNoResponse State = "no-response" // request(s) never got any response
	StateCancelled  State = "cancelled"   // caller CANCELled before answer
	StateRedirected State = "redirected"  // 3xx final response
	StateFailed     State = "failed"      // 4xx/5xx/6xx final response
	StateAnswered   State = "answered"    // 2xx to INVITE, no BYE seen (still up or capture ended)
	StateCompleted  State = "completed"   // answered and cleared with BYE
	StateOK         State = "ok"          // non-INVITE transaction got a 2xx
)

// Call is every message that shares one Call-ID plus the derived facts.
type Call struct {
	CallID   string
	Kind     Kind
	Method   string          // method of the first request ("" if only responses were captured)
	Messages []trace.Message // chronological, stable for equal timestamps

	Start, End time.Time
	From, To   string // From/To headers of the first message
	FromUser   string
	ToUser     string
	Caller     netip.AddrPort // source of the first request (zero if none captured)
	Callee     netip.AddrPort // destination of the first request

	State       State
	FinalCode   int    // status of the final response to the first request (0 if none)
	FinalReason string // reason phrase of that response
	Result      string // "<code> <reason>" of that response, "" if none

	// Timings; zero when the corresponding events were not captured.
	PDD       time.Duration // post-dial delay: first INVITE -> first 180/183 (or final response if none came first)
	RingTime  time.Duration // first 180/183 -> first 2xx (or final response)
	SetupTime time.Duration // first INVITE -> first 2xx
	TalkTime  time.Duration // first 2xx -> first BYE (INVITE calls)
	Answered  time.Time     // first 2xx to the INVITE
	Ended     time.Time     // first BYE (or CANCEL) time

	EndedBy   string // "caller", "callee" or "" (who sent the first BYE; for CANCEL always "caller")
	EndMethod string // "BYE", "CANCEL" or ""
	Reason    string // Reason header (RFC 3326) of the terminating request/response, "" if none

	Retransmissions int              // messages recognised as retransmissions (same branch/CSeq/method/direction repeated)
	UserAgents      []string         // distinct User-Agent / Server values in first-seen order
	Endpoints       []netip.AddrPort // distinct SIP signalling endpoints in first-seen order

	Media   []Media      // negotiated SDP media, one entry per m-line change over time (offer/answer, re-INVITE)
	Streams []rtp.Stream // RTP streams correlated to the call (call.Attach), CallID/Leg filled

	Attempts   int  // initial INVITE transactions (distinct CSeq) of an INVITE call; 2 after an auth challenge round
	Forks      int  // distinct To tags in the 101-299 responses to the deciding INVITE (>1: forking)
	MissingACK bool // 2xx to the INVITE was retransmitted and no ACK for it was captured (the caller never confirmed the answer)

	Related []string // Call-IDs of other legs of the same logical call (only when correlation was requested)
}

// Duration is End - Start.
func (c Call) Duration() time.Duration { return c.End.Sub(c.Start) }

// Media describes the media of one m-line as negotiated by SDP at a point in time.
type Media struct {
	Time      time.Time      // time of the message that completed/changed the description
	Type      string         // "audio", "video", ...
	Caller    netip.AddrPort // RTP endpoint announced by the caller side (zero if unknown)
	Callee    netip.AddrPort // RTP endpoint announced by the callee side (zero if unknown)
	Codecs    []string       // answer's codecs in preference order, e.g. ["PCMA", "telephone-event"]; offer's if no answer was seen
	Offered   []string       // offered codecs
	Direction string         // answer's direction (sendrecv/sendonly/recvonly/inactive); "hold" detection is derived from it
	PTime     int
	Secure    bool // SRTP/DTLS
	Disabled  bool // port 0 in the answer
	Early     bool // the (first) answer of this description arrived in a provisional response (early media)
	Hold      bool // either side signalled hold: sendonly/inactive or an unspecified (0.0.0.0/::) connection address
}

// Options tunes Build.
type Options struct {
	// CorrelateHeaders lists headers (e.g. "X-CID", "Session-ID") whose equal
	// value links Call-IDs into one logical call (B2BUA legs); results go in Call.Related.
	CorrelateHeaders []string
}
