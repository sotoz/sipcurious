// Package stats computes capture-wide statistics (the "what is in this pcap"
// summary a Voice/SIP team wants in ten seconds) from the messages, calls and
// RTP streams of a loaded capture, and renders them as report tables and
// HTML summary cards.
//
// Everything is O(n log n) in the input size, never divides by zero and never
// produces NaN: a metric that cannot be computed is zero in Summary (check
// the matching count, e.g. CallStats.Attempts) and an empty cell in the
// report tables.
//
// # Definitions
//
// An attempt is a call of kind [call.KindCall] whose initial INVITE was
// captured ([call.Call.Caller] is valid); calls that start mid-dialog and
// non-INVITE Call-IDs are never attempts. An answered call is an attempt
// whose state is answered or completed.
//
//   - ASR (answer-seizure ratio, ITU-T E.411) = 100 * answered / attempts.
//     Cancelled, unanswered and in-setup calls stay in the denominator.
//   - Adjusted ASR = 100 * answered / (attempts - user-caused failures).
//     A user-caused failure is an attempt in state failed with a final
//     response of 486, 480, 404 or 603.
//   - ACD (average call duration) = mean TalkTime of the completed calls
//     (answered, then cleared by BYE). Calls still up at the end of the
//     capture have no known duration and are left out.
//   - Peak concurrent calls: sweep line over [Answered, end] of every
//     answered call, where end is the first BYE ([call.Call.Ended]) or, when
//     none was captured, the last message of the call. Intervals that only
//     touch (one ends at the instant another starts) do not overlap; an
//     interval of zero length counts as one nanosecond.
//   - Peak INVITE attempts per second: the largest number of attempts whose
//     first INVITE falls into a window [t, t+1s) starting at an attempt.
//   - Percentiles use the nearest-rank method: for n sorted values the p-th
//     percentile is the value at 1-based rank ceil(p*n/100); n = 0 gives 0.
//     PDD, ring and setup time are taken over answered attempts for which the
//     value is positive (zero means "not captured"); talk time over completed
//     calls.
package stats

import (
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// Input is everything Compute looks at. Streams should be the streams as
// returned by the RTP handler; streams correlated by [call.Attach] are found
// through the Calls to name the call of the worst streams.
type Input struct {
	Messages         []trace.Message
	Calls            []call.Call
	Streams          []rtp.Stream
	Packets, Skipped int
	Files            []string
}

// Count is a named counter. Count slices are sorted by count (descending)
// and then by key, unless documented otherwise.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// StatusCount is the number of responses with one status code.
type StatusCount struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"` // reason phrase of the first response seen with this code
	Count  int    `json:"count"`
}

// KindState is the number of calls of one kind in one state.
type KindState struct {
	Kind  call.Kind  `json:"kind"`
	State call.State `json:"state"`
	Count int        `json:"count"`
}

// Peak is a maximum and the (first) moment it was reached.
type Peak struct {
	Value int       `json:"value"`
	At    time.Time `json:"at"` // zero when Value is 0
}

// Dist summarises a set of durations. All fields are zero when N is 0.
// Durations are nanoseconds in JSON.
type Dist struct {
	N    int           `json:"n"`
	Min  time.Duration `json:"min_ns"`
	Mean time.Duration `json:"mean_ns"`
	P50  time.Duration `json:"p50_ns"`
	P90  time.Duration `json:"p90_ns"`
	P95  time.Duration `json:"p95_ns"`
	P99  time.Duration `json:"p99_ns"`
	Max  time.Duration `json:"max_ns"`
}

// Failure is a group of unsuccessful calls with the same kind, state and final
// response code.
type Failure struct {
	Kind         call.Kind  `json:"kind"`
	State        call.State `json:"state"`
	Code         int        `json:"code"`   // final response code, 0 if there was none
	Reason       string     `json:"reason"` // reason phrase of the sample's final response
	Count        int        `json:"count"`
	SampleCallID string     `json:"sample_call_id"` // the earliest call of the group
}

// Number is how often a number (SIP user part) called or was called.
type Number struct {
	Number   string `json:"number"`
	Calls    int    `json:"calls"`
	Answered int    `json:"answered"`
}

// StreamRef identifies an RTP stream in the worst-streams lists.
type StreamRef struct {
	CallID     string        `json:"call_id"` // "" if the stream is not correlated to a call
	Leg        string        `json:"leg"`     // "caller->callee" / "callee->caller" or ""
	Src        string        `json:"src"`
	Dst        string        `json:"dst"`
	SSRC       uint32        `json:"ssrc"`
	Codec      string        `json:"codec"`
	Packets    uint64        `json:"packets"`
	LossPct    float64       `json:"loss_pct"`
	JitterMean time.Duration `json:"jitter_mean_ns"`
	JitterMax  time.Duration `json:"jitter_max_ns"`
	MOS        float64       `json:"mos"` // 0 if not computed
}

// SIPStats describes the SIP messages.
type SIPStats struct {
	Messages  int `json:"messages"`
	Requests  int `json:"requests"`
	Responses int `json:"responses"`
	// Methods counts requests per method.
	Methods []Count `json:"methods"`
	// Statuses counts responses per status code (100-699), ascending by code.
	Statuses []StatusCount `json:"statuses"`
	// Classes always has six entries, "1xx" to "6xx".
	Classes    []Count `json:"classes"`
	Transports []Count `json:"transports"`
	// Hosts is the number of distinct IP addresses, Endpoints of distinct
	// address:port pairs, over sources and destinations.
	Hosts     int `json:"hosts"`
	Endpoints int `json:"endpoints"`
	// TopSources and TopDestinations are the ten hosts that sent / received
	// most messages.
	TopSources      []Count `json:"top_sources"`
	TopDestinations []Count `json:"top_destinations"`
	// Retransmissions is the sum of Call.Retransmissions.
	Retransmissions int `json:"retransmissions"`
}

// CallStats describes the calls.
type CallStats struct {
	Total  int         `json:"total"` // every Call-ID, all kinds
	Kinds  []Count     `json:"kinds"`
	States []KindState `json:"states"` // ordered by kind, then state

	Attempts    int     `json:"attempts"` // INVITE attempts, see the package comment
	Answered    int     `json:"answered"`
	UserCaused  int     `json:"user_caused"` // failed with 486, 480, 404 or 603
	ASR         float64 `json:"asr_pct"`     // 0 when Attempts is 0
	AdjustedASR float64 `json:"asr_adjusted_pct"`
	// ACD is the mean talk time of the Completed calls.
	ACD       time.Duration `json:"acd_ns"`
	Completed int           `json:"completed"`

	PeakConcurrent  Peak `json:"peak_concurrent"`
	PeakAttemptRate Peak `json:"peak_attempts_per_second"`

	PDD   Dist `json:"pdd"`
	Setup Dist `json:"setup"`
	Ring  Dist `json:"ring"`
	Talk  Dist `json:"talk"`

	// Failures are the ten most frequent unsuccessful (failed, no-response,
	// in-setup, cancelled) kind/state/code groups.
	Failures []Failure `json:"failures"`
	// FailureGroups is the number of groups before cutting to ten.
	FailureGroups int `json:"failure_groups"`

	// UserAgents counts calls per User-Agent/Server value (top ten).
	UserAgents []Count `json:"user_agents"`
	// TopCalling and TopCalled rank From and To users of attempts (top ten).
	TopCalling []Number `json:"top_calling"`
	TopCalled  []Number `json:"top_called"`

	// NegotiatedCodecs counts answered calls by the first real codec of
	// their first enabled audio media (telephone-event and CN are skipped).
	NegotiatedCodecs []Count `json:"negotiated_codecs"`
	// NoMedia is the number of answered calls without any correlated RTP
	// stream; meaningful only when RTP.Streams > 0.
	NoMedia int `json:"no_media"`
}

// RTPStats describes the RTP streams.
type RTPStats struct {
	Streams int    `json:"streams"`
	Packets uint64 `json:"packets"`
	// MOSStreams is the number of streams with a computed MOS; the three MOS
	// values below are 0 when it is 0. MOSP5 is the nearest-rank 5th
	// percentile.
	MOSStreams int     `json:"mos_streams"`
	MOSMin     float64 `json:"mos_min"`
	MOSP5      float64 `json:"mos_p5"`
	MOSMean    float64 `json:"mos_mean"`
	// WorstLoss are the five streams with the highest loss (> 0 only),
	// WorstJitter the five with the highest mean jitter (> 0 only).
	WorstLoss   []StreamRef `json:"worst_loss"`
	WorstJitter []StreamRef `json:"worst_jitter"`
	// Codecs counts streams per codec ("unknown" if none).
	Codecs []Count `json:"codecs"`
}

// Summary is the result of Compute. Durations are nanoseconds in JSON (keys
// end in _ns), percentages are 0-100 (keys end in _pct), slices are never
// null.
type Summary struct {
	Files    []string      `json:"files"`
	Packets  int           `json:"packets"`
	Skipped  int           `json:"skipped"`
	Start    time.Time     `json:"start"` // first message or stream packet, zero if none
	End      time.Time     `json:"end"`   // last message or stream packet
	Duration time.Duration `json:"duration_ns"`

	SIP   SIPStats  `json:"sip"`
	Calls CallStats `json:"calls"`
	RTP   RTPStats  `json:"rtp"`
}
