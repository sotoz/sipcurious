package stats

import (
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// scenario returns a capture with
//
//	A  answered, completed: INVITE 0, 180 @200, 200 @2200, BYE @12200 (talk 10s), PCMU
//	B  answered, completed: INVITE 1000, 180 @1500, 200 @3000, BYE @33000 (talk 30s), PCMA, no media
//	C  486 busy (user caused)
//	D  503
//	E  cancelled
//	F  no response, INVITE sent three times (2 retransmissions)
//	H  404 (user caused)
//	G  REGISTER over TCP, 200
func scenario() Input {
	sdpA1, sdpA2 := sdpBody("10.0.0.1", 4000, "PCMU", 0), sdpBody("10.0.1.2", 6000, "PCMU", 0)
	sdpB1, sdpB2 := sdpBody("10.0.0.1", 4002, "PCMA", 8), sdpBody("10.0.1.2", 6002, "PCMA", 8)
	a := newFlow("A", "1001", "2001").invite(0, sdpA1).resp(10, 100, "").resp(200, 180, "").resp(2200, 200, sdpA2).ack(2210).bye(12200).byeResp(12210)
	b := newFlow("B", "1001", "2002").invite(1000, sdpB1).resp(1500, 180, "").resp(3000, 200, sdpB2).ack(3010).bye(33000).byeResp(33010)
	c := newFlow("C", "1002", "2001").invite(1000, "").resp(1400, 486, "").ack(1410)
	d := newFlow("D", "1003", "2003").invite(5000, "").resp(5100, 503, "").ack(5110)
	e := newFlow("E", "1004", "2004").invite(6000, "").resp(6100, 180, "").cancel(7000).cancelResp(7005, 200).resp(7010, 487, "").ack(7020)
	f := newFlow("F", "1005", "2005").invite(8000, "").invite(8500, "").invite(9500, "")
	h := newFlow("H", "1006", "2006").invite(9000, "").resp(9050, 404, "").ack(9060)
	g := newFlow("G", "1001", "1001").register(500).registerOK(520)
	msgs := buildMessages(a, b, c, d, e, f, h, g)
	slices.SortStableFunc(msgs, func(x, y trace.Message) int { return x.Time.Compare(y.Time) })

	calls := call.Build(msgs, call.Options{})
	streams := []rtp.Stream{
		{Key: rtpKey("10.0.0.1:4000", "10.0.1.2:6000", 1), Start: t0.Add(ms(2300)), End: t0.Add(ms(12100)), Codec: "PCMU", Packets: 490, LossPct: 2, JitterMean: ms(5), JitterMax: ms(9), MOS: 4.2},
		{Key: rtpKey("10.0.1.2:6000", "10.0.0.1:4000", 2), Start: t0.Add(ms(2300)), End: t0.Add(ms(12100)), Codec: "PCMU", Packets: 480, LossPct: 0.5, JitterMean: ms(20), JitterMax: ms(30), MOS: 3.8},
		{Key: rtpKey("10.9.9.9:8000", "10.9.9.8:8000", 3), Start: t0.Add(ms(100)), End: t0.Add(ms(40000)), Codec: "PCMA", Packets: 100, MOS: 4.4},
	}
	call.Attach(calls, streams)
	return Input{Messages: msgs, Calls: calls, Streams: streams, Packets: 120, Skipped: 7, Files: []string{"t.pcap"}}
}

func TestScenario(t *testing.T) {
	in := scenario()
	s := Compute(in)

	eq := func(name string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
	eq("files", s.Files, []string{"t.pcap"})
	eq("packets", [2]int{s.Packets, s.Skipped}, [2]int{120, 7})
	eq("start", s.Start, t0)
	eq("end", s.End, t0.Add(ms(40000))) // the unrelated RTP stream ends last
	eq("duration", s.Duration, ms(40000))

	sip := s.SIP
	eq("messages", sip.Messages, len(in.Messages))
	eq("req+resp", sip.Requests+sip.Responses, sip.Messages)
	eq("methods", sip.Methods, []Count{
		{"INVITE", 9}, {"ACK", 6}, {"BYE", 2}, {"CANCEL", 1}, {"REGISTER", 1},
	})
	eq("statuses", sip.Statuses, []StatusCount{
		{100, "Trying", 1}, {180, "Ringing", 3}, {200, "OK", 6}, {404, "Not Found", 1},
		{486, "Busy Here", 1}, {487, "Request Terminated", 1}, {503, "Service Unavailable", 1},
	})
	eq("classes", sip.Classes, []Count{{"1xx", 4}, {"2xx", 6}, {"3xx", 0}, {"4xx", 3}, {"5xx", 1}, {"6xx", 0}})
	eq("transports", sip.Transports, []Count{{"UDP", sip.Messages - 2}, {"TCP", 2}})
	eq("hosts", sip.Hosts, 2)
	eq("endpoints", sip.Endpoints, 2)
	eq("top sources", sip.TopSources, []Count{{"10.0.0.1", sip.Requests}, {"10.0.1.2", sip.Responses}})
	eq("retransmissions", sip.Retransmissions, 2)

	c := s.Calls
	eq("total", c.Total, 8)
	eq("kinds", c.Kinds, []Count{{"call", 7}, {"registration", 1}})
	eq("attempts", c.Attempts, 7)
	eq("answered", c.Answered, 2)
	eq("user caused", c.UserCaused, 2)
	eq("completed", c.Completed, 2)
	approx(t, "ASR", c.ASR, 200.0/7)
	approx(t, "adjusted ASR", c.AdjustedASR, 40)
	eq("ACD", c.ACD, 20*time.Second)
	eq("peak concurrent", c.PeakConcurrent, Peak{2, t0.Add(ms(3000))})
	eq("peak rate", c.PeakAttemptRate, Peak{2, t0.Add(ms(1000))})
	eq("pdd", c.PDD, Dist{N: 2, Min: ms(200), Mean: ms(350), P50: ms(200), P90: ms(500), P95: ms(500), P99: ms(500), Max: ms(500)})
	eq("ring", c.Ring, Dist{N: 2, Min: ms(1500), Mean: ms(1750), P50: ms(1500), P90: ms(2000), P95: ms(2000), P99: ms(2000), Max: ms(2000)})
	eq("setup", c.Setup, Dist{N: 2, Min: ms(2000), Mean: ms(2100), P50: ms(2000), P90: ms(2200), P95: ms(2200), P99: ms(2200), Max: ms(2200)})
	eq("talk", c.Talk, Dist{N: 2, Min: 10 * time.Second, Mean: 20 * time.Second, P50: 10 * time.Second, P90: 30 * time.Second, P95: 30 * time.Second, P99: 30 * time.Second, Max: 30 * time.Second})
	eq("states", c.States, []KindState{
		{call.KindCall, call.StateFailed, 3}, {call.KindCall, call.StateCompleted, 2},
		{call.KindCall, call.StateCancelled, 1}, {call.KindCall, call.StateNoResponse, 1},
		{call.KindRegistration, call.StateOK, 1},
	})
	eq("failure groups", c.FailureGroups, 4)
	eq("failures", c.Failures, []Failure{
		{call.KindCall, call.StateFailed, 404, "Not Found", 1, "H"},
		{call.KindCall, call.StateFailed, 486, "Busy Here", 1, "C"},
		{call.KindCall, call.StateFailed, 503, "Service Unavailable", 1, "D"},
		{call.KindCall, call.StateNoResponse, 0, "", 1, "F"},
	})
	eq("user agents", c.UserAgents, []Count{{"PhoneA/1.0", 7}, {"PBX-B/2.0", 6}})
	eq("top calling[0]", c.TopCalling[0], Number{"1001", 2, 2})
	eq("top calling len", len(c.TopCalling), 6)
	eq("top called[0]", c.TopCalled[0], Number{"2001", 2, 1})
	eq("negotiated", c.NegotiatedCodecs, []Count{{"PCMA", 1}, {"PCMU", 1}})
	eq("no media", c.NoMedia, 1)

	r := s.RTP
	eq("streams", r.Streams, 3)
	eq("rtp packets", r.Packets, uint64(1070))
	eq("mos streams", r.MOSStreams, 3)
	approx(t, "mos min", r.MOSMin, 3.8)
	approx(t, "mos p5", r.MOSP5, 3.8)
	approx(t, "mos mean", r.MOSMean, (4.2+3.8+4.4)/3)
	eq("codecs", r.Codecs, []Count{{"PCMU", 2}, {"PCMA", 1}})
	if len(r.WorstLoss) != 2 || r.WorstLoss[0].LossPct != 2 || r.WorstLoss[0].CallID != "A" || r.WorstLoss[0].Leg != "caller->callee" {
		t.Errorf("worst loss = %+v", r.WorstLoss)
	}
	if len(r.WorstJitter) != 2 || r.WorstJitter[0].JitterMean != ms(20) || r.WorstJitter[0].Leg != "callee->caller" {
		t.Errorf("worst jitter = %+v", r.WorstJitter)
	}
}

func approx(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

func rtpKey(src, dst string, ssrc uint32) rtp.Key {
	return rtp.Key{Src: ap(src), Dst: ap(dst), SSRC: ssrc}
}

func TestPercentiles(t *testing.T) {
	d := func(n ...int) []time.Duration {
		out := make([]time.Duration, len(n))
		for i, v := range n {
			out[i] = time.Duration(v)
		}
		return out
	}
	tests := []struct {
		name string
		in   []time.Duration
		want Dist
	}{
		{"empty", nil, Dist{}},
		{"one", d(7), Dist{N: 1, Min: 7, Mean: 7, P50: 7, P90: 7, P95: 7, P99: 7, Max: 7}},
		{"two", d(20, 10), Dist{N: 2, Min: 10, Mean: 15, P50: 10, P90: 20, P95: 20, P99: 20, Max: 20}},
		{"ten", d(10, 9, 8, 7, 6, 5, 4, 3, 2, 1), Dist{N: 10, Min: 1, Mean: 5, P50: 5, P90: 9, P95: 10, P99: 10, Max: 10}},
		{"hundred", seq(100), Dist{N: 100, Min: 1, Mean: 50, P50: 50, P90: 90, P95: 95, P99: 99, Max: 100}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dist(slices.Clone(tt.in)); got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func seq(n int) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = time.Duration(n - i)
	}
	return out
}

func TestPeakConcurrent(t *testing.T) {
	iv := func(pairs ...int64) []interval {
		var out []interval
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, interval{pairs[i], pairs[i+1]})
		}
		return out
	}
	tests := []struct {
		name string
		in   []interval
		val  int
		at   int64
	}{
		{"none", nil, 0, 0},
		{"single", iv(5, 9), 1, 5},
		{"touching do not overlap", iv(0, 10, 10, 20, 20, 30), 1, 0},
		{"overlap by one ns", iv(0, 11, 10, 20), 2, 10},
		{"nested", iv(0, 100, 10, 20, 15, 18), 3, 15},
		{"first max wins", iv(0, 10, 5, 10, 20, 30, 25, 30), 2, 5},
		{"zero length counts one ns", iv(5, 5, 5, 5, 6, 8), 2, 5},
		{"reversed interval", iv(9, 3, 9, 4), 2, 9},
		{"same start", iv(1, 5, 1, 6, 1, 7), 3, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peakConcurrent(tt.in)
			if got.Value != tt.val {
				t.Fatalf("value = %d, want %d", got.Value, tt.val)
			}
			if tt.val > 0 && got.At != time.Unix(0, tt.at).UTC() {
				t.Errorf("at = %v, want %v", got.At.UnixNano(), tt.at)
			}
			if tt.val == 0 && !got.At.IsZero() {
				t.Errorf("at = %v, want zero", got.At)
			}
		})
	}
}

func TestPeakRate(t *testing.T) {
	sec := int64(time.Second)
	tests := []struct {
		name string
		in   []int64
		val  int
		at   int64
	}{
		{"none", nil, 0, 0},
		{"one", []int64{5}, 1, 5},
		{"window is half open", []int64{0, sec, 2 * sec}, 1, 0},
		{"burst", []int64{9 * sec, 0, sec - 1, 10, 9*sec + 5}, 3, 0},
		{"later burst wins only when larger", []int64{0, 1, 5 * sec, 5*sec + 1}, 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peakRate(slices.Clone(tt.in), time.Second)
			if got.Value != tt.val || (tt.val > 0 && got.At != time.Unix(0, tt.at).UTC()) {
				t.Errorf("got %+v, want %d at %d", got, tt.val, tt.at)
			}
		})
	}
}

func TestASRDefinitions(t *testing.T) {
	mk := func(state call.State, code int, caller bool) call.Call {
		c := call.Call{Kind: call.KindCall, State: state, FinalCode: code, Start: t0}
		if caller {
			c.Caller = alice
		}
		return c
	}
	calls := []call.Call{
		mk(call.StateCompleted, 200, true),
		mk(call.StateAnswered, 200, true),
		mk(call.StateCancelled, 487, true),  // stays in both denominators
		mk(call.StateFailed, 486, true),     // user caused
		mk(call.StateFailed, 603, true),     // user caused
		mk(call.StateFailed, 503, true),     // network
		mk(call.StateNoResponse, 0, true),   // network
		mk(call.StateCancelled, 487, false), // mid-dialog: not an attempt
		mk(call.StateCompleted, 200, false), // mid-dialog: not an attempt, not counted as answered
		{Kind: call.KindRegistration, State: call.StateFailed, FinalCode: 404, Caller: alice},
	}
	c := Compute(Input{Calls: calls}).Calls
	if c.Attempts != 7 || c.Answered != 2 || c.UserCaused != 2 {
		t.Fatalf("attempts=%d answered=%d user=%d", c.Attempts, c.Answered, c.UserCaused)
	}
	approx(t, "ASR", c.ASR, 100*2.0/7)
	approx(t, "adjusted", c.AdjustedASR, 100*2.0/5)

	// Only user-caused failures: adjusted denominator is 0, no NaN/Inf.
	c = Compute(Input{Calls: []call.Call{mk(call.StateFailed, 486, true)}}).Calls
	if c.ASR != 0 || c.AdjustedASR != 0 {
		t.Errorf("asr=%v adjusted=%v", c.ASR, c.AdjustedASR)
	}
}

func TestEmpty(t *testing.T) {
	for _, in := range []Input{{}, {Messages: []trace.Message{}, Calls: []call.Call{}, Streams: []rtp.Stream{}}} {
		s := Compute(in)
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "null") {
			t.Errorf("null in JSON: %s", b)
		}
		if !s.Start.IsZero() || s.Duration != 0 || s.Calls.ASR != 0 {
			t.Errorf("non-zero summary: %+v", s)
		}
		checkSections(t, s)
		_ = s.KeyValues()
	}
}

func checkSections(t *testing.T, s Summary) {
	t.Helper()
	secs := s.Sections(report.Options{UTC: true})
	seen := map[string]bool{}
	for _, sec := range secs {
		if seen[sec.Name] {
			t.Errorf("duplicate section %q", sec.Name)
		}
		seen[sec.Name] = true
		for _, row := range sec.Table.Rows {
			for _, v := range row {
				if f, ok := v.(float64); ok && (math.IsNaN(f) || math.IsInf(f, 0)) {
					t.Errorf("%s: non-finite cell", sec.Name)
				}
			}
		}
	}
	for _, f := range []report.Format{report.FormatJSON, report.FormatTable, report.FormatMarkdown, report.FormatHTML} {
		var sb strings.Builder
		if err := report.WriteSections(&sb, f, secs, report.Options{UTC: true}); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func TestSections(t *testing.T) {
	s := Compute(scenario())
	checkSections(t, s)
	secs := s.Sections(report.Options{UTC: true})
	var sb strings.Builder
	if err := report.WriteSections(&sb, report.FormatJSON, secs, report.Options{UTC: true}); err != nil {
		t.Fatal(err)
	}
	var doc map[string][]map[string]any
	if err := json.Unmarshal([]byte(sb.String()), &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"overview", "sip_methods", "sip_status", "sip_classes", "transports", "top_sources",
		"top_destinations", "user_agents", "call_states", "timings", "failures", "top_calling", "top_called",
		"negotiated_codecs", "rtp_codecs", "rtp_worst_loss", "rtp_worst_jitter"} {
		if _, ok := doc[name]; !ok {
			t.Errorf("missing section %q", name)
		}
	}
	if got := doc["timings"][3]["p90_ms"]; got != 30000.0 {
		t.Errorf("talk p90_ms = %v", got)
	}
	if got := doc["rtp_worst_loss"][0]["call_id"]; got != "A" {
		t.Errorf("worst loss call = %v", got)
	}
	if got := doc["sip_status"][0]["code"]; got != 100.0 {
		t.Errorf("first status = %v", got)
	}
	// Overview ASR row.
	var asr any
	for _, r := range doc["overview"] {
		if r["metric"] == "ASR %" {
			asr = r["value"]
		}
	}
	if asr != "28.6" {
		t.Errorf("overview ASR = %v", asr)
	}
	kv := s.KeyValues()
	if len(kv) == 0 || kv[0].Key != "Capture duration" {
		t.Errorf("key values: %+v", kv)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	s := Compute(scenario())
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back Summary
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s, back) {
		t.Errorf("round trip differs:\n%+v\n%+v", s, back)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]any) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	want := []string{"calls", "duration_ns", "end", "files", "packets", "rtp", "sip", "skipped", "start"}
	if got := keys(generic); !slices.Equal(got, want) {
		t.Errorf("top-level keys = %v", got)
	}
	calls := generic["calls"].(map[string]any)
	for _, k := range []string{"asr_pct", "asr_adjusted_pct", "acd_ns", "peak_concurrent", "peak_attempts_per_second",
		"pdd", "setup", "ring", "talk", "failures", "user_agents", "top_calling", "top_called", "negotiated_codecs", "no_media"} {
		if _, ok := calls[k]; !ok {
			t.Errorf("missing calls.%s", k)
		}
	}
	rt := generic["rtp"].(map[string]any)
	for _, k := range []string{"streams", "packets", "mos_min", "mos_p5", "mos_mean", "worst_loss", "worst_jitter", "codecs"} {
		if _, ok := rt[k]; !ok {
			t.Errorf("missing rtp.%s", k)
		}
	}
}

func TestTopListsLimits(t *testing.T) {
	var calls []call.Call
	for i := 0; i < 25; i++ {
		calls = append(calls, call.Call{
			CallID: string(rune('a' + i)), Kind: call.KindCall, State: call.StateFailed, FinalCode: 500 + i,
			Caller: alice, Start: t0, FromUser: string(rune('a' + i)), ToUser: "x",
			UserAgents: []string{string(rune('A' + i))},
		})
	}
	var streams []rtp.Stream
	for i := 0; i < 9; i++ {
		streams = append(streams, rtp.Stream{Key: rtpKey("10.0.0.1:1000", "10.0.0.2:1000", uint32(i)), LossPct: float64(i), JitterMean: ms(i), Packets: 1})
	}
	s := Compute(Input{Calls: calls, Streams: streams})
	if len(s.Calls.Failures) != 10 || s.Calls.FailureGroups != 25 || len(s.Calls.UserAgents) != 10 ||
		len(s.Calls.TopCalling) != 10 || len(s.Calls.TopCalled) != 1 {
		t.Errorf("limits: %d %d %d %d %d", len(s.Calls.Failures), s.Calls.FailureGroups, len(s.Calls.UserAgents), len(s.Calls.TopCalling), len(s.Calls.TopCalled))
	}
	if len(s.RTP.WorstLoss) != 5 || s.RTP.WorstLoss[0].SSRC != 8 || s.RTP.WorstLoss[4].SSRC != 4 {
		t.Errorf("worst loss: %+v", s.RTP.WorstLoss)
	}
	if len(s.RTP.WorstJitter) != 5 || s.RTP.WorstJitter[0].SSRC != 8 {
		t.Errorf("worst jitter: %+v", s.RTP.WorstJitter)
	}
}

func TestDoesNotMutateInput(t *testing.T) {
	in := scenario()
	before, _ := json.Marshal(in.Streams)
	callsBefore := len(in.Calls)
	order := make([]string, len(in.Calls))
	for i, c := range in.Calls {
		order[i] = c.CallID
	}
	Compute(in)
	after, _ := json.Marshal(in.Streams)
	if string(before) != string(after) || len(in.Calls) != callsBefore {
		t.Error("input modified")
	}
	for i, c := range in.Calls {
		if c.CallID != order[i] {
			t.Error("calls reordered")
		}
	}
}
