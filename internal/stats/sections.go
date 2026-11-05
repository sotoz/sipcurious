package stats

import (
	"fmt"
	"strconv"
	"time"

	"github.com/sotoz/sipcurious/internal/report"
)

// Sections renders the summary as report tables. The set and order of
// sections and their names (the JSON keys) are fixed; sections without data
// are present with no rows. Tables hold typed cells and rely on the report
// writers for formatting; only the overview holds formatted text (times in
// the zone selected by o), so its values read the same in every format.
//
// Names: overview, sip_methods, sip_status, sip_classes, transports,
// top_sources, top_destinations, user_agents, call_states, timings,
// failures, top_calling, top_called, negotiated_codecs, rtp_codecs,
// rtp_worst_loss, rtp_worst_jitter.
func (s Summary) Sections(o report.Options) []report.Section {
	fmtTime := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		if o.UTC {
			return report.FormatTime(t, true)
		}
		if o.Location != nil {
			return t.In(o.Location).Format("2006-01-02T15:04:05.000Z07:00")
		}
		return report.FormatTime(t, false)
	}
	peak := func(p Peak) string {
		if p.Value == 0 {
			return "0"
		}
		return fmt.Sprintf("%d at %s", p.Value, fmtTime(p.At))
	}

	overview := report.Table{Title: "Overview", Columns: []report.Column{
		{Name: "Metric", Key: "metric"},
		{Name: "Value", Key: "value"},
	}}
	add := func(k, v string) { overview.Rows = append(overview.Rows, []any{k, v}) }
	add("Files", strconv.Itoa(len(s.Files)))
	add("Start", fmtTime(s.Start))
	add("End", fmtTime(s.End))
	add("Duration", report.FormatDuration(s.Duration))
	add("Packets read", strconv.Itoa(s.Packets))
	add("Packets skipped", strconv.Itoa(s.Skipped))
	add("SIP messages", strconv.Itoa(s.SIP.Messages))
	add("SIP requests", strconv.Itoa(s.SIP.Requests))
	add("SIP responses", strconv.Itoa(s.SIP.Responses))
	add("Retransmissions", strconv.Itoa(s.SIP.Retransmissions))
	add("Hosts", strconv.Itoa(s.SIP.Hosts))
	add("Endpoints", strconv.Itoa(s.SIP.Endpoints))
	add("Call-IDs", strconv.Itoa(s.Calls.Total))
	add("INVITE attempts", strconv.Itoa(s.Calls.Attempts))
	add("Answered", strconv.Itoa(s.Calls.Answered))
	add("ASR %", pct(s.Calls.ASR, s.Calls.Attempts > 0))
	add("Adjusted ASR %", pct(s.Calls.AdjustedASR, s.Calls.Attempts-s.Calls.UserCaused > 0))
	add("ACD", ifAny(s.Calls.Completed > 0, report.FormatDuration(s.Calls.ACD)))
	add("Peak concurrent calls", peak(s.Calls.PeakConcurrent))
	add("Peak INVITEs per second", peak(s.Calls.PeakAttemptRate))
	add("RTP streams", strconv.Itoa(s.RTP.Streams))
	add("RTP packets", strconv.FormatUint(s.RTP.Packets, 10))
	add("MOS min / p5 / mean", ifAny(s.RTP.MOSStreams > 0,
		fmt.Sprintf("%.2f / %.2f / %.2f", s.RTP.MOSMin, s.RTP.MOSP5, s.RTP.MOSMean)))
	add("Calls without media", ifAny(s.RTP.Streams > 0, strconv.Itoa(s.Calls.NoMedia)))

	return []report.Section{
		{Name: "overview", Table: overview},
		{Name: "sip_methods", Table: s.methodsTable()},
		{Name: "sip_status", Table: s.statusTable()},
		{Name: "sip_classes", Table: countTable("Response classes", "Class", "class", s.SIP.Classes, s.SIP.Responses)},
		{Name: "transports", Table: countTable("Transports", "Transport", "transport", s.SIP.Transports, s.SIP.Messages)},
		{Name: "top_sources", Table: countTable("Top sources", "Host", "host", s.SIP.TopSources, s.SIP.Messages)},
		{Name: "top_destinations", Table: countTable("Top destinations", "Host", "host", s.SIP.TopDestinations, s.SIP.Messages)},
		{Name: "user_agents", Table: countTable("User agents", "User-Agent", "user_agent", s.Calls.UserAgents, s.Calls.Total)},
		{Name: "call_states", Table: s.statesTable()},
		{Name: "timings", Table: s.timingsTable()},
		{Name: "failures", Table: s.failuresTable()},
		{Name: "top_calling", Table: numbersTable("Top calling numbers", s.Calls.TopCalling)},
		{Name: "top_called", Table: numbersTable("Top called numbers", s.Calls.TopCalled)},
		{Name: "negotiated_codecs", Table: countTable("Negotiated codecs (answered calls)", "Codec", "codec", s.Calls.NegotiatedCodecs, s.Calls.Answered)},
		{Name: "rtp_codecs", Table: countTable("RTP codecs (streams)", "Codec", "codec", s.RTP.Codecs, s.RTP.Streams)},
		{Name: "rtp_worst_loss", Table: streamsTable("Worst RTP streams by loss", s.RTP.WorstLoss)},
		{Name: "rtp_worst_jitter", Table: streamsTable("Worst RTP streams by jitter", s.RTP.WorstJitter)},
	}
}

// KeyValues returns the headline cards of the summary for the HTML report.
// Cards that do not apply (no calls, no RTP) are left out.
func (s Summary) KeyValues() report.KeyValues {
	var kv report.KeyValues
	add := func(k, v string, st report.Style) {
		kv = append(kv, report.KeyValue{Key: k, Value: v, Style: st})
	}
	add("Capture duration", report.FormatDuration(s.Duration), report.None)
	add("Packets", strconv.Itoa(s.Packets), report.None)
	if s.Skipped > 0 {
		add("Skipped packets", strconv.Itoa(s.Skipped), report.Dim)
	}
	add("SIP messages", strconv.Itoa(s.SIP.Messages), report.None)
	add("Endpoints", strconv.Itoa(s.SIP.Endpoints), report.None)
	if s.SIP.Retransmissions > 0 {
		add("Retransmissions", strconv.Itoa(s.SIP.Retransmissions), report.Warn)
	}
	c := s.Calls
	if c.Attempts > 0 {
		add("Calls", strconv.Itoa(c.Attempts), report.None)
		add("ASR", pct(c.ASR, true)+"%", asrStyle(c.ASR))
		if c.UserCaused > 0 {
			add("Adjusted ASR", pct(c.AdjustedASR, c.Attempts-c.UserCaused > 0)+"%", asrStyle(c.AdjustedASR))
		}
		if c.Completed > 0 {
			add("ACD", report.FormatDuration(c.ACD), report.None)
		}
		add("Peak concurrent", strconv.Itoa(c.PeakConcurrent.Value), report.None)
		if c.PDD.N > 0 {
			add("PDD p95", report.FormatDuration(c.PDD.P95), report.None)
		}
	}
	if s.RTP.Streams > 0 {
		add("RTP streams", strconv.Itoa(s.RTP.Streams), report.None)
		if s.RTP.MOSStreams > 0 {
			add("MOS mean", fmt.Sprintf("%.2f", s.RTP.MOSMean), mosStyle(s.RTP.MOSMean))
		}
		if c.NoMedia > 0 {
			add("Calls without media", strconv.Itoa(c.NoMedia), report.Warn)
		}
	}
	return kv
}

func ifAny(ok bool, v string) string {
	if ok {
		return v
	}
	return ""
}

func pct(v float64, ok bool) string {
	if !ok {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func asrStyle(v float64) report.Style {
	switch {
	case v >= 90:
		return report.Good
	case v >= 60:
		return report.Warn
	}
	return report.Bad
}

func mosStyle(v float64) report.Style {
	switch {
	case v >= 4:
		return report.Good
	case v >= 3.1:
		return report.Warn
	}
	return report.Bad
}

// share returns 100*n/total, 0 for an empty total.
func share(n, total int) float64 { return percent(n, total) }

var pctCol = report.Column{Name: "%", Key: "pct", Kind: report.Float}

func countTable(title, keyName, key string, rows []Count, total int) report.Table {
	t := report.Table{Title: title, Columns: []report.Column{
		{Name: keyName, Key: key},
		{Name: "Count", Key: "count", Kind: report.Int},
		pctCol,
	}, Rows: make([][]any, 0, len(rows))}
	for _, r := range rows {
		t.Rows = append(t.Rows, []any{r.Key, r.Count, share(r.Count, total)})
	}
	return t
}

func (s Summary) methodsTable() report.Table {
	t := countTable("SIP requests by method", "Method", "method", s.SIP.Methods, s.SIP.Requests)
	return t
}

func (s Summary) statusTable() report.Table {
	statusStyle := func(v any) report.Style {
		if c, ok := v.(int); ok {
			return report.StatusStyle(c)
		}
		return report.None
	}
	t := report.Table{Title: "SIP responses by status code", Columns: []report.Column{
		{Name: "Code", Key: "code", Kind: report.Int, Style: statusStyle},
		{Name: "Reason", Key: "reason"},
		{Name: "Count", Key: "count", Kind: report.Int},
		pctCol,
	}, Rows: make([][]any, 0, len(s.SIP.Statuses))}
	for _, r := range s.SIP.Statuses {
		t.Rows = append(t.Rows, []any{r.Code, r.Reason, r.Count, share(r.Count, s.SIP.Responses)})
	}
	return t
}

func (s Summary) statesTable() report.Table {
	state := func(v any) report.Style {
		switch v {
		case "completed", "answered", "ok":
			return report.Good
		case "failed":
			return report.Bad
		case "no-response", "in-setup":
			return report.Warn
		case "cancelled", "redirected":
			return report.None
		}
		return report.None
	}
	t := report.Table{Title: "Calls by kind and state", Columns: []report.Column{
		{Name: "Kind", Key: "kind"},
		{Name: "State", Key: "state", Style: state},
		{Name: "Count", Key: "count", Kind: report.Int},
		pctCol,
	}, Rows: make([][]any, 0, len(s.Calls.States))}
	for _, r := range s.Calls.States {
		t.Rows = append(t.Rows, []any{string(r.Kind), string(r.State), r.Count, share(r.Count, s.Calls.Total)})
	}
	return t
}

func (s Summary) timingsTable() report.Table {
	t := report.Table{Title: "Timings (nearest-rank percentiles)", Columns: []report.Column{
		{Name: "Metric", Key: "metric"},
		{Name: "N", Key: "n", Kind: report.Int},
		{Name: "Min", Key: "min", Kind: report.Duration},
		{Name: "Mean", Key: "mean", Kind: report.Duration},
		{Name: "P50", Key: "p50", Kind: report.Duration},
		{Name: "P90", Key: "p90", Kind: report.Duration},
		{Name: "P95", Key: "p95", Kind: report.Duration},
		{Name: "P99", Key: "p99", Kind: report.Duration},
		{Name: "Max", Key: "max", Kind: report.Duration},
	}}
	for _, r := range []struct {
		name string
		d    Dist
	}{{"PDD", s.Calls.PDD}, {"Ring time", s.Calls.Ring}, {"Setup time", s.Calls.Setup}, {"Talk time", s.Calls.Talk}} {
		row := []any{r.name, r.d.N}
		if r.d.N > 0 {
			row = append(row, r.d.Min, r.d.Mean, r.d.P50, r.d.P90, r.d.P95, r.d.P99, r.d.Max)
		}
		t.Rows = append(t.Rows, row)
	}
	return t
}

func (s Summary) failuresTable() report.Table {
	code := func(v any) report.Style {
		if c, ok := v.(int); ok && c != 0 {
			return report.StatusStyle(c)
		}
		return report.None
	}
	t := report.Table{Title: "Top failures", Columns: []report.Column{
		{Name: "Kind", Key: "kind"},
		{Name: "State", Key: "state"},
		{Name: "Code", Key: "code", Kind: report.Int, Style: code},
		{Name: "Reason", Key: "reason"},
		{Name: "Count", Key: "count", Kind: report.Int},
		{Name: "Sample Call-ID", Key: "sample_call_id"},
	}, Rows: make([][]any, 0, len(s.Calls.Failures))}
	for _, f := range s.Calls.Failures {
		var c any
		if f.Code != 0 {
			c = f.Code
		}
		t.Rows = append(t.Rows, []any{string(f.Kind), string(f.State), c, f.Reason, f.Count, f.SampleCallID})
	}
	return t
}

func numbersTable(title string, rows []Number) report.Table {
	t := report.Table{Title: title, Columns: []report.Column{
		{Name: "Number", Key: "number"},
		{Name: "Calls", Key: "calls", Kind: report.Int},
		{Name: "Answered", Key: "answered", Kind: report.Int},
		{Name: "ASR %", Key: "asr_pct", Kind: report.Float},
	}, Rows: make([][]any, 0, len(rows))}
	for _, r := range rows {
		t.Rows = append(t.Rows, []any{r.Number, r.Calls, r.Answered, percent(r.Answered, r.Calls)})
	}
	return t
}

func streamsTable(title string, rows []StreamRef) report.Table {
	loss := func(v any) report.Style {
		f, ok := v.(float64)
		switch {
		case !ok:
			return report.None
		case f >= 5:
			return report.Bad
		case f >= 1:
			return report.Warn
		}
		return report.None
	}
	mos := func(v any) report.Style {
		if f, ok := v.(float64); ok && f > 0 {
			return mosStyle(f)
		}
		return report.None
	}
	t := report.Table{Title: title, Columns: []report.Column{
		{Name: "Call-ID", Key: "call_id"},
		{Name: "Direction", Key: "direction"},
		{Name: "Source", Key: "src"},
		{Name: "Destination", Key: "dst"},
		{Name: "SSRC", Key: "ssrc", Extra: true},
		{Name: "Codec", Key: "codec"},
		{Name: "Packets", Key: "packets", Kind: report.Int},
		{Name: "Loss %", Key: "loss_pct", Kind: report.Float, Style: loss},
		{Name: "Jitter", Key: "jitter", Kind: report.Duration},
		{Name: "Max jitter", Key: "jitter_max", Kind: report.Duration, Extra: true},
		{Name: "MOS", Key: "mos", Kind: report.Float, Style: mos},
	}, Rows: make([][]any, 0, len(rows))}
	for _, r := range rows {
		var m any
		if r.MOS > 0 {
			m = r.MOS
		}
		t.Rows = append(t.Rows, []any{r.CallID, r.Leg, r.Src, r.Dst, fmt.Sprintf("0x%08x", r.SSRC), r.Codec,
			r.Packets, r.LossPct, r.JitterMean, r.JitterMax, m})
	}
	return t
}
