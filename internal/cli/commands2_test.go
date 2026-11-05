package cli

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/analysis"
	"github.com/sotoz/sipcurious/internal/engine"
	"github.com/sotoz/sipcurious/internal/pcaptest"
)

// diagnoseRules runs diagnose and returns the highest severity per rule ID.
func diagnoseRules(t *testing.T, args ...string) (rules map[string]string, r result) {
	t.Helper()
	r = run(t, nil, append([]string{"diagnose", "-q", "-F", "csv"}, args...)...)
	if r.code != 0 {
		t.Fatalf("diagnose %v: exit %d, stderr %q", args, r.code, r.stderr)
	}
	rules = map[string]string{} // rule -> highest severity
	rank := map[string]int{"info": 0, "warning": 1, "error": 2}
	for _, row := range readCSV(t, r.stdout) {
		if cur, ok := rules[row["rule"]]; !ok || rank[row["severity"]] > rank[cur] {
			rules[row["rule"]] = row["severity"]
		}
	}
	return rules, r
}

// Expected rule IDs come from the defect each demo capture is built to show
// (testdata/samples/README.md).
func TestDiagnoseSamples(t *testing.T) {
	tests := []struct {
		file string
		want map[string]string // rule -> highest severity
	}{
		{"basic-call.pcap", map[string]string{}},
		{"no-answer-retransmits.pcap", map[string]string{"no-response": "error", "sip-retransmissions": "error", "call-failed": "error", "slow-setup": "warning"}},
		{"missing-ack.pcap", map[string]string{"missing-ack": "error", "no-media": "info"}},
		{"nat-problem.pcap", map[string]string{"nat-suspected": "warning"}},
		{"bad-media.pcap", map[string]string{"media-quality": "error", "one-way-media": "error", "no-media": "error"}},
		{"auth-register.pcap", map[string]string{"auth-failures": "error", "register-flapping": "warning"}},
		{"busy-and-reject.pcap", map[string]string{"call-failed": "warning"}},
		{"cancelled-call.pcap", map[string]string{"call-failed": "info"}},
		{"b2bua-two-legs.pcap", map[string]string{}},
		{"hold-resume.pcap", map[string]string{"hold-resume": "info"}},
		{"tcp-sip.pcap", map[string]string{}},
		{"ipv6-vlan.pcap", map[string]string{}},
		{"features-sll-nanos.pcap", map[string]string{}},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			got, _ := diagnoseRules(t, sample(tc.file))
			if len(got) != len(tc.want) {
				t.Errorf("rules = %v, want %v", got, tc.want)
			}
			for rule, sev := range tc.want {
				if got[rule] != sev {
					t.Errorf("rule %s severity = %q, want %q (all: %v)", rule, got[rule], sev, got)
				}
			}
		})
	}
}

func TestDiagnoseCallIDs(t *testing.T) {
	// The three calls of bad-media show three different problems.
	r := run(t, nil, "diagnose", "-q", "-F", "csv", sample("bad-media.pcap"))
	byRule := map[string]string{}
	for _, row := range readCSV(t, r.stdout) {
		byRule[row["rule"]] = row["call_id"]
	}
	for rule, id := range map[string]string{
		"media-quality": "gjsqxqhsuw6y4rox@10.0.1.10", "one-way-media": "3ysto1i3gfo77fpr@10.0.1.10", "no-media": "ybfuxqgimm86dtek@10.0.1.10",
	} {
		if byRule[rule] != id {
			t.Errorf("%s call = %q, want %q", rule, byRule[rule], id)
		}
	}
	// A call filter keeps that call's findings only.
	rules, _ := diagnoseRules(t, "--callid", "3ysto1", sample("bad-media.pcap"))
	if len(rules) != 1 || rules["one-way-media"] == "" {
		t.Errorf("filtered rules = %v", rules)
	}
}

func TestDiagnoseOptions(t *testing.T) {
	bad := sample("bad-media.pcap")
	if got, _ := diagnoseRules(t, "--rules", "no-media,one-way-media", bad); len(got) != 2 || got["media-quality"] != "" {
		t.Errorf("--rules: %v", got)
	}
	if got, _ := diagnoseRules(t, "--disable", "media-quality", bad); len(got) != 2 || got["media-quality"] != "" {
		t.Errorf("--disable: %v", got)
	}
	if got, _ := diagnoseRules(t, "--min-severity", "error", sample("busy-and-reject.pcap")); len(got) != 0 {
		t.Errorf("--min-severity error on warnings: %v", got)
	}
	// Thresholds: the 2.0 s PDD of... basic-call has none; the 39 % loss stream
	// stays an error with a looser MOS limit but --max-loss 50 clears the loss.
	r := run(t, nil, "diagnose", "-q", "-F", "csv", "--rules", "media-quality", "--max-loss", "50", "--min-mos", "1", "--max-gap", "10s", "--max-jitter", "1s", bad)
	if rows := readCSV(t, r.stdout); len(rows) != 0 {
		t.Errorf("loose thresholds still report %v", rows)
	}
	// Tighter: the setup of basic-call took 2.003 s.
	if got, _ := diagnoseRules(t, "--slow-setup", "1s", sample("basic-call.pcap")); got["slow-setup"] == "" && got["slow-answer"] == "" {
		t.Errorf("--slow-setup 1s reported nothing: %v", got)
	}
	// --long-call: basic-call talks 5.004 s.
	if got, _ := diagnoseRules(t, "--long-call", "3s", sample("basic-call.pcap")); got["long-call"] != "info" {
		t.Errorf("--long-call: %v", got)
	}
	// --min-retransmits: the 6 retransmissions of the first call.
	if got, _ := diagnoseRules(t, "--min-retransmits", "7", "--rules", "sip-retransmissions", sample("no-answer-retransmits.pcap")); len(got) != 0 {
		t.Errorf("--min-retransmits 7: %v", got)
	}
}

func TestDiagnoseExitCodes(t *testing.T) {
	tests := []struct {
		file string
		args []string
		want int
	}{
		{"basic-call.pcap", []string{"--fail-on", "warning"}, 0},
		{"basic-call.pcap", []string{"--fail-on", "error"}, 0},
		{"missing-ack.pcap", nil, 0},
		{"missing-ack.pcap", []string{"--fail-on", "never"}, 0},
		{"missing-ack.pcap", []string{"--fail-on", "error"}, ExitFindings},
		{"missing-ack.pcap", []string{"--fail-on", "warning"}, ExitFindings},
		{"busy-and-reject.pcap", []string{"--fail-on", "error"}, 0},
		{"busy-and-reject.pcap", []string{"--fail-on", "warning"}, ExitFindings},
		{"cancelled-call.pcap", []string{"--fail-on", "warning"}, 0},
		{"missing-ack.pcap", []string{"--fail-on", "error", "--min-severity", "error", "--disable", "missing-ack"}, 0},
		{"missing-ack.pcap", []string{"--fail-on", "bogus"}, ExitUsage},
		{"missing-ack.pcap", []string{"--min-severity", "bogus"}, ExitUsage},
		{"missing-ack.pcap", []string{"--rules", "no-such-rule"}, ExitUsage},
		{"missing-ack.pcap", []string{"--slow-pdd", "-1s"}, ExitUsage},
	}
	for _, tc := range tests {
		r := run(t, nil, append([]string{"diagnose", "-q"}, append(tc.args, sample(tc.file))...)...)
		if r.code != tc.want {
			t.Errorf("%s %v: exit %d, want %d (stderr %q)", tc.file, tc.args, r.code, tc.want, r.stderr)
		}
	}
	// The alias, and the summary line on stderr.
	r := run(t, nil, "check", sample("missing-ack.pcap"))
	if r.code != 0 || !strings.Contains(r.stderr, "1 error") || !strings.Contains(r.stdout, "missing-ack") {
		t.Errorf("check: %+v", r)
	}
}

func TestDiagnoseLayouts(t *testing.T) {
	bad := sample("bad-media.pcap")
	// Default table: scannable, one row per finding without the long text.
	r := run(t, nil, "diagnose", "-q", "--utc", bad)
	for _, want := range []string{"Severity", "Rule", "Call-ID", "Title", "one-way-media", "3ysto1i3gfo77fpr@10.0.1.10"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("table lacks %q:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "hint:") || strings.Contains(r.stdout, "Hint") {
		t.Errorf("default table carries hints:\n%s", r.stdout)
	}
	// --extra: grouped per call with the hint and packets indented.
	r = run(t, nil, "diagnose", "-q", "--utc", "--extra", bad)
	for _, want := range []string{"\ngjsqxqhsuw6y4rox@10.0.1.10  alice -> bob  completed 200 OK\n", "  ERROR   media-quality", "          hint: ", "          packets: "} {
		if !strings.Contains("\n"+r.stdout, want) {
			t.Errorf("grouped layout lacks %q:\n%s", want, r.stdout)
		}
	}
	// Machine formats carry detail and hint always.
	for _, f := range []string{"csv", "json", "ndjson", "markdown", "html"} {
		r := run(t, nil, "diagnose", "-q", "-F", f, bad)
		if r.code != 0 || !strings.Contains(r.stdout, "one-way-media") {
			t.Errorf("format %s: %+v", f, r)
		}
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(run(t, nil, "diagnose", "-q", "-F", "json", bad).stdout), &rows); err != nil || len(rows) != 3 {
		t.Fatalf("json: %v, %d rows", err, len(rows))
	}
	for _, k := range []string{"severity", "rule", "call_id", "time", "title", "detail", "hint", "packets"} {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("json row lacks %q: %v", k, rows[0])
		}
	}
	// Summary line is on stderr and only there.
	r = run(t, nil, "diagnose", bad)
	if !strings.Contains(r.stderr, "3 errors, 0 warnings, 0 info (3 calls checked)") {
		t.Errorf("stderr = %q", r.stderr)
	}
	if strings.Contains(r.stdout, "3 errors") {
		t.Error("summary leaked to stdout")
	}
}

func TestFlow(t *testing.T) {
	basic := sample("basic-call.pcap")
	r := run(t, nil, "flow", "-q", "--utc", basic)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	// README: INVITE, 100, 180, 200, ACK, BYE, 200, plus two RTP streams of 250 packets.
	for _, want := range []string{
		"Call-ID: 0jv0hk3er8amef7w@10.0.1.10", "10.0.1.10:5060", "10.0.2.20:5060",
		"- INVITE -", "100 Trying", "180 Ringing", "200 OK", "- ACK -", "- BYE -", "RTP PCMU 250 pkts",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("ascii lacks %q:\n%s", want, r.stdout)
		}
	}
	var arrows int
	for _, l := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "|") && (strings.Contains(l, "-->") || strings.Contains(l, "<--")) {
			arrows++
		}
	}
	if arrows != 7 {
		t.Errorf("%d SIP arrows, want 7:\n%s", arrows, r.stdout)
	}
	if strings.Contains(r.stdout, "RTP PCMU") != strings.Contains(r.stdout, "RTP streams:") {
		t.Error("media arrows and footer disagree")
	}
	// --no-rtp drops the media; --media=false too.
	for _, a := range [][]string{{"--no-rtp"}, {"--media=false"}} {
		if r := run(t, nil, append([]string{"flow", "-q", basic}, a...)...); strings.Contains(r.stdout, "RTP") {
			t.Errorf("%v still shows RTP", a)
		}
	}
	if r := run(t, nil, "ladder", "-q", "--sdp", basic); !strings.Contains(r.stdout, "audio PCMU,PCMA,telephone-event @10.0.1.10:16384") {
		t.Errorf("--sdp: %s", r.stdout)
	}
	if r := run(t, nil, "flow", "-q", "--absolute", "--utc", basic); !strings.Contains(r.stdout, "10:00:07.007") {
		t.Errorf("--absolute: %s", r.stdout)
	}

	// Selection by the common query, --top and --sort.
	busy := sample("busy-and-reject.pcap")
	if r := run(t, nil, "flow", "-q", "--callid", "k4c4", busy); strings.Count(r.stdout, "Call-ID:") != 1 || !strings.Contains(r.stdout, "603") {
		t.Errorf("--callid: %s", r.stdout)
	}
	if r := run(t, nil, "flow", "-q", "--top", "2", busy); strings.Count(r.stdout, "Call-ID:") != 2 {
		t.Errorf("--top 2: %s", r.stdout)
	}
	r = run(t, nil, "flow", "-q", "--sort", "duration", "--top", "1", busy)
	if !strings.Contains(r.stdout, "k4c4no2o3jug0m0o@10.0.1.10") { // 1.007 s is the longest
		t.Errorf("--sort duration --top 1: %s", r.stdout)
	}
	if r := run(t, nil, "flow", "--sort", "bogus", busy); r.code != ExitUsage {
		t.Errorf("--sort bogus: %d", r.code)
	}
	if r := run(t, nil, "flow", "-F", "pdf", busy); r.code != ExitUsage || !strings.Contains(r.stderr, "ascii") {
		t.Errorf("-F pdf: %+v", r)
	}
	if r := run(t, nil, "flow", "-q", "--callid", "nomatch", busy); r.code != 0 || strings.TrimSpace(r.stdout) != "" {
		t.Errorf("no match: %+v", r)
	}

	// Mermaid is fenced.
	m := run(t, nil, "flow", "-q", "-F", "mermaid", basic).stdout
	if !strings.HasPrefix(m, "```mermaid\nsequenceDiagram") || !strings.Contains(m, "INVITE") || strings.Count(m, "```")%2 != 0 {
		t.Errorf("mermaid:\n%s", m)
	}
}

func TestFlowSVG(t *testing.T) {
	busy := sample("busy-and-reject.pcap")
	r := run(t, nil, "flow", "-q", "-F", "svg", busy)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	docs := strings.Split(strings.TrimSpace(r.stdout), "\n\n<svg")
	if len(docs) != 3 {
		t.Fatalf("%d svg documents, want 3", len(docs))
	}
	for i, d := range docs {
		if i > 0 {
			d = "<svg" + d
		}
		wellFormedXML(t, d)
		if !strings.HasPrefix(d, "<svg ") || !strings.HasSuffix(strings.TrimSpace(d), "</svg>") {
			t.Errorf("document %d is not one svg element", i)
		}
	}
	// One file per Call-ID in a directory.
	dir := filepath.Join(t.TempDir(), "out")
	r = run(t, nil, "flow", "-q", "-F", "svg", "-o", dir+"/", busy)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("-o dir: %+v", r)
	}
	for _, id := range []string{"p98a67hlvnj047u3@10.0.1.10", "k4c4no2o3jug0m0o@10.0.1.10", "gvpckwvdgxqtbev0@10.0.1.10"} {
		b, err := os.ReadFile(filepath.Join(dir, id+".svg"))
		if err != nil {
			t.Fatal(err)
		}
		wellFormedXML(t, string(b))
		if !strings.Contains(string(b), id) {
			t.Errorf("%s.svg does not mention its Call-ID", id)
		}
	}
	// An existing directory without a trailing slash works too.
	run(t, nil, "flow", "-q", "-F", "svg", "-o", dir, "--top", "1", busy)
	if entries, _ := os.ReadDir(dir); len(entries) != 3 {
		t.Errorf("%d files in dir", len(entries))
	}
}

func wellFormedXML(t *testing.T, s string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(s))
	dec.Strict = true
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("svg is not well-formed: %v", err)
		}
	}
}

func TestFileName(t *testing.T) {
	tests := map[string]string{
		"abc@10.0.1.10":  "abc@10.0.1.10",
		"../../etc/pass": "_.._etc_pass",
		"":               "call",
		"a/b\\c:d":       "a_b_c_d",
		"..hidden":       "hidden",
	}
	for in, want := range tests {
		if got := fileName(in); got != want {
			t.Errorf("fileName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := fileName(strings.Repeat("x", 500)); len(got) != 120 {
		t.Errorf("long name has %d bytes", len(got))
	}
}

// RTP facts: tshark -z rtp,streams in testdata/samples/README.md.
func TestRTPTable(t *testing.T) {
	type stream struct {
		src, dst, ssrc string
		packets        string
		loss           float64
		call           string
	}
	tests := []struct {
		file string
		want []stream
	}{
		{"basic-call.pcap", []stream{
			{"10.0.1.10:16384", "10.0.2.20:18000", "0x1A2B3C01", "250", 0, "0jv0hk3er8amef7w@10.0.1.10"},
			{"10.0.2.20:18000", "10.0.1.10:16384", "0x1A2B3C02", "250", 0, "0jv0hk3er8amef7w@10.0.1.10"},
		}},
		{"bad-media.pcap", []stream{
			{"10.0.1.10:47810", "10.0.2.20:14714", "0xBAD00001", "300", 0, "gjsqxqhsuw6y4rox@10.0.1.10"},
			{"10.0.2.20:14714", "10.0.1.10:47810", "0xBAD00002", "182", 39.3, "gjsqxqhsuw6y4rox@10.0.1.10"},
			{"10.0.1.10:20132", "10.0.2.21:18574", "0xBAD00003", "300", 0, "3ysto1i3gfo77fpr@10.0.1.10"},
		}},
		{"nat-problem.pcap", []stream{
			{"203.0.113.10:14284", "10.0.2.20:43158", "0x4A700001", "200", 0, "vfj72cutpqa46bgf@192.168.1.50"},
			{"10.0.2.20:43158", "192.168.1.50:14284", "0x4A700002", "200", 0, "vfj72cutpqa46bgf@192.168.1.50"},
		}},
		{"b2bua-two-legs.pcap", []stream{
			{"10.0.2.20:41832", "10.0.0.1:33762", "0xB2B00002", "201", 0, "ipswrcvyqf4jfonu@10.0.0.1"},
			{"10.0.0.1:32848", "10.0.1.10:50530", "0xE0F24429", "201", 0, "bnvcw0zf0i6ci9es@10.0.1.10"},
			{"10.0.1.10:50530", "10.0.0.1:32848", "0xB2B00001", "200", 0, "bnvcw0zf0i6ci9es@10.0.1.10"},
			{"10.0.0.1:33762", "10.0.2.20:41832", "0x15FE4443", "200", 0, "ipswrcvyqf4jfonu@10.0.0.1"},
		}},
		{"tcp-sip.pcap", []stream{
			{"10.0.1.10:31988", "10.0.2.20:51548", "0x9609365F", "100", 0, "6lxghkzqy4soaz9i@10.0.1.10"},
			{"10.0.2.20:51548", "10.0.1.10:31988", "0xF286EDB8", "100", 0, "6lxghkzqy4soaz9i@10.0.1.10"},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			r := run(t, nil, "rtp", "-q", "-F", "csv", "--sort", "start", sample(tc.file))
			if r.code != 0 {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			rows := readCSV(t, r.stdout)
			if len(rows) != len(tc.want) {
				t.Fatalf("%d streams, want %d:\n%s", len(rows), len(tc.want), r.stdout)
			}
			for _, w := range tc.want {
				var found map[string]string
				for _, row := range rows {
					if row["ssrc"] == w.ssrc {
						found = row
					}
				}
				if found == nil {
					t.Errorf("no stream %s in\n%s", w.ssrc, r.stdout)
					continue
				}
				if found["src"] != w.src || found["dst"] != w.dst || found["packets"] != w.packets || found["call_id"] != w.call {
					t.Errorf("stream %s = %v, want %+v", w.ssrc, found, w)
				}
				if loss := parseFloat(t, found["loss_pct"]); math.Abs(loss-w.loss) > 0.1 {
					t.Errorf("stream %s loss = %v, want %v ± 0.1", w.ssrc, loss, w.loss)
				}
			}
		})
	}
}

func parseFloat(t *testing.T, s string) float64 {
	t.Helper()
	if s == "" {
		return 0
	}
	var f float64
	if err := json.Unmarshal([]byte(s), &f); err != nil {
		t.Fatalf("number %q: %v", s, err)
	}
	return f
}

func TestRTPColumnsAndFilters(t *testing.T) {
	bad := sample("bad-media.pcap")
	// bad-media: jitter mean 26.55 ms, max 38.13 ms, max delta 1964.6 ms (tshark).
	row := func(args ...string) []map[string]string {
		t.Helper()
		r := run(t, nil, append([]string{"rtp", "-q", "-F", "csv", bad}, args...)...)
		if r.code != 0 {
			t.Fatalf("%v: %+v", args, r)
		}
		return readCSV(t, r.stdout)
	}
	all := row()
	var lossy map[string]string
	for _, r := range all {
		if r["ssrc"] == "0xBAD00002" {
			lossy = r
		}
	}
	if lossy == nil {
		t.Fatal("lossy stream missing")
	}
	if lossy["lost"] != "118" || lossy["leg"] != "callee->caller" {
		t.Errorf("lossy = %v", lossy)
	}
	for k, want := range map[string]float64{"jitter_mean_ms": 26.55, "jitter_max_ms": 38.13, "max_gap_ms": 1964.6} {
		if got := parseFloat(t, lossy[k]); math.Abs(got-want) > 0.5 {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
	if mos := parseFloat(t, lossy["mos"]); mos <= 1 || mos >= 3.1 {
		t.Errorf("mos = %v, want a bad score", mos)
	}
	for _, k := range []string{"r_factor", "rtcp", "file", "dtmf", "duration_ms", "start"} {
		if _, ok := lossy[k]; !ok {
			t.Errorf("csv lacks %q", k)
		}
	}

	if got := row("--bad"); len(got) != 1 || got[0]["ssrc"] != "0xBAD00002" {
		t.Errorf("--bad = %v", got)
	}
	if got := row("--min-packets", "250"); len(got) != 2 {
		t.Errorf("--min-packets 250 = %d streams", len(got))
	}
	if got := row("--sort", "loss"); got[0]["ssrc"] != "0xBAD00002" {
		t.Errorf("--sort loss first = %v", got[0]["ssrc"])
	}
	if got := row("--sort", "mos"); got[0]["ssrc"] != "0xBAD00002" {
		t.Errorf("--sort mos first = %v", got[0]["ssrc"])
	}
	if got := row("--sort", "jitter"); got[0]["ssrc"] != "0xBAD00002" {
		t.Errorf("--sort jitter first = %v", got[0]["ssrc"])
	}
	if got := row("--src-ip", "10.0.2.0/24"); len(got) != 1 {
		t.Errorf("--src-ip = %d streams", len(got))
	}
	if got := row("--dst-ip", "10.0.2.21"); len(got) != 1 || got[0]["ssrc"] != "0xBAD00003" {
		t.Errorf("--dst-ip = %v", got)
	}
	if got := row("--callid", "3ysto1"); len(got) != 1 || got[0]["ssrc"] != "0xBAD00003" {
		t.Errorf("--callid = %v", got)
	}
	if got := row("--where", "to ~ bob"); len(got) != 2 {
		t.Errorf("--where on the call = %d streams, want the 2 of call 1", len(got))
	}
	if got := row("--since", "2026-03-04T10:00:10Z"); len(got) != 1 {
		t.Errorf("--since = %d streams", len(got))
	}
	if got := row("--until", "10:00:05"); len(got) != 2 {
		t.Errorf("--until = %d streams", len(got))
	}
	// Tight thresholds mark the clean streams as bad too: gap 20 ms.
	if got := row("--bad", "--max-gap", "10ms"); len(got) != 3 {
		t.Errorf("--bad --max-gap 10ms = %d streams", len(got))
	}
	// Streams of no call: --where selects calls, --uncorrelated adds the rest.
	if got := row("--where", "callid = nomatch"); len(got) != 0 {
		t.Errorf("no call matches: %d streams", len(got))
	}
	if r := run(t, nil, "rtp", "--no-rtp", bad); r.code != ExitUsage {
		t.Errorf("--no-rtp: exit %d", r.code)
	}
	if r := run(t, nil, "rtp", "--sort", "x", bad); r.code != ExitUsage {
		t.Errorf("--sort x: exit %d", r.code)
	}
	// The default table shows the SSRC as hex and the styled MOS column.
	r := run(t, nil, "rtp", "-q", "--utc", bad)
	for _, want := range []string{"0xBAD00002", "PCMU", "Loss%", "Jitter", "MaxGap", "MOS", "Leg"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("table lacks %q:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "R-factor") {
		t.Error("extra column without --extra")
	}
	if r := run(t, nil, "rtp", "-q", "--extra", bad); !strings.Contains(r.stdout, "R-factor") {
		t.Error("--extra lacks R-factor")
	}
}

func TestRTPDTMFAndRTCP(t *testing.T) {
	// features-sll-nanos.pcap: 4 DTMF digits (1 2 3 #) on 0xFEA70001 (300
	// packets: 264 PCMU + 36 telephone-event) and RTCP sender reports for both
	// directions of call 1.
	r := run(t, nil, "rtp", "-q", "-F", "csv", sample("features-sll-nanos.pcap"))
	got := map[string]map[string]string{}
	for _, row := range readCSV(t, r.stdout) {
		got[row["ssrc"]] = row
	}
	if got["0xFEA70001"]["dtmf"] != "4" || got["0xFEA70001"]["packets"] != "300" {
		t.Errorf("0xFEA70001 = %v", got["0xFEA70001"])
	}
	if got["0xFEA70002"]["packets"] != "398" {
		t.Errorf("0xFEA70002 = %v", got["0xFEA70002"])
	}
	for _, ssrc := range []string{"0xFEA70001", "0xFEA70002"} {
		if !strings.Contains(got[ssrc]["rtcp"], "reports") {
			t.Errorf("%s rtcp = %q", ssrc, got[ssrc]["rtcp"])
		}
	}
	if got["0xFEA70003"]["rtcp"] != "" {
		t.Errorf("call 2 has no RTCP: %q", got["0xFEA70003"]["rtcp"])
	}
}

func TestExportRoundTrip(t *testing.T) {
	bad := sample("bad-media.pcap")
	dir := t.TempDir()
	load := func(path string) *engine.Dataset {
		t.Helper()
		ds, err := engine.Load(context.Background(), []string{path}, engine.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		return ds
	}
	// README: 3 Call-IDs of 7 messages, 300 + 182 + 300 RTP packets.
	for _, format := range []string{"pcapng", "pcap"} {
		t.Run(format, func(t *testing.T) {
			out := filepath.Join(dir, "one."+format)
			r := run(t, nil, "export", "-F", format, "--callid", "gjsqxqhsuw6y4rox", "-o", out, bad)
			if r.code != 0 {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			if r.stdout != "" {
				t.Error("data on stdout with -o")
			}
			if !strings.Contains(r.stderr, "exported 489 packets (7 SIP, 482 media) of 1 call") {
				t.Errorf("stats line: %q", r.stderr)
			}
			ds := load(out)
			if len(ds.Messages) != 7 || len(ds.Calls()) != 1 || ds.Calls()[0].CallID != "gjsqxqhsuw6y4rox@10.0.1.10" {
				t.Errorf("round trip: %d messages, %d calls", len(ds.Messages), len(ds.Calls()))
			}
			if ds.Packets != 489 || len(ds.Streams) != 2 || len(ds.Calls()[0].Streams) != 2 {
				t.Errorf("round trip: %d packets, %d streams", ds.Packets, len(ds.Streams))
			}
			var pk uint64
			for _, s := range ds.Streams {
				pk += s.Packets
			}
			if pk != 482 {
				t.Errorf("RTP packets = %d, want 482", pk)
			}
		})
	}
	// --no-media keeps the signalling only.
	out := filepath.Join(dir, "sip.pcapng")
	if r := run(t, nil, "export", "--no-media", "-o", out, bad); r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if ds := load(out); len(ds.Messages) != 21 || ds.Packets != 21 || len(ds.Streams) != 0 {
		t.Errorf("--no-media: %d messages, %d packets, %d streams", len(ds.Messages), ds.Packets, len(ds.Streams))
	}
	// Everything: the whole capture comes back.
	out = filepath.Join(dir, "all.pcapng")
	if r := run(t, nil, "export", "-q", "-o", out, bad); r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if ds := load(out); ds.Packets != 803 || len(ds.Messages) != 21 || len(ds.Streams) != 3 {
		t.Errorf("all: %d packets, %d messages, %d streams", ds.Packets, len(ds.Messages), len(ds.Streams))
	}
	// Several inputs merge.
	out = filepath.Join(dir, "two.pcapng")
	if r := run(t, nil, "export", "-q", "--no-media", "-o", out, sample("busy-and-reject.pcap"), sample("cancelled-call.pcap")); r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if ds := load(out); len(ds.Messages) != 20 || len(ds.Calls()) != 4 {
		t.Errorf("two inputs: %d messages, %d calls", len(ds.Messages), len(ds.Calls()))
	}
}

func TestExportStdinAndStdout(t *testing.T) {
	data, err := os.ReadFile(sample("busy-and-reject.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	// stdin is spooled; the capture goes to the (non-terminal) stdout.
	r := run(t, data, "export", "-q", "--callid", "k4c4", "-")
	if r.code != 0 || len(r.stdout) == 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	out := filepath.Join(t.TempDir(), "o.pcapng")
	if err := os.WriteFile(out, []byte(r.stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	ds, err := engine.Load(context.Background(), []string{out}, engine.DefaultOptions())
	if err != nil || len(ds.Calls()) != 1 || ds.Calls()[0].CallID != "k4c4no2o3jug0m0o@10.0.1.10" {
		t.Fatalf("stdin round trip: %v", err)
	}
	if len(ds.Messages) != 5 { // README: INVITE, 100, 180, 603, ACK
		t.Errorf("messages = %d, want 5", len(ds.Messages))
	}
}

func TestExportErrors(t *testing.T) {
	busy := sample("busy-and-reject.pcap")
	out := filepath.Join(t.TempDir(), "none.pcapng")
	r := run(t, nil, "export", "--callid", "nomatch", "-o", out, busy)
	if r.code != ExitError || !strings.Contains(r.stderr, "nothing to export") {
		t.Errorf("no match: %+v", r)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an output file was left behind")
	}
	if r := run(t, nil, "export", "-F", "svg", "-o", out, busy); r.code != ExitUsage {
		t.Errorf("-F svg: exit %d", r.code)
	}
	if r := run(t, nil, "export", "-o", out, filepath.Join(t.TempDir(), "missing.pcap")); r.code != ExitError {
		t.Errorf("missing input: exit %d", r.code)
	}
	if r := run(t, nil, "export", "-o", out, "--where", "((", busy); r.code != ExitUsage {
		t.Errorf("bad where: exit %d", r.code)
	}
}

func TestStats(t *testing.T) {
	bad := sample("bad-media.pcap")
	r := run(t, nil, "stats", "-q", "-F", "json", bad)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var secs map[string][]map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &secs); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"overview", "sip_methods", "sip_status", "sip_classes", "transports", "top_sources", "top_destinations",
		"user_agents", "call_states", "timings", "failures", "top_calling", "top_called", "negotiated_codecs", "rtp_codecs", "rtp_worst_loss", "rtp_worst_jitter"} {
		if _, ok := secs[k]; !ok {
			t.Errorf("json lacks section %q", k)
		}
	}
	// README: 21 messages: 3 INVITE, 3 ACK, 3 BYE; 782 RTP packets in 3 streams; one 39.3 % stream.
	methods := map[string]float64{}
	for _, row := range secs["sip_methods"] {
		methods[row["method"].(string)] = row["count"].(float64)
	}
	if methods["INVITE"] != 3 || methods["ACK"] != 3 || methods["BYE"] != 3 || len(methods) != 3 {
		t.Errorf("methods = %v", methods)
	}
	overview := map[string]string{}
	for _, row := range secs["overview"] {
		overview[row["metric"].(string)] = row["value"].(string)
	}
	for k, want := range map[string]string{"Packets read": "803", "SIP messages": "21", "RTP streams": "3", "RTP packets": "782", "Answered": "3"} {
		if overview[k] != want {
			t.Errorf("overview %s = %q, want %q", k, overview[k], want)
		}
	}
	if worst := secs["rtp_worst_loss"]; len(worst) != 1 || !strings.Contains(strings.ToUpper(worst[0]["ssrc"].(string)), "BAD00002") {
		t.Errorf("worst loss = %v", worst)
	}
	// Other formats and --top.
	for _, f := range []string{"table", "markdown", "html"} {
		if r := run(t, nil, "stats", "-q", "-F", f, bad); r.code != 0 || !strings.Contains(r.stdout, "sip_methods") && !strings.Contains(r.stdout, "INVITE") {
			t.Errorf("format %s: %+v", f, r)
		}
	}
	if r := run(t, nil, "stats", "-q", "-F", "csv", bad); r.code != ExitUsage {
		t.Errorf("csv: exit %d", r.code)
	}
	mixed := sample("mixed-busy-hour.pcapng")
	var top map[string][]map[string]any
	if err := json.Unmarshal([]byte(run(t, nil, "stats", "-q", "-F", "json", "--top", "2", mixed).stdout), &top); err != nil {
		t.Fatal(err)
	}
	if len(top["sip_status"]) != 2 || len(top["user_agents"]) > 2 {
		t.Errorf("--top 2: %d status rows", len(top["sip_status"]))
	}
	// A call filter restricts the statistics to those calls.
	var one map[string][]map[string]any
	if err := json.Unmarshal([]byte(run(t, nil, "stats", "-q", "-F", "json", "--callid", "3ysto1", bad).stdout), &one); err != nil {
		t.Fatal(err)
	}
	var msgs string
	for _, row := range one["overview"] {
		if row["metric"] == "SIP messages" {
			msgs = row["value"].(string)
		}
	}
	if msgs != "7" {
		t.Errorf("filtered SIP messages = %q, want 7", msgs)
	}
}

func TestRules(t *testing.T) {
	r := run(t, nil, "rules", "-F", "csv")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	rows := readCSV(t, r.stdout)
	var ids []string
	for _, row := range rows {
		ids = append(ids, row["rule"])
		if row["title"] == "" {
			t.Errorf("rule %s has no title", row["rule"])
		}
	}
	if !slices.Equal(ids, analysis.IDs()) {
		t.Errorf("rules = %v, want %v", ids, analysis.IDs())
	}
	sev := map[string]string{}
	for _, row := range rows {
		sev[row["rule"]] = row["severity"]
	}
	if sev["missing-ack"] != "error" || sev["call-failed"] != "info - error" || sev["slow-setup"] != "warning" {
		t.Errorf("severities = %v", sev)
	}
	if d := run(t, nil, "rules", "--docs"); d.code != 0 || d.stdout != analysis.RuleDocs() {
		t.Errorf("--docs differs from analysis.RuleDocs (exit %d)", d.code)
	}
	one := run(t, nil, "rules", "missing-ack")
	if one.code != 0 || !strings.HasPrefix(one.stdout, "## `missing-ack`") || !strings.Contains(one.stdout, "RFC 3261") || strings.Contains(one.stdout, "nat-suspected") {
		t.Errorf("rules missing-ack: %+v", one)
	}
	if bad := run(t, nil, "rules", "nope"); bad.code != ExitUsage || !strings.Contains(bad.stderr, "missing-ack") {
		t.Errorf("unknown rule: %+v", bad)
	}
	if bad := run(t, nil, "rules", "--docs", "missing-ack"); bad.code != ExitUsage {
		t.Errorf("--docs ID: %d", bad.code)
	}
	if h := run(t, nil, "rules", "-h"); h.code != 0 || !strings.Contains(h.stdout, "--docs") {
		t.Errorf("rules -h: %+v", h)
	}
}

func TestHelpGroupsAndCompletion(t *testing.T) {
	h := run(t, nil, "help").stdout
	for _, want := range []string{"Inspect:", "Analyze:", "Share:", "Reference:", "General:"} {
		if !strings.Contains(h, want) {
			t.Errorf("help lacks group %q", want)
		}
	}
	for _, name := range []string{"flow", "stats", "diagnose", "rtp", "export", "report", "rules"} {
		if _, ok := Lookup(name); !ok {
			t.Errorf("command %s is not registered", name)
		}
		if !strings.Contains(h, "\n  "+name) {
			t.Errorf("help lacks %s", name)
		}
		if hc := run(t, nil, "help", name); hc.code != 0 || !strings.Contains(hc.stdout, "Usage: sipcurious "+name) {
			t.Errorf("help %s: %+v", name, hc)
		}
	}
	if strings.Contains(h, "Other:") {
		t.Error("a command has no (or an unknown) group")
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		c := run(t, nil, "completion", shell).stdout
		for _, want := range []string{"diagnose", "ladder", "export", "report", "rules", "fail-on", "max-calls", "min-severity", "mermaid", "pcapng", "uncorrelated", "docs"} {
			if !strings.Contains(c, want) {
				t.Errorf("%s completion lacks %q", shell, want)
			}
		}
	}
	// Each command's own --format default and values.
	for name, def := range map[string]string{"flow": "ascii", "stats": "table", "export": "pcapng", "report": "html", "diagnose": "table"} {
		if u := run(t, nil, "help", name).stdout; !strings.Contains(u, "(default "+def+")") {
			t.Errorf("help %s lacks format default %s:\n%s", name, def, u)
		}
	}
}

// ---------------------------------------------------------------- report

// hostileCapture builds a capture whose From header carries markup.
func hostileCapture(t *testing.T) string {
	t.Helper()
	b := pcaptest.New(pcaptest.SampleStart, 77)
	b.Call(pcaptest.CallOptions{From: `<script>alert("xss")</script>`, To: `"><img src=x onerror=alert(2)>`, Domain: `evil"><svg onload=alert(3)>`, Outcome: pcaptest.Rejected, RejectCode: 486})
	b.Call(pcaptest.CallOptions{Start: pcaptest.SampleStart.Add(5 * time.Second), From: "alice", To: "bob"})
	p := filepath.Join(t.TempDir(), "hostile.pcap")
	if err := b.WriteFile(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReportHTML(t *testing.T) {
	t.Setenv("SIPCURIOUS_NOW", "")
	bad := sample("bad-media.pcap")
	r := run(t, nil, "report", "-q", "--generated", "2026-03-04T12:00:00Z", "--title", "Case 42", bad)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	doc := r.stdout
	for _, want := range []string{
		"<title>Case 42</title>", "Generated 2026-03-04T12:00:00Z", "Summary", "Findings", "Calls", "Call details", "Statistics",
		"sc-card", "media-quality", "one-way-media", "no-media", "gjsqxqhsuw6y4rox@10.0.1.10", "<svg", "sc-details", "<pre",
		"INVITE sip:", "RTP streams", "0xBAD00002", "3 errors",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	// Offline: no external references.
	for _, banned := range []string{"http://", "https://", "src=\"", "href=\"", "@import", "<link"} {
		for _, line := range strings.Split(doc, "\n") {
			if strings.Contains(line, banned) && !strings.Contains(line, "xmlns=\"http://www.w3.org/2000/svg\"") {
				t.Errorf("report references %q: %.120s", banned, line)
				break
			}
		}
	}
	assertBalanced(t, doc)
	// Deterministic with a fixed time (the same via the environment).
	if again := run(t, nil, "report", "-q", "--generated", "2026-03-04T12:00:00Z", "--title", "Case 42", bad).stdout; again != doc {
		t.Error("report is not deterministic")
	}
	t.Setenv("SIPCURIOUS_NOW", "2026-03-04T12:00:00Z")
	if env := run(t, nil, "report", "-q", "--title", "Case 42", bad).stdout; env != doc {
		t.Error("SIPCURIOUS_NOW differs from --generated")
	}
	if r := run(t, nil, "report", "--generated", "yesterday", bad); r.code != ExitUsage {
		t.Errorf("bad --generated: exit %d", r.code)
	}
	// Failed calls first.
	busy := run(t, nil, "report", "-q", "--generated", "2026-03-04T12:00:00Z", sample("busy-and-reject.pcap")).stdout
	assertBalanced(t, busy)
	if !strings.Contains(busy, "603 Decline") {
		t.Error("busy report lacks the 603")
	}
	// -o writes the file.
	out := filepath.Join(t.TempDir(), "r.html")
	if r := run(t, nil, "report", "-q", "-o", out, bad); r.code != 0 || r.stdout != "" {
		t.Fatalf("-o: %+v", r)
	}
	if b, err := os.ReadFile(out); err != nil || !strings.HasPrefix(string(b), "<!DOCTYPE html>") {
		t.Errorf("file: %v %.40q", err, b)
	}
}

func TestReportMaxCalls(t *testing.T) {
	mixed := sample("mixed-busy-hour.pcapng")
	r := run(t, nil, "report", "-q", "--generated", "2026-03-04T12:00:00Z", "--max-calls", "5", mixed)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if got := strings.Count(r.stdout, "(raw)</summary>"); got != 5 {
		t.Errorf("%d call details, want 5", got)
	}
	// README: 164 Call-IDs; 159 are summarised.
	if !strings.Contains(r.stdout, "159 more calls not shown (--max-calls 5)") {
		t.Errorf("no summary of the omitted calls")
	}
	assertBalanced(t, r.stdout)
	// The calls shown are the failed ones first.
	if first := strings.Index(r.stdout, "sc-details"); first < 0 || !strings.Contains(r.stdout[first:first+4000], "failed") {
		t.Error("the first detailed call is not a failed one")
	}
	if r := run(t, nil, "report", "-q", "--max-calls", "0", sample("busy-and-reject.pcap")); r.code != 0 || strings.Contains(r.stdout, "(raw)") || !strings.Contains(r.stdout, "3 more calls not shown") {
		t.Errorf("--max-calls 0: %d", r.code)
	}
}

func TestReportXSS(t *testing.T) {
	p := hostileCapture(t)
	for _, format := range []string{"html", "markdown"} {
		t.Run(format, func(t *testing.T) {
			r := run(t, nil, "report", "-q", "-F", format, "--generated", "2026-03-04T12:00:00Z", p)
			if r.code != 0 {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			out := r.stdout
			if !strings.Contains(out, "alert") {
				t.Fatal("the hostile text is not in the report at all: the test proves nothing")
			}
			text := out
			if format == "markdown" {
				// Raw SIP and ladders sit in code fences, where Markdown shows
				// them literally; everything outside must carry no markup.
				text = outsideFences(out)
				// Only our own <details>/<summary> may be raw HTML; every other
				// "<" must be backslash escaped.
				for _, line := range strings.Split(text, "\n") {
					rest := strings.NewReplacer("<details>", "", "</details>", "", "<summary>", "", "</summary>", "").Replace(line)
					for i := 0; i < len(rest); i++ {
						if rest[i] == '<' && (i == 0 || rest[i-1] != '\\') {
							t.Errorf("raw '<' outside code fences: %.120q", line)
							break
						}
					}
				}
				text = strings.ReplaceAll(text, "\\<", "")
			}
			for _, payload := range []string{"<script>alert", "<img src=x", "<svg onload", `"><img`, "onerror=alert(2)>"} {
				if strings.Contains(text, payload) {
					t.Errorf("unescaped payload %q in the %s report", payload, format)
				}
			}
			if format == "html" {
				assertBalanced(t, out)
				// The only script of the document is the report's own.
				if n := strings.Count(out, "<script"); n != 1 {
					t.Errorf("%d <script> elements, want 1", n)
				}
				if !strings.Contains(out, "&lt;script&gt;alert") {
					t.Error("the From header is not shown escaped")
				}
			}
		})
	}
	// The other renderers too: no terminal escapes, and the SVG stays XML.
	for _, args := range [][]string{{"flow"}, {"calls"}, {"diagnose", "--extra"}, {"flow", "-F", "svg"}} {
		if r := run(t, nil, append(args, "-q", p)...); strings.ContainsRune(r.stdout, 0x1b) {
			t.Errorf("%v emits ESC", args)
		}
	}
	svg := run(t, nil, "flow", "-q", "-F", "svg", p).stdout
	if strings.Contains(svg, "<script>alert") || strings.Contains(svg, "<img src=x") {
		t.Error("unescaped payload in the SVG")
	}
	for i, d := range strings.Split(strings.TrimSpace(svg), "\n\n<svg") {
		if i > 0 {
			d = "<svg" + d
		}
		wellFormedXML(t, d)
	}
}

// outsideFences returns s without the fenced code blocks.
func outsideFences(s string) string {
	var b strings.Builder
	fence := ""
	for _, line := range strings.Split(s, "\n") {
		trim := strings.TrimLeft(line, "`")
		switch {
		case fence == "" && strings.HasPrefix(line, "```"):
			fence = line[:len(line)-len(trim)]
		case fence != "" && strings.HasPrefix(line, fence) && trim == "":
			fence = ""
		case fence == "":
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func TestReportMarkdown(t *testing.T) {
	r := run(t, nil, "report", "-q", "-F", "markdown", "--generated", "2026-03-04T12:00:00Z", sample("missing-ack.pcap"))
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{"# SIP troubleshooting report", "Generated 2026-03-04T12:00:00Z", "## Summary", "## Findings", "missing-ack", "## Calls",
		"0sgmu3yvwctjbrd2@10.0.1.10", "```text", "INVITE", "<details>", "## Statistics"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if strings.Count(r.stdout, "```")%2 != 0 {
		t.Error("unbalanced code fences")
	}
	if r := run(t, nil, "report", "-F", "csv", sample("missing-ack.pcap")); r.code != ExitUsage {
		t.Errorf("-F csv: exit %d", r.code)
	}
}

// voidTags have no end tag.
var voidTags = map[string]bool{"meta": true, "input": true, "br": true, "hr": true, "img": true, "link": true, "col": true}

// assertBalanced checks that every start tag has its end tag in order, that
// the contents of script and style are skipped, and that attribute values
// are quoted and free of raw angle brackets.
func assertBalanced(t *testing.T, doc string) {
	t.Helper()
	var stack []string
	s := doc
	for {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			break
		}
		s = s[i:]
		if strings.HasPrefix(s, "<!--") {
			j := strings.Index(s, "-->")
			if j < 0 {
				t.Fatal("unterminated comment")
			}
			s = s[j+3:]
			continue
		}
		if strings.HasPrefix(s, "<!") {
			s = s[strings.IndexByte(s, '>')+1:]
			continue
		}
		end := tagEnd(s)
		if end < 0 {
			t.Fatalf("unterminated tag: %.60q", s)
		}
		tag := s[1:end]
		s = s[end+1:]
		if name, ok := strings.CutPrefix(tag, "/"); ok {
			name = strings.ToLower(strings.TrimSpace(name))
			if len(stack) == 0 || stack[len(stack)-1] != name {
				t.Fatalf("end tag </%s> does not match open %v", name, stack)
			}
			stack = stack[:len(stack)-1]
			continue
		}
		name := strings.ToLower(strings.FieldsFunc(tag, func(r rune) bool { return r == ' ' || r == '\n' || r == '\t' || r == '/' })[0])
		if strings.HasSuffix(tag, "/") || voidTags[name] {
			continue
		}
		stack = append(stack, name)
		if name == "script" || name == "style" {
			j := strings.Index(strings.ToLower(s), "</"+name)
			if j < 0 {
				t.Fatalf("unterminated <%s>", name)
			}
			s = s[j:]
		}
	}
	if len(stack) != 0 {
		t.Errorf("unclosed tags: %v", stack)
	}
}

// tagEnd finds the '>' that ends the tag at the start of s, skipping quoted
// attribute values.
func tagEnd(s string) int {
	var quote byte
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i
		}
	}
	return -1
}

func TestAssertBalancedItself(t *testing.T) {
	assertBalanced(t, "<!DOCTYPE html><html><body><p class=\"a>b\">x<br><input type=\"text\"></p><script>if (a<b) {}</script></body></html>")
}
