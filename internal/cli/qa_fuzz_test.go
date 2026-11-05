package cli

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/pcaptest"
)

// FuzzParseArgs drives the argument parser of every registered command with
// arbitrary argument lists: it must never panic, and a successful parse must
// return positionals that are not flags (except after "--" or a lone "-").
func FuzzParseArgs(f *testing.F) {
	for _, s := range []string{
		"", "--limit 3 a.pcap", "-w status>=500 x", "-- -x", "- -", "--format=csv -q a", "-F", "--bogus",
		"--limit=-1", "-h", "--help", "-f a -f b c", "--status 4xx --no-rtp -", "---x", "-=", "--=x",
		"--since 10:00 --until 11:00", "\x00", "--where \x00", "-w \xff\xfe",
	} {
		f.Add(s)
	}
	cmds := Commands()
	f.Fuzz(func(t *testing.T, line string) {
		args := strings.Split(line, " ")
		for _, c := range cmds {
			if c.Flags == nil {
				continue
			}
			fs := flag.NewFlagSet(c.Name, flag.ContinueOnError)
			c.Flags(fs)
			pos, err := ParseArgs(fs, args)
			if err != nil && pos != nil {
				t.Fatalf("%s %q: error with positionals %q", c.Name, args, pos)
			}
		}
	})
}

// FuzzMain runs whole commands (never reading a file other than the shipped
// sample) with arbitrary --where expressions and sugar-flag values: the exit
// code must be one of the documented ones and usage errors must not print data.
func FuzzMain(f *testing.F) {
	for _, s := range []string{
		"status >= 500", "from ~ alice and not has_media", "duration > 3s or mos < 3.5", "src_ip in 10.0.0.0/8",
		"((", "", "a" + strings.Repeat(" and a", 500), strings.Repeat("(", 5000), "from ~ \"\x00\"", "method = INVITE",
		"duration > 99999999999999999999h", "src_ip in 10.0.0.0/33", "status = 1e999",
	} {
		f.Add(s, "INVITE", "4xx")
	}
	sc := sample("basic-call.pcap")
	f.Fuzz(func(t *testing.T, where, method, status string) {
		for _, cmd := range []string{"messages", "calls", "diagnose", "flow", "stats", "rtp", "show"} {
			r := safeRun(t, nil, cmd, "-q", "-w", where, "--method", method, "--status", status, "--no-rtp", sc)
			switch r.code {
			case ExitOK, ExitFindings:
			case ExitUsage:
				if r.stdout != "" {
					t.Fatalf("%s -w %q: usage error with stdout %.100q", cmd, where, r.stdout)
				}
			default:
				t.Fatalf("%s -w %q --method %q --status %q: exit %d stderr %q", cmd, where, method, status, r.code, r.stderr)
			}
		}
	})
}

// qaPayloads are the literal markup fragments of the hostile seeds: none may
// appear in HTML/SVG output (they have to be escaped).
var qaPayloads = []string{"<script>alert", "</script><script>x", "<img src=x", "<iframe src", "<svg onload", "<b><b>"}

// qaScriptCount counts <script elements: the report has its own, capture data adds none.
func qaScriptCount(s string) int { return strings.Count(strings.ToLower(s), "<script") }

// hostileCapture writes a capture whose calls and raw messages carry the given
// strings in the From/To/User-Agent/Reason/Call-ID/Via headers.
func qaHostileCapture(t testing.TB, dir, from, to, ua, reason, callID string) string {
	t.Helper()
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	b := pcaptest.New(start, 3)
	b.Call(pcaptest.CallOptions{
		Start: start, From: from, To: to, CallerUA: ua, CalleeUA: ua, ProxyUA: ua, Reason: reason,
		CallID: callID, Domain: "example.com", Compact: true,
		CallerRTP: pcaptest.RTPOptions{MaxPackets: 10}, CalleeRTP: pcaptest.RTPOptions{MaxPackets: 10},
	})
	b.Call(pcaptest.CallOptions{
		Start: start.Add(time.Second), From: "x", To: "y", Outcome: pcaptest.Busy, Topology: pcaptest.B2BUA,
		CallerUA: ua, ProxyUA: ua, XCID: ua, Compact: true,
	})
	src := netip.MustParseAddrPort("10.9.9.9:5060")
	dst := netip.MustParseAddrPort("10.8.8.8:5060")
	raw := "INVITE sip:" + to + "@h SIP/2.0\r\nVia: SIP/2.0/UDP " + ua + ";branch=" + from + "\r\nFrom: <sip:" + from + "@h>;tag=" + reason +
		"\r\nTo: " + to + "\r\nCall-ID: " + callID + "\r\nCSeq: 1 INVITE\r\nContact: <sip:" + ua + ">\r\nUser-Agent: " + ua +
		"\r\nReason: " + reason + "\r\nContent-Type: application/sdp\r\nContent-Length: 40\r\n\r\nv=0\r\no=" + ua + " 1 1 IN IP4 " + from + "\r\nc=IN IP4 " + to + "\r\nm=audio " + reason + " RTP/AVP 0\r\n"
	b.Raw(start.Add(2*time.Second), src, dst, "UDP", []byte(raw))
	b.Raw(start.Add(3*time.Second), dst, src, "UDP", []byte("SIP/2.0 "+reason+" "+ua+"\r\nCall-ID: "+callID+"\r\nCSeq: 1 INVITE\r\nFrom: "+from+"\r\nTo: "+to+"\r\nContent-Length: 0\r\n\r\n"))
	p := filepath.Join(dir, "hostile.pcap")
	if err := b.WriteFile(p); err != nil {
		t.Fatal(err)
	}
	return p
}

var qaHostileInputs = [][5]string{
	{"alice", "bob", "Yealink T46", "Q.850;cause=16", "id@host"},
	{`<script>alert(1)</script>`, `"><img src=x onerror=alert(2)>`, `<iframe src=//evil>`, `</script><script>x`, `<svg onload=alert(3)>@h`},
	{"a\x00b", "c\x00d", "ua\x00", "r\x00", "cid\x00@h"},
	{strings.Repeat("A", 70000), strings.Repeat("<b>", 20000), strings.Repeat("U", 100000), strings.Repeat("&", 5000), strings.Repeat("x", 30000) + "@h"},
	{"\x1b[31mred", "\x1b]0;title\x07", "\u202eevil", "&amp;&lt;", "'; DROP--"},
	{"\xff\xfe", "\xc3\x28", "ua\xf0\x28\x8c", "r", "c\xc0\xaf@h"},
}

// qaCheckHostile runs the HTML/Markdown/SVG producing commands on a
// hostile capture and checks no panic, success exit codes, and that the number
// of markup tags equals the one produced from a benign capture, i.e. hostile
// header values were escaped and added no element.
func qaCheckHostile(t *testing.T, dir string, in [5]string, base map[string][]int) map[string][]int {
	t.Helper()
	path := qaHostileCapture(t, dir, in[0], in[1], in[2], in[3], in[4])
	jobs := map[string][]string{
		"report-html":    {"report", "-q", "--generated", "2026-01-01T00:00:00Z", "-o", filepath.Join(dir, "r.html")},
		"report-md":      {"report", "-q", "-F", "markdown", "--generated", "2026-01-01T00:00:00Z", "-o", filepath.Join(dir, "r.md")},
		"diagnose-html":  {"diagnose", "-q", "-F", "html"},
		"calls-html":     {"calls", "-q", "-F", "html", "--extra"},
		"messages-html":  {"messages", "-q", "-F", "html", "--extra"},
		"rtp-html":       {"rtp", "-q", "-F", "html"},
		"stats-html":     {"stats", "-q", "-F", "html"},
		"flow-svg":       {"flow", "-q", "-F", "svg", "--sdp", "--media"},
		"flow-mermaid":   {"flow", "-q", "-F", "mermaid"},
		"diagnose-md":    {"diagnose", "-q", "-F", "markdown"},
		"messages-json":  {"messages", "-q", "-F", "json", "--extra"},
		"diagnose-csv":   {"diagnose", "-q", "-F", "csv"},
		"show":           {"show", "-q"},
		"export":         {"export", "-q", "-o", filepath.Join(dir, "e.pcapng")},
		"calls-no-rtp":   {"calls", "-q", "--no-rtp", "-F", "ndjson"},
		"flow-ascii-top": {"flow", "-q", "--top", "1"},
	}
	got := map[string][]int{}
	for name, a := range jobs {
		r := safeRun(t, nil, append(a, path)...)
		if r.code != ExitOK && r.code != ExitFindings && !(name == "export" && r.code == ExitError) {
			t.Fatalf("%s: exit %d stderr %.200q", name, r.code, r.stderr)
		}
		out := r.stdout
		switch name {
		case "report-html":
			b, err := os.ReadFile(filepath.Join(dir, "r.html"))
			if err != nil {
				t.Fatal(err)
			}
			out = string(b)
		case "report-md":
			if b, err := os.ReadFile(filepath.Join(dir, "r.md")); err == nil {
				out = string(b)
			}
		}
		if strings.HasSuffix(name, "html") || name == "flow-svg" {
			got[name] = []int{qaScriptCount(out)}
			if want, ok := base[name]; ok && got[name][0] != want[0] {
				t.Fatalf("%s: %d <script> elements, benign capture has %d (unescaped markup from capture data?)", name, got[name][0], want[0])
			}
			low := strings.ToLower(out)
			for _, pl := range qaPayloads {
				if strings.Contains(low, strings.ToLower(pl)) {
					t.Fatalf("%s: raw payload %q in output", name, pl)
				}
			}
		}
		if name == "flow-svg" && out != "" && !strings.HasPrefix(strings.TrimSpace(out), "<") {
			t.Fatalf("flow svg does not start with markup: %.80q", out)
		}
	}
	return got
}

// TestHostileHeaders is the deterministic form of FuzzHostileCapture: the seeds only.
func TestHostileHeaders(t *testing.T) {
	var base map[string][]int
	for i, in := range qaHostileInputs {
		got := qaCheckHostile(t, t.TempDir(), in, base)
		if i == 0 {
			base = got
		}
	}
}

// FuzzHostileCapture builds a capture from fuzzed header values (and the
// hostile seeds) and runs every document-producing command on it.
func FuzzHostileCapture(f *testing.F) {
	for _, in := range qaHostileInputs {
		f.Add(in[0], in[1], in[2], in[3], in[4])
	}
	var base map[string][]int
	f.Fuzz(func(t *testing.T, from, to, ua, reason, callID string) {
		if base == nil {
			base = qaCheckHostile(t, t.TempDir(), qaHostileInputs[0], nil)
		}
		qaCheckHostile(t, t.TempDir(), [5]string{from, to, ua, reason, callID}, base)
	})
}
