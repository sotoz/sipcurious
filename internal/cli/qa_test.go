package cli

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sweepFiles lists every capture shipped in testdata.
func sweepFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pat := range []string{
		testdata("samples", "*.pcap"), testdata("samples", "*.pcapng"),
		testdata("realworld", "*.pcap"), testdata("realworld", "*.pcapng"),
		testdata("aaa.pcap"),
	} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	if len(files) < 60 {
		t.Fatalf("only %d captures found in testdata", len(files))
	}
	return files
}

// safeRun is run with a panic converted into a test failure that names the case.
func safeRun(t *testing.T, stdin []byte, args ...string) (r result) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("PANIC for %q: %v", args, p)
			r = result{code: -1}
		}
	}()
	var out, errb bytes.Buffer
	env := &Env{Stdout: &out, Stderr: &errb, Stdin: bytes.NewReader(stdin), Version: "qa"}
	code := Main(context.Background(), env, args)
	return result{code, out.String(), errb.String()}
}

// checkFormat asserts that out is well formed for the requested format.
func checkFormat(t *testing.T, format, out string, args []string) {
	t.Helper()
	switch format {
	case "json":
		if !json.Valid([]byte(out)) {
			t.Errorf("%q: invalid JSON: %.200q", args, out)
		}
	case "ndjson":
		sc := bufio.NewScanner(strings.NewReader(out))
		sc.Buffer(nil, 1<<26)
		for sc.Scan() {
			if !json.Valid(sc.Bytes()) {
				t.Errorf("%q: invalid NDJSON line: %.200q", args, sc.Text())
				return
			}
		}
	case "csv":
		if out == "" {
			return
		}
		cr := csv.NewReader(strings.NewReader(out))
		if _, err := cr.ReadAll(); err != nil {
			t.Errorf("%q: invalid CSV: %v", args, err)
		}
	case "html":
		if out != "" && !strings.Contains(out, "<") {
			t.Errorf("%q: html output without markup: %.100q", args, out)
		}
	case "svg":
		if out != "" && !strings.Contains(out, "<svg") {
			t.Errorf("%q: svg output without <svg>: %.100q", args, out)
		}
	}
}

type sweepCmd struct {
	cmd     string
	formats []string // "" = default
	extra   [][]string
	diag    bool // exit 3 allowed
}

var sweepCmds = []sweepCmd{
	{cmd: "messages", formats: []string{"", "csv", "json", "ndjson", "markdown", "html"}, extra: [][]string{nil, {"--extra", "--utc"}, {"--count"}, {"--unique"}, {"--limit", "3", "--no-rtp"}}},
	{cmd: "calls", formats: []string{"", "csv", "json", "ndjson", "markdown", "html"}, extra: [][]string{nil, {"--extra"}, {"--no-rtp"}, {"--sort", "duration", "--limit", "2"}}},
	{cmd: "show", formats: []string{"", "text"}, extra: [][]string{nil, {"--headers-only", "--limit", "2"}, {"--sdp-only"}}},
	{cmd: "diagnose", formats: []string{"", "csv", "json", "ndjson", "markdown", "html"}, extra: [][]string{nil, {"--no-rtp"}, {"--calls-only", "--min-severity", "warning"}, {"--fail-on", "warning"}}, diag: true},
	{cmd: "rtp", formats: []string{"", "csv", "json", "ndjson", "markdown", "html"}, extra: [][]string{nil, {"--bad"}, {"--uncorrelated", "--sort", "loss"}}},
	{cmd: "stats", formats: []string{"", "json", "markdown", "html"}, extra: [][]string{nil, {"--no-rtp"}, {"--top", "2"}}},
	{cmd: "flow", formats: []string{"", "mermaid", "svg"}, extra: [][]string{nil, {"--media", "--sdp"}, {"--top", "2", "--absolute"}, {"--no-rtp", "--max-label", "20"}}},
}

// TestSweepSamples runs every command with representative flags over every
// shipped capture and checks: no panic, exit code in {0,1,2,3} (3 only where
// documented), usage errors never happen with valid flags, stdout holds only
// data (the "sipcurious: " lines stay on stderr), and requested structured
// formats are well formed.
func TestSweepSamples(t *testing.T) {
	files := sweepFiles(t)
	if testing.Short() {
		files = files[:6]
	}
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			for _, sc := range sweepCmds {
				for _, format := range sc.formats {
					for _, extra := range sc.extra {
						args := []string{sc.cmd, "-q"}
						if format != "" {
							args = append(args, "--format", format)
						}
						if strings.Contains(strings.Join(extra, " "), "--count") && format != "" {
							continue // --count prints a bare number
						}
						args = append(args, extra...)
						args = append(args, f)
						r := safeRun(t, nil, args...)
						okCode := r.code == ExitOK || (sc.diag && r.code == ExitFindings)
						if !okCode {
							t.Errorf("%q: exit %d, stderr %q", args[:len(args)-1], r.code, r.stderr)
							continue
						}
						if strings.Contains(r.stdout, "sipcurious: ") && sc.cmd != "show" {
							t.Errorf("%q: diagnostic text on stdout: %.200q", args[:len(args)-1], r.stdout)
						}
						if !strings.Contains(strings.Join(extra, " "), "--count") {
							checkFormat(t, format, r.stdout, args[:len(args)-1])
						}
					}
				}
			}
			dir := t.TempDir()
			for _, tc := range []struct {
				out  string
				args []string
			}{
				{"a.pcapng", []string{"export"}},
				{"a.pcap", []string{"export", "-F", "pcap"}},
				{"b.pcapng", []string{"export", "--no-media"}},
				{"r.html", []string{"report", "--generated", "2026-01-01T00:00:00Z"}},
				{"r.md", []string{"report", "-F", "markdown", "--no-rtp", "--max-calls", "3"}},
			} {
				out := filepath.Join(dir, tc.out)
				full := append(append([]string{tc.args[0], "-q", "-o", out}, tc.args[1:]...), f)
				r := safeRun(t, nil, full...)
				if r.code == ExitError && tc.args[0] == "export" &&
					(strings.Contains(r.stderr, "needs one link type") || strings.Contains(r.stderr, "nothing to export")) {
					continue // mixed link types need pcapng; captures without a call have nothing to export
				}
				if r.code != ExitOK {
					t.Errorf("%q: exit %d stderr %q", full, r.code, r.stderr)
					continue
				}
				if r.stdout != "" {
					t.Errorf("%q: stdout not empty with -o: %.100q", full, r.stdout)
				}
				if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
					t.Errorf("%q: output file missing or empty (%v)", full, err)
				}
			}
		})
	}
}

// TestSweepBadInputs feeds every command inputs that are not valid captures.
func TestSweepBadInputs(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	orig, err := os.ReadFile(sample("basic-call.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(orig)
	zw.Close()
	var cut bytes.Buffer
	zw = gzip.NewWriter(&cut)
	zw.Write(orig)
	zw.Close()
	flipped := bytes.Clone(orig)
	for i := 24; i < len(flipped); i += 97 {
		flipped[i] ^= 0xA5
	}
	emptyDir := filepath.Join(dir, "emptydir")
	if err := os.Mkdir(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	type input struct {
		name  string
		path  string
		stdin []byte
		// mustFail: a runtime error (1) is required; otherwise 0 or 1 is fine.
		mustFail bool
	}
	inputs := []input{
		{"empty", write("empty.pcap", nil), nil, true},
		{"text", write("text.pcap", []byte("hello, this is just a text file\nwith two lines\n")), nil, true},
		{"dir-empty", emptyDir, nil, false},
		{"missing", filepath.Join(dir, "nope.pcap"), nil, true},
		{"stdin-empty", "-", nil, true},
		{"stdin-text", "-", []byte("garbage"), true},
		{"stdin-pcap", "-", orig, false},
		{"gz", write("c.pcap.gz", gz.Bytes()), nil, false},
		{"gz-truncated", write("t.pcap.gz", cut.Bytes()[:cut.Len()/2]), nil, false},
		{"header-only", write("hdr.pcap", orig[:24]), nil, false},
		{"truncated-header", write("th.pcap", orig[:10]), nil, true},
		{"truncated-mid-packet", write("tm.pcap", orig[:len(orig)/2+7]), nil, false},
		{"truncated-3-bytes", write("t3.pcap", orig[:len(orig)-3]), nil, false},
		{"flipped-bytes", write("fl.pcap", flipped), nil, false},
		{"huge-caplen", write("hc.pcap", append(bytes.Clone(orig[:24]), 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0x7F)), nil, false},
		{"pcapng-garbage", write("g.pcapng", append([]byte{0x0A, 0x0D, 0x0D, 0x0A, 0xFF, 0xFF, 0xFF, 0x7F}, make([]byte, 40)...)), nil, false},
	}
	cmds := [][]string{
		{"messages"}, {"messages", "-F", "json"}, {"messages", "--count"}, {"calls"}, {"calls", "-F", "csv"},
		{"show"}, {"diagnose"}, {"diagnose", "-F", "json"}, {"rtp"}, {"rtp", "-F", "json"}, {"stats"}, {"stats", "-F", "json"},
		{"flow"}, {"flow", "-F", "svg"}, {"export", "-o", filepath.Join(dir, "out.pcapng")},
		{"report", "-o", filepath.Join(dir, "out.html")},
	}
	for _, in := range inputs {
		for _, c := range cmds {
			args := append(append([]string{c[0], "-q"}, c[1:]...), in.path)
			t.Run(in.name+"/"+strings.Join(c, "_"), func(t *testing.T) {
				r := safeRun(t, in.stdin, args...)
				switch {
				case r.code == ExitError:
					if in.mustFail || r.stderr != "" {
						if !strings.HasPrefix(r.stderr, "sipcurious: ") {
							t.Errorf("stderr lacks prefix: %q", r.stderr)
						}
					}
					if r.stdout != "" && !strings.Contains(strings.Join(c, " "), "-o") {
						t.Errorf("error exit but stdout has %.100q", r.stdout)
					}
				case in.mustFail:
					t.Errorf("exit %d (want 1) stdout %.80q stderr %.120q", r.code, r.stdout, r.stderr)
				case r.code == ExitOK || r.code == ExitFindings:
					for i, a := range c {
						if a == "-F" || a == "--format" {
							checkFormat(t, c[i+1], r.stdout, args)
						}
					}
				default:
					t.Errorf("exit %d stderr %q", r.code, r.stderr)
				}
			})
		}
	}
	// A directory and a mix of good and bad files in one invocation.
	good := sample("basic-call.pcap")
	r := safeRun(t, nil, "messages", "--count", good, filepath.Join(dir, "nope.pcap"))
	t.Logf("good+missing: exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
	if r.code != ExitError && r.code != ExitOK {
		t.Errorf("good+missing exit %d", r.code)
	}
	r = safeRun(t, nil, "messages", "--count", dir)
	t.Logf("dir with mixed files: exit %d stdout %q stderr %.300q", r.code, r.stdout, r.stderr)
	if r.code != ExitError && r.code != ExitOK {
		t.Errorf("dir exit %d", r.code)
	}
}

// TestSweepUsageErrors: every command rejects nonsense flags with exit 2, and
// prints nothing on stdout.
func TestSweepUsageErrors(t *testing.T) {
	good := sample("basic-call.pcap")
	for _, c := range Commands() {
		switch c.Name {
		case "help", "version", "completion", "fields", "rules":
			continue
		}
		for _, bad := range [][]string{
			{"--bogus-flag"},
			{"--format", "nonesuch"},
			{"--limit", "x"},
			{"-w", "((("},
			{"--color"},
		} {
			args := append(append([]string{c.Name}, bad...), good)
			t.Run(fmt.Sprintf("%s/%s", c.Name, strings.Join(bad, "_")), func(t *testing.T) {
				r := safeRun(t, nil, args...)
				if r.code != ExitUsage {
					t.Errorf("exit %d, want 2 (stderr %q)", r.code, r.stderr)
				}
				if r.stdout != "" {
					t.Errorf("stdout not empty: %.100q", r.stdout)
				}
			})
		}
	}
}

// tsharkGolden holds what `tshark -Y sip -T fields -e sip.Call-ID -e sip.Method
// -e sip.Status-Code` reports for every real-world capture (tshark 4.x, generated once):
// file, SIP message count, distinct Call-ID count and the method/status histogram.
var tsharkGolden = []struct {
	file          string
	msgs, callIDs int
	kinds         string
}{
	{"realworld/derived-cloudshark-microsecond-be.pcap", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/derived-cloudshark-multiif.pcapng", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/derived-cloudshark-nanosecond-be.pcap", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/derived-cloudshark-nanosecond-le.pcap", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/derived-cloudshark-qinq.pcap", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/derived-cloudshark-sll.pcap", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/derived-cloudshark-sll2.pcap", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/derived-cloudshark-vlan.pcap", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/derived-cloudshark.pcapng", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/ndpi-http-on-sip-port.pcap", 0, 0, ""},
	{"realworld/ndpi-sip-keepalive-hello.pcapng", 8, 1, "200=2 401=2 REGISTER=4"},
	{"realworld/pcapplusplus-nanosecs-bigendian-http.pcap", 0, 0, ""},
	{"realworld/pcapplusplus-nanosecs.pcap", 0, 0, ""},
	{"realworld/pcapplusplus-sip-200-sdp.pcap", 1, 1, "200=1"},
	{"realworld/pcapplusplus-sip-port52380.pcap", 2, 2, "200=1 INVITE=1"},
	{"realworld/pcapplusplus-sip-publish.pcap", 1, 1, "PUBLISH=1"},
	{"realworld/pcapplusplus-sip-requests-pppoe.pcap", 4, 3, "ACK=1 BYE=1 CANCEL=1 INVITE=1"},
	{"realworld/pcapplusplus-sip-responses.pcap", 7, 5, "100=1 180=1 200=1 401=2 503=1 504=1"},
	{"realworld/sngrep-ipip-tcp.pcap", 4, 1, "183=1 200=1 BYE=1 INVITE=1"},
	{"realworld/sngrep-ipv6-frag-sll.pcap", 32, 1, "100=1 183=4 200=13 ACK=2 BYE=2 INVITE=2 PRACK=4 UPDATE=4"},
	{"realworld/suricata-sip-body-frames-cloudshark.pcap", 10, 3, "100=2 180=2 200=2 ACK=1 INVITE=2 REGISTER=1"},
	{"realworld/suricata-sip-body-large-tcp-loopback.pcap", 2, 1, "100=1 INVITE=1"},
	{"realworld/suricata-sip-compact-form.pcap", 1, 1, "INVITE=1"},
	{"realworld/suricata-sip-header-multi-value.pcap", 1, 1, "INVITE=1"},
	{"realworld/suricata-sip-options.pcap", 2, 1, "200=1 OPTIONS=1"},
	{"realworld/suricata-sip-sdp.pcap", 2, 1, "200=1 INVITE=1"},
	{"realworld/suricata-sip-tcp-port5062.pcap", 2, 1, "401=1 REGISTER=1"},
	{"realworld/suricata-sip-tcp-register.pcap", 2, 1, "200=1 REGISTER=1"},
	{"realworld/suricata-sip-udp-port5062.pcap", 2, 1, "401=1 REGISTER=1"},
	{"realworld/wireshark-asterisk-zfone-xlite.pcap", 27, 5, "100=1 180=1 200=5 401=4 404=2 ACK=3 BYE=1 INVITE=3 OPTIONS=1 REGISTER=2 SUBSCRIBE=4"},
	{"realworld/wireshark-dtmf-sipinfo.pcap", 32, 1, "100=5 200=11 ACK=5 CANCEL=2 INFO=4 INVITE=5"},
	{"realworld/wireshark-fax-t38.pcap", 92, 2, "100=16 180=4 200=24 488=4 ACK=16 BYE=4 INVITE=16 OPTIONS=8"},
	{"realworld/wireshark-h263-over-rtp.pcap", 4, 1, "100=1 200=1 ACK=1 INVITE=1"},
	{"realworld/wireshark-magicjack-short-call.pcap", 11, 1, "100=2 183=1 200=2 401=1 ACK=2 BYE=1 INVITE=2"},
	{"realworld/wireshark-metasploit-invite-spoof.pcap", 2, 1, "180=1 INVITE=1"},
	{"realworld/wireshark-nb6-startup.pcap", 4, 1, "200=1 401=1 REGISTER=2"},
	{"realworld/wireshark-nb6-telephone.pcap", 7, 1, "100=1 183=1 200=2 ACK=1 BYE=1 INVITE=1"},
	{"realworld/wireshark-rtp-conversacion.pcap", 12, 2, "100=1 180=1 200=3 407=1 ACK=2 BYE=1 INVITE=2 OPTIONS=1"},
	{"realworld/wireshark-rtp-dtmf-event.pcap", 26, 5, "100=7 180=2 200=6 603=1 ACK=3 INVITE=3 REGISTER=4"},
	{"realworld/wireshark-rtp-rtcp-g722-freeswitch.pcap", 0, 0, ""},
	{"realworld/wireshark-sctp-megaco-bigendian.pcap", 0, 0, ""},
	{"realworld/wireshark-sip-call-g711.pcap", 14, 4, "100=2 180=2 200=4 ACK=1 INVITE=2 REGISTER=3"},
	{"realworld/wireshark-sip-dtmf2.pcap", 29, 5, "100=8 180=2 200=7 603=1 ACK=3 INVITE=3 REGISTER=5"},
	{"realworld/wireshark-sip-rawip.pcapng", 5, 2, "100=1 181=1 200=1 INVITE=1 REGISTER=1"},
	{"realworld/wireshark-sip-rtp-g711.pcap", 10, 2, "100=2 200=3 ACK=2 BYE=1 INVITE=2"},
	{"realworld/wireshark-sip-rtp.pcapng", 14, 4, "100=2 180=2 200=4 ACK=1 INVITE=2 REGISTER=3"},
	{"realworld/wireshark-sip-tls13-caplen-gt-origlen.pcap", 0, 0, ""},
	{"realworld/wireshark-switchport-sip-with-arp-stp.pcap", 3, 1, "ACK=1 BYE=1 INVITE=1"},
	{"realworld/zeek-sip-junk-before-request.pcap", 1, 0, "REGISTER=1"},
	{"realworld/zeek-sip-long-paths-rawipv4.pcap", 2, 1, "200=1 OPTIONS=1"},
	{"aaa.pcap", 81, 6, "100=7 183=1 200=3 401=14 403=3 407=3 408=2 480=1 ACK=7 CANCEL=11 INVITE=11 REGISTER=18"},
}

// TestAgainstTshark checks the message count, the number of distinct Call-IDs
// and the per-message method/status of `messages --format json` against tshark.
func TestAgainstTshark(t *testing.T) {
	for _, g := range tsharkGolden {
		t.Run(g.file, func(t *testing.T) {
			r := safeRun(t, nil, "messages", "-q", "--no-rtp", "--format", "json", testdata(g.file))
			if r.code != ExitOK {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			var msgs []map[string]any
			if err := json.Unmarshal([]byte(r.stdout), &msgs); err != nil {
				t.Fatal(err)
			}
			ids := map[string]bool{}
			kinds := map[string]int{}
			for _, m := range msgs {
				if id, _ := m["call_id"].(string); id != "" {
					ids[id] = true
				}
				info, _ := m["info"].(string)
				kinds[strings.Fields(info + " ")[0]]++
			}
			if len(msgs) != g.msgs || len(ids) != g.callIDs {
				t.Errorf("messages=%d call-ids=%d, tshark says %d and %d", len(msgs), len(ids), g.msgs, g.callIDs)
			}
			var parts []string
			for k, n := range kinds {
				parts = append(parts, fmt.Sprintf("%s=%d", k, n))
			}
			sort.Strings(parts)
			if got := strings.Join(parts, " "); got != g.kinds {
				t.Errorf("methods/status = %q, tshark says %q", got, g.kinds)
			}
		})
	}
}

// TestTCPFrameNumber documents the one intended difference to tshark: a SIP
// message reassembled from several TCP segments is attributed to its first
// segment (tshark reports the frame that completes it).
func TestTCPFrameNumber(t *testing.T) {
	for file, want := range map[string]string{
		"realworld/suricata-sip-body-large-tcp-loopback.pcap": "#5",
		"realworld/suricata-sip-tcp-register.pcap":            "#4",
	} {
		r := safeRun(t, nil, "messages", "-q", "--no-rtp", "--extra", "-F", "csv", "--limit", "1", testdata(file))
		rows := readCSV(t, r.stdout)
		if len(rows) != 1 || !strings.HasSuffix(rows[0]["file_index"], want) {
			t.Errorf("%s: file_index %v, want suffix %s", file, rows, want)
		}
	}
}

// TestShowFormatRejected: show only prints text; --format used to be accepted
// (json, csv, ...) and silently produced the text anyway.
func TestShowFormatRejected(t *testing.T) {
	for _, f := range []string{"json", "csv", "html", "ndjson"} {
		r := safeRun(t, nil, "show", "-q", "--format", f, sample("basic-call.pcap"))
		if r.code != ExitUsage || r.stdout != "" {
			t.Errorf("show --format %s: exit %d stdout %.60q", f, r.code, r.stdout)
		}
	}
	if r := safeRun(t, nil, "show", "-q", "--format", "text", "--limit", "1", sample("basic-call.pcap")); r.code != ExitOK || !strings.HasPrefix(r.stdout, "#1 ") {
		t.Errorf("show --format text: %+v", r)
	}
}
