package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func testdata(parts ...string) string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(f), "..", "..", "testdata"}, parts...)...)
}

func sample(name string) string { return testdata("samples", name) }

var aaa = testdata("aaa.pcap")

type result struct {
	code   int
	stdout string
	stderr string
}

// run executes cli.Main with buffers; TZ-dependent output is avoided by tests
// through --utc where times matter.
func run(t *testing.T, stdin []byte, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	env := &Env{Stdout: &out, Stderr: &errb, Stdin: bytes.NewReader(stdin), Version: "v9.9.9-test"}
	code := Main(context.Background(), env, args)
	return result{code, out.String(), errb.String()}
}

func readCSV(t *testing.T, s string) []map[string]string {
	t.Helper()
	recs, err := csv.NewReader(strings.NewReader(s)).ReadAll()
	if err != nil {
		t.Fatalf("csv: %v\n%s", err, s)
	}
	if len(recs) == 0 {
		t.Fatal("csv: no header")
	}
	var rows []map[string]string
	for _, r := range recs[1:] {
		m := map[string]string{}
		for i, h := range recs[0] {
			m[h] = r[i]
		}
		rows = append(rows, m)
	}
	return rows
}

func count(t *testing.T, args ...string) int {
	t.Helper()
	r := run(t, nil, append([]string{"messages", "--count", "-q"}, args...)...)
	if r.code != 0 {
		t.Fatalf("%v: exit %d, stderr %q", args, r.code, r.stderr)
	}
	n, err := strconv.Atoi(strings.TrimSpace(r.stdout))
	if err != nil {
		t.Fatalf("%v: count %q", args, r.stdout)
	}
	return n
}

// Packet/SIP message counts of testdata/samples/README.md (from tshark).
var sampleCounts = []struct {
	file          string
	packets, msgs int
}{
	{"basic-call.pcap", 507, 7},
	{"busy-and-reject.pcap", 13, 13},
	{"cancelled-call.pcap", 7, 7},
	{"no-answer-retransmits.pcap", 18, 18},
	{"auth-register.pcap", 24, 24},
	{"bad-media.pcap", 803, 21},
	{"missing-ack.pcap", 16, 16},
	{"nat-problem.pcap", 414, 14},
	{"b2bua-two-legs.pcap", 816, 14},
	{"hold-resume.pcap", 928, 26},
	{"tcp-sip.pcap", 228, 11},
	{"ipv6-vlan.pcap", 322, 22},
	{"features-sll-nanos.pcap", 1114, 14},
	{"mixed-busy-hour.pcapng", 1574, 1100},
}

func TestSampleCounts(t *testing.T) {
	for _, tc := range sampleCounts {
		t.Run(tc.file, func(t *testing.T) {
			if n := count(t, sample(tc.file)); n != tc.msgs {
				t.Errorf("messages = %d, want %d", n, tc.msgs)
			}
			r := run(t, nil, "messages", "--count", sample(tc.file))
			want := strconv.Itoa(tc.packets) + " packets"
			if !strings.Contains(r.stderr, want) {
				t.Errorf("stderr %q lacks %q", r.stderr, want)
			}
		})
	}
	if n := count(t, aaa); n != 81 {
		t.Errorf("aaa.pcap messages = %d, want 81", n)
	}
}

// Expected counts below come from tshark on testdata/aaa.pcap (see comments)
// and on testdata/samples/busy-and-reject.pcap (frame times).
func TestFilters(t *testing.T) {
	busy := sample("busy-and-reject.pcap")
	tests := []struct {
		name string
		file string
		args []string
		want int
	}{
		{"no filter", aaa, nil, 81},
		{"status class", aaa, []string{"--status", "4xx"}, 23},          // sip.Status-Code in 400..499
		{"status exact", aaa, []string{"--status", "401"}, 14},          // sip.Status-Code==401
		{"method", aaa, []string{"--method", "CANCEL"}, 12},             // sip.CSeq.method==CANCEL (responses match by CSeq method)
		{"method lowercase", aaa, []string{"--method", "register"}, 40}, // sip.CSeq.method==REGISTER
		{"dst-ip", aaa, []string{"--dst-ip", "200.68.120.81"}, 15},
		{"src-ip", aaa, []string{"--src-ip", "200.68.120.81"}, 3},
		{"src-ip cidr", aaa, []string{"--src-ip", "212.242.33.0/24"}, 31},
		{"callid", aaa, []string{"--callid", "105090259"}, 18},
		{"uri", aaa, []string{"--uri", "cybercity"}, 32},
		{"from", aaa, []string{"--from", "voi18062"}, 21},
		{"to+method", aaa, []string{"--to", "0097239287044", "--method", "INVITE"}, 11}, // sip.CSeq.method==INVITE && sip.To contains
		{"where", aaa, []string{"--where", "method = INVITE and uri ~ cybercity"}, 8},
		{"where short", aaa, []string{"-w", "status = 401"}, 14},
		{"where + sugar", aaa, []string{"-w", "status >= 400", "--src-ip", "200.68.120.81"}, 2},
		{"case-sensitive miss", aaa, []string{"--from", "VOI18062", "--case-sensitive"}, 0},
		{"case-insensitive", aaa, []string{"--from", "VOI18062"}, 21},
		{"since", busy, []string{"--since", "2026-03-04T10:00:05Z"}, 9},
		{"until", busy, []string{"--until", "2026-03-04T10:00:05.5Z"}, 7},
		{"since+until", busy, []string{"--since", "2026-03-04T10:00:05Z", "--until", "2026-03-04T10:00:05.5Z"}, 3},
		{"from header contains Alice", busy, []string{"--from", "Alice"}, 4},
		{"call field state", busy, []string{"-w", "state = failed"}, 13},
		{"call field no match", sample("basic-call.pcap"), []string{"-w", "state = failed"}, 0},
		{"call field with message field", busy, []string{"-w", "final_code = 486 and is_request"}, 2},
		{"call field kind", busy, []string{"-w", "kind = call and final_code = 486"}, 4},
		{"mixed 4xx", sample("mixed-busy-hour.pcapng"), []string{"--status", "4xx"}, 78},
		{"mixed 603", sample("mixed-busy-hour.pcapng"), []string{"--status", "603"}, 8},
		{"mixed tcp", sample("mixed-busy-hour.pcapng"), []string{"-w", "transport = tcp"}, 48},
		{"mixed options", sample("mixed-busy-hour.pcapng"), []string{"-w", "cseq ~ OPTIONS"}, 12},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if n := count(t, append(tc.args, tc.file)...); n != tc.want {
				t.Errorf("count = %d, want %d", n, tc.want)
			}
		})
	}
}

func TestMessagesFormats(t *testing.T) {
	busy := sample("busy-and-reject.pcap")

	t.Run("csv", func(t *testing.T) {
		r := run(t, nil, "messages", "-q", "-F", "csv", "--utc", busy)
		rows := readCSV(t, r.stdout)
		if len(rows) != 13 {
			t.Fatalf("rows = %d", len(rows))
		}
		if rows[0]["timestamp"] != "2026-03-04T10:00:00Z" && !strings.HasPrefix(rows[0]["timestamp"], "2026-03-04T10:00:00") {
			t.Errorf("timestamp = %q", rows[0]["timestamp"])
		}
		if rows[0]["info"] != "INVITE" || rows[2]["info"] != "486 Busy Here" || rows[0]["call_id"] != "p98a67hlvnj047u3@10.0.1.10" {
			t.Errorf("rows[0..2] = %v %v", rows[0], rows[2])
		}
		if rows[0]["src"] != "10.0.1.10:5060" || rows[0]["dst"] != "10.0.2.20:5060" || !strings.HasSuffix(rows[0]["file_index"], "busy-and-reject.pcap#1") {
			t.Errorf("extra columns not in CSV: %v", rows[0])
		}
	})
	t.Run("json", func(t *testing.T) {
		r := run(t, nil, "messages", "-q", "-F", "json", busy)
		var rows []map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &rows); err != nil {
			t.Fatalf("json: %v\n%s", err, r.stdout)
		}
		if len(rows) != 13 || rows[1]["info"] != "100 Trying" {
			t.Errorf("rows = %d, [1] = %v", len(rows), rows[1])
		}
	})
	t.Run("json empty", func(t *testing.T) {
		r := run(t, nil, "messages", "-q", "-F", "json", "--status", "999", busy)
		if strings.TrimSpace(r.stdout) != "[]" {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("ndjson", func(t *testing.T) {
		r := run(t, nil, "messages", "-q", "-F", "ndjson", busy)
		lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 13 {
			t.Fatalf("lines = %d", len(lines))
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &m); err != nil || m["info"] != "INVITE" {
			t.Errorf("line 0 = %q (%v)", lines[0], err)
		}
	})
	t.Run("markdown", func(t *testing.T) {
		r := run(t, nil, "messages", "-q", "-F", "markdown", "--limit", "2", busy)
		if !strings.Contains(r.stdout, "| Timestamp") || !strings.Contains(r.stdout, "|---") && !strings.Contains(r.stdout, "| ---") {
			t.Errorf("markdown = %q", r.stdout)
		}
	})
	t.Run("html", func(t *testing.T) {
		r := run(t, nil, "messages", "-q", "-F", "html", "--limit", "2", busy)
		if !strings.Contains(r.stdout, "<table") {
			t.Errorf("html = %q", r.stdout)
		}
	})
	t.Run("table default has no extra columns", func(t *testing.T) {
		r := run(t, nil, "messages", "-q", "--limit", "1", busy)
		if strings.Contains(r.stdout, "Contact") || !strings.Contains(r.stdout, "Call-ID") {
			t.Errorf("table = %q", r.stdout)
		}
		r = run(t, nil, "messages", "-q", "--limit", "1", "--extra", busy)
		for _, h := range []string{"Src", "Dst", "Contact", "URI", "File#Index", "UA"} {
			if !strings.Contains(r.stdout, h) {
				t.Errorf("--extra table lacks %s: %q", h, r.stdout)
			}
		}
	})
	t.Run("utc flag", func(t *testing.T) {
		r := run(t, nil, "messages", "-q", "--utc", "--limit", "1", busy)
		if !strings.Contains(r.stdout, "2026-03-04T10:00:00.000Z") {
			t.Errorf("table = %q", r.stdout)
		}
	})
	t.Run("bad format", func(t *testing.T) {
		r := run(t, nil, "messages", "-F", "yaml", busy)
		if r.code != ExitUsage || r.stdout != "" || !strings.Contains(r.stderr, "--format") {
			t.Errorf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
		}
	})
}

func TestStreamsSeparation(t *testing.T) {
	r := run(t, nil, "messages", "-F", "csv", sample("busy-and-reject.pcap"))
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	if strings.Contains(r.stdout, "sipcurious:") {
		t.Errorf("diagnostics on stdout: %q", r.stdout)
	}
	if !strings.HasPrefix(r.stderr, "sipcurious: read 1 file, 13 packets, 13 SIP messages") || !strings.Contains(r.stderr, "13 messages matched") {
		t.Errorf("stderr = %q", r.stderr)
	}
	for _, line := range strings.Split(strings.TrimSpace(r.stderr), "\n") {
		if !strings.HasPrefix(line, "sipcurious: ") {
			t.Errorf("stderr line without prefix: %q", line)
		}
	}
	if q := run(t, nil, "messages", "-q", "-F", "csv", sample("busy-and-reject.pcap")); q.stderr != "" {
		t.Errorf("--quiet stderr = %q", q.stderr)
	}
	// Errors: nothing on stdout.
	e := run(t, nil, "messages", "-F", "csv", "/nonexistent/x.pcap")
	if e.code != ExitError || e.stdout != "" || !strings.Contains(e.stderr, "sipcurious: ") || !strings.Contains(e.stderr, "x.pcap") {
		t.Errorf("missing file: %+v", e)
	}
}

func TestExitCodes(t *testing.T) {
	busy := sample("busy-and-reject.pcap")
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no args", nil, ExitUsage},
		{"help", []string{"help"}, ExitOK},
		{"-h", []string{"-h"}, ExitOK},
		{"--help", []string{"--help"}, ExitOK},
		{"help command", []string{"help", "calls"}, ExitOK},
		{"help unknown", []string{"help", "nope"}, ExitUsage},
		{"unknown command", []string{"frobnicate"}, ExitUsage},
		{"command -h", []string{"messages", "-h"}, ExitOK},
		{"command --help", []string{"calls", "--help"}, ExitOK},
		{"unknown flag", []string{"messages", "--bogus", busy}, ExitUsage},
		{"flag missing value", []string{"messages", busy, "--where"}, ExitUsage},
		{"bad where", []string{"messages", "-w", "status >=", busy}, ExitUsage},
		{"unknown field", []string{"messages", "-w", "nosuchfield = 1", busy}, ExitUsage},
		{"bad status", []string{"messages", "--status", "abc", busy}, ExitUsage},
		{"bad src-ip", []string{"messages", "--src-ip", "999.1.1.1", busy}, ExitUsage},
		{"bad since", []string{"messages", "--since", "yesterday-ish", busy}, ExitUsage},
		{"bad color", []string{"messages", "--color", "purple", busy}, ExitUsage},
		{"negative limit", []string{"messages", "--limit", "-1", busy}, ExitUsage},
		{"no capture", []string{"messages"}, ExitUsage},
		{"missing file", []string{"messages", "/nonexistent/x.pcap"}, ExitError},
		{"not a capture", []string{"messages", filepath.Join(testdata(), "README.md")}, ExitError},
		{"no matches is ok", []string{"messages", "--status", "999", busy}, ExitOK},
		{"calls bad sort", []string{"calls", "--sort", "nope", busy}, ExitUsage},
		{"show conflicting", []string{"show", "--headers-only", "--sdp-only", busy}, ExitUsage},
		{"version", []string{"version"}, ExitOK},
		{"fields", []string{"fields"}, ExitOK},
		{"completion no shell", []string{"completion"}, ExitUsage},
		{"completion bad shell", []string{"completion", "powershell"}, ExitUsage},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, nil, tc.args...)
			if r.code != tc.want {
				t.Errorf("exit %d, want %d (stderr %q)", r.code, tc.want, r.stderr)
			}
			if tc.want == ExitUsage && r.stdout != "" {
				t.Errorf("usage error printed data on stdout: %q", r.stdout)
			}
			if tc.want == ExitUsage && !strings.HasPrefix(r.stderr, "sipcurious: ") && tc.args != nil {
				t.Errorf("stderr = %q", r.stderr)
			}
		})
	}
}

func TestBadQueryDiagnostics(t *testing.T) {
	r := run(t, nil, "messages", "-w", "status >= 500 and", aaa)
	if r.code != ExitUsage || r.stdout != "" {
		t.Fatalf("exit %d stdout %q", r.code, r.stdout)
	}
	if !strings.Contains(r.stderr, "status >= 500 and") || !strings.Contains(r.stderr, "^") || !strings.Contains(r.stderr, "--where") {
		t.Errorf("no caret rendering: %q", r.stderr)
	}
	// The query is checked before the capture is read.
	if strings.Contains(r.stderr, "read ") {
		t.Errorf("capture loaded before validating the query: %q", r.stderr)
	}
	r = run(t, nil, "messages", "--since", "zzz", aaa)
	if !strings.Contains(r.stderr, "--since") || !strings.Contains(r.stderr, "not a time") {
		t.Errorf("--since diagnostic: %q", r.stderr)
	}
}

func TestDidYouMean(t *testing.T) {
	for typo, want := range map[string]string{"mesages": "messages", "cals": "calls", "shwo": "show", "dialog": "dialogs", "vesion": "version"} {
		r := run(t, nil, typo)
		if r.code != ExitUsage || !strings.Contains(r.stderr, `did you mean "`+want+`"`) {
			t.Errorf("%s: exit %d stderr %q", typo, r.code, r.stderr)
		}
	}
	if r := run(t, nil, "zzzzzzzz"); strings.Contains(r.stderr, "did you mean") {
		t.Errorf("unrelated word got a suggestion: %q", r.stderr)
	}
}

func TestAliases(t *testing.T) {
	busy := sample("busy-and-reject.pcap")
	for _, name := range []string{"messages", "search", "grep"} {
		if r := run(t, nil, name, "--count", "-q", busy); strings.TrimSpace(r.stdout) != "13" {
			t.Errorf("%s: %q", name, r.stdout)
		}
	}
	a := run(t, nil, "calls", "-q", "-F", "csv", busy).stdout
	if b := run(t, nil, "dialogs", "-q", "-F", "csv", busy).stdout; a != b || a == "" {
		t.Error("dialogs differs from calls")
	}
}

func TestFlagPlacement(t *testing.T) {
	busy := sample("busy-and-reject.pcap")
	want := run(t, nil, "messages", "-q", "-F", "csv", "--status", "4xx", busy).stdout
	for name, args := range map[string][]string{
		"flags after":    {"messages", busy, "-q", "-F", "csv", "--status", "4xx"},
		"mixed":          {"messages", "-q", busy, "-F", "csv", "--status=4xx"},
		"file flag":      {"messages", "-q", "-F", "csv", "--status", "4xx", "--file", busy},
		"short file":     {"messages", "-q", "-F", "csv", "--status", "4xx", "-f", busy},
		"double dash":    {"messages", "-q", "-F", "csv", "--status", "4xx", "--", busy},
		"single dash -F": {"messages", "-q", "-F=csv", "-status", "4xx", busy},
	} {
		t.Run(name, func(t *testing.T) {
			if got := run(t, nil, args...).stdout; got != want || got == "" {
				t.Errorf("output differs:\n%s\nwant\n%s", got, want)
			}
		})
	}
	t.Run("after double dash a dash-prefixed name is a file", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "-weird.pcap")
		copyFile(t, busy, p)
		old, _ := os.Getwd()
		defer os.Chdir(old)
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		r := run(t, nil, "messages", "--count", "-q", "--", "-weird.pcap")
		if strings.TrimSpace(r.stdout) != "13" {
			t.Errorf("got %q (%q)", r.stdout, r.stderr)
		}
	})
	t.Run("repeated file flag and positional merge", func(t *testing.T) {
		n := count(t, "-f", sample("basic-call.pcap"), "-f", busy, sample("cancelled-call.pcap"))
		if n != 7+13+7 {
			t.Errorf("count = %d", n)
		}
	})
	t.Run("duplicate paths are read once", func(t *testing.T) {
		if n := count(t, busy, busy, "-f", busy); n != 13 {
			t.Errorf("count = %d", n)
		}
	})
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func gzipFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryAndGlob(t *testing.T) {
	dir := t.TempDir()
	copyFile(t, sample("basic-call.pcap"), filepath.Join(dir, "a", "one.pcap"))
	copyFile(t, sample("mixed-busy-hour.pcapng"), filepath.Join(dir, "a", "b", "two.PCAPNG"))
	copyFile(t, sample("cancelled-call.pcap"), filepath.Join(dir, "three.cap"))
	gzipFile(t, sample("busy-and-reject.pcap"), filepath.Join(dir, "four.pcap.gz"))
	gzipFile(t, sample("auth-register.pcap"), filepath.Join(dir, "five.pcapng.gz"))
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a capture"), 0o644)
	os.WriteFile(filepath.Join(dir, "a", "README.md"), []byte("nor this"), 0o644)

	if n, want := count(t, dir), 7+1100+7+13+24; n != want {
		t.Errorf("directory walk: %d messages, want %d", n, want)
	}
	r := run(t, nil, "messages", "--count", dir)
	if !strings.Contains(r.stderr, "read 5 files") {
		t.Errorf("stderr = %q", r.stderr)
	}
	if n := count(t, filepath.Join(dir, "a")); n != 1107 {
		t.Errorf("subdir = %d", n)
	}
	// Glob patterns are expanded by us when the shell did not (Windows).
	if n := count(t, filepath.Join(dir, "*.cap")); n != 7 {
		t.Errorf("glob *.cap = %d", n)
	}
	if n := count(t, filepath.Join(dir, "*.pcap.gz"), filepath.Join(dir, "a", "*.pcap")); n != 13+7 {
		t.Errorf("globs = %d", n)
	}
	if r := run(t, nil, "messages", filepath.Join(dir, "*.nomatch")); r.code != ExitError || !strings.Contains(r.stderr, "no files match") {
		t.Errorf("empty glob: %+v", r)
	}
	empty := t.TempDir()
	if r := run(t, nil, "messages", empty); r.code != ExitError || !strings.Contains(r.stderr, "no capture files") {
		t.Errorf("empty dir: %+v", r)
	}
}

func TestGzipInput(t *testing.T) {
	dir := t.TempDir()
	gz := filepath.Join(dir, "x.pcap.gz")
	gzipFile(t, aaa, gz)
	if n := count(t, gz); n != 81 {
		t.Errorf("gz = %d", n)
	}
	// Gzip is detected by magic, not by extension.
	noext := filepath.Join(dir, "capture.bin")
	gzipFile(t, aaa, noext)
	if n := count(t, noext); n != 81 {
		t.Errorf("gz without extension = %d", n)
	}
}

func TestStdin(t *testing.T) {
	data, err := os.ReadFile(aaa)
	if err != nil {
		t.Fatal(err)
	}
	r := run(t, data, "messages", "--count", "-", "--status", "4xx")
	if r.code != 0 || strings.TrimSpace(r.stdout) != "23" {
		t.Errorf("stdin: %+v", r)
	}
	if !strings.Contains(r.stderr, "read 1 file, 691 packets, 81 SIP messages") {
		t.Errorf("stderr = %q", r.stderr)
	}
	// File names in the output say "-", never the spool file.
	r = run(t, data, "messages", "-q", "-F", "csv", "--limit", "1", "-")
	rows := readCSV(t, r.stdout)
	if len(rows) != 1 || !strings.HasPrefix(rows[0]["file_index"], "-#") {
		t.Errorf("rows = %v", rows)
	}
	// gzip on stdin, combined with a file.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(data)
	zw.Close()
	r = run(t, buf.Bytes(), "messages", "--count", "-q", "-", sample("cancelled-call.pcap"))
	if strings.TrimSpace(r.stdout) != "88" {
		t.Errorf("stdin gz + file: %+v", r)
	}
	// Garbage on stdin is a runtime error that names the input.
	r = run(t, []byte("this is not a pcap file at all, not even close"), "messages", "-")
	if r.code != ExitError || !strings.Contains(r.stderr, "-") || r.stdout != "" {
		t.Errorf("garbage stdin: %+v", r)
	}
	if strings.Contains(r.stderr, "sipcurious-stdin") {
		t.Errorf("spool file name leaked: %q", r.stderr)
	}
}

func TestLimitUniqueCount(t *testing.T) {
	r := run(t, nil, "messages", "-q", "-F", "csv", "--limit", "5", aaa)
	if rows := readCSV(t, r.stdout); len(rows) != 5 {
		t.Errorf("--limit 5: %d rows", len(rows))
	}
	r = run(t, nil, "messages", "-F", "csv", "--limit", "5", aaa)
	if !strings.Contains(r.stderr, "showing 5 of 81 rows (--limit)") {
		t.Errorf("limit note: %q", r.stderr)
	}
	// 6 Call-IDs in aaa.pcap (tshark).
	r = run(t, nil, "messages", "-q", "-F", "csv", "--unique", aaa)
	rows := readCSV(t, r.stdout)
	if len(rows) != 6 {
		t.Fatalf("--unique: %d rows", len(rows))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row["call_id"]] {
			t.Errorf("duplicate Call-ID %s", row["call_id"])
		}
		seen[row["call_id"]] = true
	}
	// First matching message per Call-ID: the first 4xx response of each.
	r = run(t, nil, "messages", "-q", "-F", "csv", "--unique", "--status", "4xx", aaa)
	if rows := readCSV(t, r.stdout); len(rows) != 6 {
		t.Errorf("--unique --status 4xx: %d rows", len(rows))
	} else if rows[0]["info"] == "REGISTER" {
		t.Errorf("unique ignored the filter: %v", rows[0])
	}
	// 164 Call-IDs in mixed-busy-hour (README).
	r = run(t, nil, "messages", "--count", "-q", "--unique", sample("mixed-busy-hour.pcapng"))
	if strings.TrimSpace(r.stdout) != "164" {
		t.Errorf("mixed --unique count = %q", r.stdout)
	}
}

type callRow struct {
	callID, kind, state, code string
	endedBy                   string
}

// States are the call.State meaning applied to the facts of
// testdata/samples/README.md (obtained with tshark).
var sampleCalls = []struct {
	file  string
	calls []callRow
}{
	{"basic-call.pcap", []callRow{{"0jv0hk3er8amef7w@10.0.1.10", "call", "completed", "200", "caller"}}},
	{"busy-and-reject.pcap", []callRow{
		{"p98a67hlvnj047u3@10.0.1.10", "call", "failed", "486", ""},
		{"k4c4no2o3jug0m0o@10.0.1.10", "call", "failed", "603", ""},
		{"gvpckwvdgxqtbev0@10.0.1.10", "call", "failed", "404", ""}}},
	{"cancelled-call.pcap", []callRow{{"5ne6xh31h7srybv3@10.0.1.10", "call", "cancelled", "487", "caller"}}},
	{"no-answer-retransmits.pcap", []callRow{
		{"wry2nm78bsadglhu@10.0.1.10", "call", "no-response", "", ""},
		{"yeqyr359bj5pafkb@10.0.1.10", "call", "failed", "408", ""}}},
	{"auth-register.pcap", []callRow{
		{"kzehd5y775y8t67n@10.0.1.10", "registration", "ok", "200", ""},
		{"dbu0naoa5iycvlsq@10.0.1.30", "registration", "failed", "403", ""}}},
	{"bad-media.pcap", []callRow{
		{"gjsqxqhsuw6y4rox@10.0.1.10", "call", "completed", "200", "caller"},
		{"3ysto1i3gfo77fpr@10.0.1.10", "call", "completed", "200", "caller"},
		{"ybfuxqgimm86dtek@10.0.1.10", "call", "completed", "200", "caller"}}},
	{"missing-ack.pcap", []callRow{{"0sgmu3yvwctjbrd2@10.0.1.10", "call", "completed", "200", "callee"}}},
	{"nat-problem.pcap", []callRow{{"vfj72cutpqa46bgf@192.168.1.50", "call", "completed", "200", "caller"}}},
	{"b2bua-two-legs.pcap", []callRow{
		{"bnvcw0zf0i6ci9es@10.0.1.10", "call", "completed", "200", "caller"},
		{"ipswrcvyqf4jfonu@10.0.0.1", "call", "completed", "200", ""}}},
	{"hold-resume.pcap", []callRow{
		{"px32wk5nthn92bu1@10.0.1.10", "call", "completed", "200", "caller"},
		{"uisk21dfk8enm092@10.0.1.10", "call", "completed", "200", "caller"}}},
	{"tcp-sip.pcap", []callRow{
		{"6lxghkzqy4soaz9i@10.0.1.10", "call", "completed", "200", "caller"},
		{"8w4bs1rpzmxdw4n5@10.0.1.10", "options", "ok", "200", ""}}},
	{"ipv6-vlan.pcap", []callRow{
		{"9ufhl5sm04bcbrzy@[2001:db8:1::10]", "registration", "ok", "200", ""},
		{"8td1bdxzv5zogzhz@[2001:db8:1::10]", "call", "completed", "200", "caller"},
		{"sb8lb0dhjqgzyajm@[2001:db8:1::10]", "options", "ok", "200", ""}}},
	{"features-sll-nanos.pcap", []callRow{
		{"va3j73e09dzse7n2@10.0.1.10", "call", "completed", "200", "callee"},
		{"ubmkf9q6ix92ibng@10.0.1.10", "call", "completed", "200", "caller"}}},
}

func TestCallsStates(t *testing.T) {
	for _, tc := range sampleCalls {
		t.Run(tc.file, func(t *testing.T) {
			r := run(t, nil, "calls", "-q", "-F", "csv", "--utc", sample(tc.file))
			if r.code != 0 {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			rows := readCSV(t, r.stdout)
			got := map[string]map[string]string{}
			for _, row := range rows {
				got[row["call_id"]] = row
			}
			if len(rows) != len(tc.calls) {
				t.Errorf("%d calls, want %d", len(rows), len(tc.calls))
			}
			for _, want := range tc.calls {
				row := got[want.callID]
				if row == nil {
					t.Errorf("call %s missing", want.callID)
					continue
				}
				if row["kind"] != want.kind || row["state"] != want.state || !strings.HasPrefix(row["result"], want.code) {
					t.Errorf("%s: kind %q state %q result %q; want %s %s %s", want.callID, row["kind"], row["state"], row["result"], want.kind, want.state, want.code)
				}
				if want.endedBy != "" && row["ended_by"] != want.endedBy {
					t.Errorf("%s: ended_by %q, want %q", want.callID, row["ended_by"], want.endedBy)
				}
			}
		})
	}
}

func ms(t *testing.T, s string) float64 {
	t.Helper()
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		t.Fatalf("not a number: %q", s)
	}
	return f
}

func TestCallsTimingsAndMedia(t *testing.T) {
	r := run(t, nil, "calls", "-q", "-F", "csv", sample("basic-call.pcap"))
	row := readCSV(t, r.stdout)[0]
	// README: duration 7.011 s, talk 5.004 s, 2 PCMU streams, 0 loss.
	for col, want := range map[string]float64{"duration_ms": 7011, "talk_ms": 5004, "setup_ms": 2003} {
		if got := ms(t, row[col]); got < want-1 || got > want+1 {
			t.Errorf("%s = %v, want %v", col, got, want)
		}
	}
	if row["codec"] != "PCMU" || ms(t, row["mos"]) < 4 {
		t.Errorf("codec %q mos %q", row["codec"], row["mos"])
	}
	if !strings.Contains(row["media"], "10.0.1.10:16384") || !strings.Contains(row["media"], "10.0.2.20:18000") {
		t.Errorf("media = %q", row["media"])
	}
	// Retransmissions: README no-answer-retransmits has 12 resent messages (6 per call).
	r = run(t, nil, "calls", "-q", "-F", "csv", sample("no-answer-retransmits.pcap"))
	total := 0
	for _, row := range readCSV(t, r.stdout) {
		n, _ := strconv.Atoi(row["retransmissions"])
		total += n
	}
	if total != 12 {
		t.Errorf("retransmissions = %d, want 12", total)
	}
	// --no-rtp: no MOS.
	r = run(t, nil, "calls", "-q", "--no-rtp", "-F", "csv", sample("basic-call.pcap"))
	if got := readCSV(t, r.stdout)[0]["mos"]; got != "" {
		t.Errorf("--no-rtp mos = %q", got)
	}
}

func TestCallsFiltersAndSort(t *testing.T) {
	mixed := sample("mixed-busy-hour.pcapng")
	ids := func(args ...string) []string {
		r := run(t, nil, append([]string{"calls", "-q", "-F", "csv"}, args...)...)
		if r.code != 0 {
			t.Fatalf("%v: %s", args, r.stderr)
		}
		var out []string
		for _, row := range readCSV(t, r.stdout) {
			out = append(out, row["call_id"])
		}
		return out
	}
	// Counts from README (tshark): 67 completed, 24+18+13+8+7 failed/cancelled etc.
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"all", nil, 164},
		{"state completed", []string{"--state", "completed"}, 67},
		{"state cancelled", []string{"--state", "cancelled"}, 18},
		{"failed", []string{"--failed"}, 24 + 18 + 13 + 8 + 7},
		{"answered", []string{"--answered"}, 67},
		{"kind options", []string{"--kind", "options"}, 6},
		{"kind registration", []string{"--kind", "registration"}, 3},
		{"kind call", []string{"--kind", "call"}, 155},
		{"where call field", []string{"-w", "final_code = 486"}, 24},
		{"where message field (any message)", []string{"-w", "status = 503"}, 13},
		{"where combined", []string{"-w", "state = failed", "--status", "603"}, 7},
		{"top", []string{"--top", "5"}, 5},
		{"limit", []string{"--limit", "7"}, 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if n := len(ids(append(tc.args, mixed)...)); n != tc.want {
				t.Errorf("%d calls, want %d", n, tc.want)
			}
		})
	}
	t.Run("sort duration", func(t *testing.T) {
		// README: yeqyr359bj5pafkb 32.007 s, wry2nm78bsadglhu 31.500 s.
		got := ids("--sort", "duration", sample("no-answer-retransmits.pcap"))
		if len(got) != 2 || got[0] != "yeqyr359bj5pafkb@10.0.1.10" {
			t.Errorf("order = %v", got)
		}
		got = ids(sample("no-answer-retransmits.pcap"))
		if got[0] != "wry2nm78bsadglhu@10.0.1.10" {
			t.Errorf("start order = %v", got)
		}
	})
	t.Run("sort mos worst first", func(t *testing.T) {
		// README: the stream of gjsqxqhsuw6y4rox has 39.3 % loss; the others are clean.
		got := ids("--sort", "mos", "--top", "1", sample("bad-media.pcap"))
		if len(got) != 1 || got[0] != "gjsqxqhsuw6y4rox@10.0.1.10" {
			t.Errorf("worst = %v", got)
		}
		got = ids("--sort", "mos", sample("bad-media.pcap"))
		if got[2] != "ybfuxqgimm86dtek@10.0.1.10" { // no media at all goes last
			t.Errorf("order = %v", got)
		}
	})
	t.Run("sort pdd and setup", func(t *testing.T) {
		for _, by := range []string{"pdd", "setup", "start"} {
			if got := ids("--sort", by, "--top", "3", mixed); len(got) != 3 {
				t.Errorf("--sort %s: %v", by, got)
			}
		}
	})
}

func TestShow(t *testing.T) {
	cancelled := sample("cancelled-call.pcap")
	r := run(t, nil, "show", "-q", "--utc", "--method", "CANCEL", "--status", "", cancelled)
	if r.code != ExitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	// CANCEL request and its 200 response are frames 4 and 5 (README).
	r = run(t, nil, "show", "-q", "--utc", "-w", "cseq ~ CANCEL", cancelled)
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("exit %d stderr %q", r.code, r.stderr)
	}
	blocks := strings.Split(strings.TrimRight(r.stdout, "\n"), "\n\n")
	if len(blocks) != 2 {
		t.Fatalf("%d blocks:\n%s", len(blocks), r.stdout)
	}
	head, body, _ := strings.Cut(blocks[0], "\n")
	wantHead := "#4 " + cancelled + " 2026-03-04T10:00:04.003Z 10.0.1.10:5060 -> 10.0.2.20:5060"
	if head != wantHead {
		t.Errorf("header line\n got %q\nwant %q", head, wantHead)
	}
	if !strings.HasPrefix(body, "CANCEL sip:bob@10.0.2.20:5060 SIP/2.0\n") ||
		!strings.Contains(body, "Reason: SIP;cause=200;text=\"Call completed elsewhere\"\n") ||
		strings.Contains(body, "\r") || strings.Contains(body, "\x1b") {
		t.Errorf("body:\n%q", body)
	}
	if !strings.HasPrefix(blocks[1], "#5 ") || !strings.Contains(blocks[1], "SIP/2.0 200 OK\n") {
		t.Errorf("second block:\n%s", blocks[1])
	}

	t.Run("limit", func(t *testing.T) {
		r := run(t, nil, "show", "-q", "--limit", "1", cancelled)
		if n := strings.Count(r.stdout, "\n#"); n != 0 || !strings.HasPrefix(r.stdout, "#1 ") {
			t.Errorf("stdout:\n%s", r.stdout)
		}
	})
	t.Run("color only for header names", func(t *testing.T) {
		r := run(t, nil, "show", "-q", "--color", "always", "-w", "cseq ~ CANCEL and is_request", cancelled)
		if !strings.Contains(r.stdout, "\x1b[1mVia\x1b[0m: SIP/2.0/UDP") {
			t.Errorf("no bold header name: %q", r.stdout)
		}
		if strings.Contains(r.stdout, "\x1b[1mCANCEL") || strings.Contains(strings.SplitN(r.stdout, "\n", 3)[0], "\x1b") {
			t.Errorf("colour outside header names: %q", r.stdout)
		}
		plain := run(t, nil, "show", "-q", "--color", "never", "-w", "cseq ~ CANCEL and is_request", cancelled)
		if strings.Contains(plain.stdout, "\x1b") || strings.ReplaceAll(r.stdout, "\x1b[1m", "") == "" {
			t.Errorf("--color never has escapes: %q", plain.stdout)
		}
	})
	t.Run("default is no colour when not a terminal", func(t *testing.T) {
		if strings.Contains(run(t, nil, "show", "-q", cancelled).stdout, "\x1b") {
			t.Error("escape sequences on non-tty stdout")
		}
	})
	t.Run("headers-only and sdp-only", func(t *testing.T) {
		inv := sample("basic-call.pcap")
		full := run(t, nil, "show", "-q", "--method", "INVITE", inv).stdout
		hdr := run(t, nil, "show", "-q", "--headers-only", "--method", "INVITE", inv).stdout
		sdp := run(t, nil, "show", "-q", "--sdp-only", "--method", "INVITE", inv).stdout
		if !strings.Contains(full, "\nv=0\n") || strings.Contains(hdr, "v=0") || !strings.Contains(hdr, "Call-ID:") {
			t.Errorf("headers-only:\n%s\nfull:\n%s", hdr, full)
		}
		if !strings.Contains(sdp, "v=0\n") || !strings.Contains(sdp, "m=audio 16384") || strings.Contains(sdp, "Call-ID:") {
			t.Errorf("sdp-only:\n%s", sdp)
		}
		// README: SDP offer PCMU, PCMA, telephone-event.
		if !strings.Contains(sdp, "PCMU") || !strings.Contains(sdp, "PCMA") || !strings.Contains(sdp, "telephone-event") {
			t.Errorf("offer codecs missing:\n%s", sdp)
		}
		// Messages without SDP are skipped by --sdp-only (INVITE, 200 OK are the two with SDP).
		all := run(t, nil, "show", "-q", "--sdp-only", inv).stdout
		if n := strings.Count(all, "\n#") + 1; n != 2 {
			t.Errorf("--sdp-only printed %d messages, want 2:\n%s", n, all)
		}
	})
	t.Run("output file", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "o.txt")
		r := run(t, nil, "show", "-q", "-o", out, cancelled)
		b, err := os.ReadFile(out)
		if err != nil || r.stdout != "" || !strings.HasPrefix(string(b), "#1 ") {
			t.Errorf("err %v stdout %q file %q", err, r.stdout, b)
		}
	})
}

func TestOutputFileAndColor(t *testing.T) {
	busy := sample("busy-and-reject.pcap")
	out := filepath.Join(t.TempDir(), "o.csv")
	r := run(t, nil, "messages", "-q", "-F", "csv", "-o", out, busy)
	b, err := os.ReadFile(out)
	if err != nil || r.stdout != "" || len(readCSV(t, string(b))) != 13 {
		t.Errorf("err %v stdout %q file lines %d", err, r.stdout, strings.Count(string(b), "\n"))
	}
	if r := run(t, nil, "messages", "-q", "-o", "/nonexistent-dir/x.csv", busy); r.code != ExitError {
		t.Errorf("unwritable output: %+v", r)
	}
	always := run(t, nil, "calls", "-q", "--color", "always", busy).stdout
	never := run(t, nil, "calls", "-q", "--color", "never", busy).stdout
	auto := run(t, nil, "calls", "-q", busy).stdout
	if !strings.Contains(always, "\x1b[") || strings.Contains(never, "\x1b") || strings.Contains(auto, "\x1b") {
		t.Errorf("colour: always %v never %v auto %v", strings.Contains(always, "\x1b["), strings.Contains(never, "\x1b"), strings.Contains(auto, "\x1b"))
	}
	// Colour never leaks into machine formats.
	if csv := run(t, nil, "calls", "-q", "-F", "csv", "--color", "always", busy).stdout; strings.Contains(csv, "\x1b") {
		t.Error("escape in CSV")
	}
}

func TestVersionFieldsHelp(t *testing.T) {
	r := run(t, nil, "version")
	if !strings.HasPrefix(r.stdout, "sipcurious v9.9.9-test\n") || !strings.Contains(r.stdout, "go1.") {
		t.Errorf("version: %q", r.stdout)
	}
	if r := run(t, nil, "--version"); !strings.HasPrefix(r.stdout, "sipcurious v9.9.9-test") {
		t.Errorf("--version: %q", r.stdout)
	}
	f := run(t, nil, "fields")
	for _, want := range []string{"callid", "status", "duration", "state"} {
		if !strings.Contains(f.stdout, want) {
			t.Errorf("fields lacks %q", want)
		}
	}
	h := run(t, nil, "help")
	for _, c := range Commands() {
		if !strings.Contains(h.stdout, c.Name) {
			t.Errorf("help lacks command %s", c.Name)
		}
	}
	hc := run(t, nil, "help", "calls")
	for _, want := range []string{"--failed", "--sort", "-w, --where", "-F, --format", "--limit"} {
		if !strings.Contains(hc.stdout, want) {
			t.Errorf("help calls lacks %q:\n%s", want, hc.stdout)
		}
	}
	if hm := run(t, nil, "messages", "-h").stdout; !strings.Contains(hm, "--unique") {
		t.Errorf("messages -h: %q", hm)
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		pos  []string
		v    string
		b    bool
		err  bool
	}{
		{"empty", nil, nil, "", false, false},
		{"only positionals", []string{"a", "b"}, []string{"a", "b"}, "", false, false},
		{"interspersed", []string{"a", "-v", "x", "b", "-b", "c"}, []string{"a", "b", "c"}, "x", true, false},
		{"equals", []string{"--v=x", "a"}, []string{"a"}, "x", false, false},
		{"double dash", []string{"-b", "--", "-v", "x"}, []string{"-v", "x"}, "", true, false},
		{"double dash after positional", []string{"a", "--", "-b"}, []string{"a", "-b"}, "", false, false},
		{"lone dash is positional", []string{"-", "-b"}, []string{"-"}, "", true, false},
		{"unknown flag", []string{"a", "--zzz"}, nil, "", false, true},
		{"missing value", []string{"a", "-v"}, nil, "", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			v := fs.String("v", "", "")
			b := fs.Bool("b", false, "")
			pos, err := ParseArgs(fs, tc.args)
			if (err != nil) != tc.err {
				t.Fatalf("err = %v", err)
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(pos, tc.pos) && (len(pos) != 0 || len(tc.pos) != 0) {
				t.Errorf("pos = %q, want %q", pos, tc.pos)
			}
			if *v != tc.v || *b != tc.b {
				t.Errorf("v = %q b = %v", *v, *b)
			}
		})
	}
}

func TestRegisterExtension(t *testing.T) {
	// A new command is one Register call; it shows up in help and completion.
	name := "zz-test-command"
	Register(NewCommand(Command{Name: name, Summary: "test command"}, func(fs *flag.FlagSet, o *struct{ n int }) {
		fs.IntVar(&o.n, "zz-number", 0, "a `NUMBER`")
	}, func(ctx context.Context, env *Env, c *Common, o *struct{ n int }) int {
		q, err := c.Query()
		if err != nil {
			return env.Fail(err)
		}
		ds, err := c.Open(ctx, env)
		if err != nil {
			return env.Fail(err)
		}
		idx, err := Select(ctx, ds, q, 0)
		if err != nil {
			return env.Fail(err)
		}
		return env.Result(c.WriteTable(env, MessageTable(ds.Messages, idx[:min(len(idx), o.n)])))
	}))
	defer func() {
		regMu.Lock()
		registry = registry[:len(registry)-1]
		regMu.Unlock()
	}()
	r := run(t, nil, name, "--zz-number", "2", "-q", "-F", "csv", sample("busy-and-reject.pcap"))
	if rows := readCSV(t, r.stdout); len(rows) != 2 {
		t.Errorf("rows = %d (%q)", len(rows), r.stderr)
	}
	if !strings.Contains(run(t, nil, "completion", "bash").stdout, "--zz-number") || !strings.Contains(run(t, nil, "help").stdout, name) {
		t.Error("new command missing from completion/help")
	}
	defer func() {
		if recover() == nil {
			t.Error("duplicate Register did not panic")
		}
	}()
	Register(Command{Name: "calls", Run: func(context.Context, *Env, []string) int { return 0 }})
}

func TestCompletion(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			r := run(t, nil, "completion", shell)
			if r.code != 0 || len(r.stdout) < 500 || r.stderr != "" {
				t.Fatalf("exit %d, %d bytes, stderr %q", r.code, len(r.stdout), r.stderr)
			}
			for _, c := range Commands() {
				if !strings.Contains(r.stdout, c.Name) {
					t.Errorf("%s completion lacks command %s", shell, c.Name)
				}
			}
			for _, f := range []string{"where", "callid", "format", "no-rtp", "unique", "sort", "headers-only"} {
				if !strings.Contains(r.stdout, f) {
					t.Errorf("%s completion lacks flag %s", shell, f)
				}
			}
			if !strings.Contains(r.stdout, "csv") || !strings.Contains(r.stdout, "ndjson") {
				t.Errorf("%s completion lacks format values", shell)
			}
			if shell != "fish" {
				// Balanced quoting and brackets is a cheap sanity check; the real
				// syntax check with the shell itself follows.
				if strings.Count(r.stdout, "'")%2 != 0 {
					t.Errorf("%s: unbalanced single quotes", shell)
				}
			}
			if bin, err := exec.LookPath(map[string]string{"bash": "bash", "zsh": "zsh", "fish": "fish"}[shell]); err == nil {
				args := []string{"-n"}
				if shell == "fish" {
					args = []string{"--no-execute"}
				}
				path := filepath.Join(t.TempDir(), "completion."+shell)
				os.WriteFile(path, []byte(r.stdout), 0o644)
				if out, err := exec.Command(bin, append(args, path)...).CombinedOutput(); err != nil {
					t.Errorf("%s %v: %v\n%s", bin, args, err, out)
				}
			} else {
				t.Logf("%s not installed: syntax check skipped", shell)
			}
		})
	}
	t.Run("bash completion works", func(t *testing.T) {
		bash, err := exec.LookPath("bash")
		if err != nil {
			t.Skip("bash not installed")
		}
		script := filepath.Join(t.TempDir(), "c.bash")
		os.WriteFile(script, []byte(run(t, nil, "completion", "bash").stdout), 0o644)
		probe := `source '` + filepath.ToSlash(script) + `'
COMP_WORDS=(sipcurious calls --so); COMP_CWORD=2; _sipcurious; echo "flags: ${COMPREPLY[*]}"
COMP_WORDS=(sipcurious ca); COMP_CWORD=1; _sipcurious; echo "cmds: ${COMPREPLY[*]}"
COMP_WORDS=(sipcurious calls --sort ""); COMP_CWORD=3; _sipcurious; echo "vals: ${COMPREPLY[*]}"
`
		out, err := exec.Command(bash, "-c", probe).CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		for _, want := range []string{"flags: --sort", "cmds: calls", "vals: start duration pdd setup mos"} {
			if !strings.Contains(string(out), want) {
				t.Errorf("probe lacks %q:\n%s", want, out)
			}
		}
	})
}

func TestCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := Main(ctx, &Env{Stdout: &out, Stderr: &errb}, []string{"messages", aaa})
	if code != ExitSignal || out.Len() != 0 || !strings.Contains(errb.String(), "interrupted") {
		t.Errorf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

func TestWarningsOnStderr(t *testing.T) {
	// A capture cut in the middle of a record yields a warning, not an error.
	data, err := os.ReadFile(sample("busy-and-reject.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	cut := filepath.Join(t.TempDir(), "cut.pcap")
	os.WriteFile(cut, data[:len(data)-40], 0o644)
	r := run(t, nil, "messages", "-F", "csv", cut)
	if r.code != 0 || !strings.Contains(r.stderr, "warning:") || strings.Contains(r.stdout, "warning") {
		t.Errorf("exit %d stderr %q", r.code, r.stderr)
	}
	if q := run(t, nil, "messages", "-q", "-F", "csv", cut); q.stderr != "" {
		t.Errorf("--quiet printed %q", q.stderr)
	}
}
