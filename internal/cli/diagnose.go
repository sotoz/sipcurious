package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/sotoz/sipcurious/internal/analysis"
	"github.com/sotoz/sipcurious/internal/engine"
	"github.com/sotoz/sipcurious/internal/query"
	"github.com/sotoz/sipcurious/internal/report"
)

type diagnoseOpts struct {
	rules, disable string
	minSeverity    string
	failOn         string
	callsOnly      bool
	thresholds
}

var (
	severities = []string{"info", "warning", "error"}
	failOns    = []string{"never", "warning", "error"}
)

func init() {
	FlagChoices("min-severity", severities...)
	FlagChoices("fail-on", failOns...)
	Register(NewCommand(Command{
		Name:    "diagnose",
		Aliases: []string{"check"},
		Group:   "Analyze",
		Summary: "run the diagnostic rules (failed calls, retransmissions, NAT, media quality, ...) and list the findings",
		Usage:   "diagnose [flags] CAPTURE...",
		Long: `Runs every rule of 'sipcurious rules' over the capture and lists the findings,
worst first. The default table has one row per finding: Severity, Rule, Call-ID,
Time and Title. With --extra the table format switches to a report grouped per
call (the call first, then each finding with its explanation, hint and packet
numbers indented below it); the machine formats (csv, json, ndjson) always
carry Detail, Hint and Packets. The summary line goes to stderr.

--where and the other filters select calls: findings of matching calls are
shown, and so are the capture-wide ones unless --calls-only is given.

Exit codes: 0 ok, 1 error, 2 usage, 3 with --fail-on when a finding of that
severity or worse exists.`,
	}, func(fs *flag.FlagSet, o *diagnoseOpts) {
		fs.StringVar(&o.rules, "rules", "", "run only these rules, comma separated `IDS` (see 'sipcurious rules')")
		fs.StringVar(&o.disable, "disable", "", "do not run these rules, comma separated `IDS`")
		fs.StringVar(&o.minSeverity, "min-severity", "info", "hide findings below this `SEVERITY`: info, warning, error")
		fs.StringVar(&o.failOn, "fail-on", "never", "exit with code 3 when a finding has at least this `SEVERITY`: warning, error, never")
		fs.BoolVar(&o.callsOnly, "calls-only", false, "with a call filter, also drop the capture-wide findings")
		o.bindSIP(fs)
		o.bindMedia(fs)
	}, runDiagnose))
}

func runDiagnose(ctx context.Context, env *Env, c *Common, o *diagnoseOpts) int {
	opt, failAt, err := o.runOptions()
	if err != nil {
		return env.Fail(err)
	}
	cfg, err := o.config()
	if err != nil {
		return env.Fail(err)
	}
	q, err := c.Query()
	if err != nil {
		return env.Fail(err)
	}
	ds, err := c.Open(ctx, env)
	if err != nil {
		return env.Fail(err)
	}
	fs, err := analysis.Run(ds.AnalysisInput(cfg), opt)
	if err != nil {
		return env.Fail(err)
	}
	if q != nil {
		fs = filterFindings(fs, ds, q, o.callsOnly)
	}
	if c.NoRTP {
		c.Infof(env, "--no-rtp: the media rules had no RTP to look at")
	}
	counts := analysis.Summary(fs)
	c.Infof(env, "%s (%s checked)", counts, plural(len(ds.Calls()), "call"))

	if c.ReportFormat() == report.FormatTable && c.Extra {
		err = c.WriteWith(env, func(w io.Writer, _ report.Format, ro report.Options) error {
			return writeGrouped(w, fs, ds, c.UTC, ro.Color)
		})
	} else {
		err = c.WriteTable(env, analysis.Table(fs))
	}
	if err != nil {
		return env.Fail(err)
	}
	if failAt >= 0 {
		for _, f := range fs {
			if f.Severity >= failAt {
				c.Infof(env, "failing: findings at or above %s (--fail-on)", failAt)
				return ExitFindings
			}
		}
	}
	return ExitOK
}

// runOptions validates the rule and severity flags. failAt is -1 for "never".
func (o *diagnoseOpts) runOptions() (opt analysis.RunOptions, failAt analysis.Severity, err error) {
	failAt = -1
	opt.Enable, opt.Disable = splitList(o.rules), splitList(o.disable)
	for flagName, ids := range map[string][]string{"--rules": opt.Enable, "--disable": opt.Disable} {
		for _, id := range ids {
			if _, ok := analysis.Lookup(id); !ok {
				return opt, 0, Usagef("%s: unknown rule %q (valid: %s)", flagName, id, strings.Join(analysis.IDs(), ", "))
			}
		}
	}
	if opt.MinSeverity, err = analysis.ParseSeverity(o.minSeverity); err != nil {
		return opt, 0, Usagef("--min-severity: %v (info, warning or error)", err)
	}
	switch strings.ToLower(o.failOn) {
	case "never":
	case "warning", "error":
		failAt, _ = analysis.ParseSeverity(o.failOn)
	default:
		return opt, 0, Usagef("--fail-on: %q is not warning, error or never", o.failOn)
	}
	return opt, failAt, nil
}

// filterFindings keeps the findings of the calls matching q, and the
// capture-wide ones unless callsOnly.
func filterFindings(fs []analysis.Finding, ds *engine.Dataset, q *query.Query, callsOnly bool) []analysis.Finding {
	out := fs[:0:0]
	for _, f := range fs {
		if f.CallID == "" {
			if !callsOnly {
				out = append(out, f)
			}
			continue
		}
		if cl := ds.CallOf(f.CallID); cl != nil && q.MatchCall(cl) {
			out = append(out, f)
		}
	}
	return out
}

// writeGrouped prints findings grouped per call, worst call first:
//
//	<Call-ID>  <from> -> <to>  <state> <result>
//	  ERROR    missing-ack   <time>  <title>
//	           <detail, indented>
//	           hint: <hint>
//
// Capture-wide findings come under the heading "capture".
func writeGrouped(w io.Writer, fs []analysis.Finding, ds *engine.Dataset, utc, color bool) error {
	var order []string
	groups := map[string][]analysis.Finding{}
	for _, f := range fs {
		if _, ok := groups[f.CallID]; !ok {
			order = append(order, f.CallID)
		}
		groups[f.CallID] = append(groups[f.CallID], f)
	}
	var sb strings.Builder
	for n, id := range order {
		if n > 0 {
			sb.WriteByte('\n')
		}
		if id == "" {
			sb.WriteString("capture\n")
		} else {
			sb.WriteString(clean(id))
			if cl := ds.CallOf(id); cl != nil {
				fmt.Fprintf(&sb, "  %s -> %s  %s", clean(nonEmpty(cl.FromUser, cl.From)), clean(nonEmpty(cl.ToUser, cl.To)), cl.State)
				if cl.Result != "" {
					sb.WriteString(" " + clean(cl.Result))
				}
			}
			sb.WriteByte('\n')
		}
		for _, f := range groups[id] {
			sev := strings.ToUpper(f.Severity.String())
			pad := fmt.Sprintf("%-7s", sev)
			if color {
				pad = sevColor(f.Severity) + pad + "\x1b[0m"
			}
			ts := ""
			if !f.Time.IsZero() {
				ts = "  " + report.FormatTime(f.Time, utc)
			}
			fmt.Fprintf(&sb, "  %s %s%s  %s\n", pad, f.Rule, ts, clean(f.Title))
			indent := "          "
			for _, line := range strings.Split(strings.TrimSpace(f.Detail), "\n") {
				if line = strings.TrimRight(line, " \t\r"); line != "" {
					sb.WriteString(indent + clean(line) + "\n")
				}
			}
			if f.Hint != "" {
				sb.WriteString(indent + "hint: " + clean(f.Hint) + "\n")
			}
			if len(f.Packets) > 0 {
				sb.WriteString(indent + "packets: " + clean(packetRefs(f.Packets)) + "\n")
			}
		}
	}
	_, err := w.Write([]byte(sb.String()))
	return err
}

func packetRefs(refs []analysis.Ref) string {
	parts := make([]string, len(refs))
	for i, r := range refs {
		parts[i] = fmt.Sprintf("%s:%d", r.File, r.Index)
	}
	return strings.Join(parts, ", ")
}

func sevColor(s analysis.Severity) string {
	switch s {
	case analysis.Error:
		return "\x1b[31m"
	case analysis.Warning:
		return "\x1b[33m"
	}
	return "\x1b[2m"
}
