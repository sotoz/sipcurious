package analysis

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// RunOptions selects the rules Run executes and the findings it keeps.
type RunOptions struct {
	// Enable, if not empty, restricts the run to these rule IDs.
	Enable []string
	// Disable removes these rule IDs from the run (applied after Enable).
	Disable []string
	// MinSeverity drops findings below this severity.
	MinSeverity Severity
}

// ParseSeverity converts "info", "warning" ("warn") or "error" (case
// insensitive) to a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, nil
	case "warning", "warn":
		return Warning, nil
	case "error", "err":
		return Error, nil
	}
	return Info, fmt.Errorf("analysis: unknown severity %q (valid: info, warning, error)", s)
}

// Run executes the selected rules over in and returns their findings sorted
// by severity (highest first), time (earliest first, findings without a time
// last), rule ID, Call-ID, then title. A nil in is treated as empty. The
// caller's Input is not modified: its Config is completed with
// Config.WithDefaults for the rules only. Unknown rule IDs in opt give an
// error that lists the valid IDs.
func Run(in *Input, opt RunOptions) ([]Finding, error) {
	if err := checkIDs("enable", opt.Enable); err != nil {
		return nil, err
	}
	if err := checkIDs("disable", opt.Disable); err != nil {
		return nil, err
	}
	var local Input
	if in != nil {
		local = *in
	}
	local.Config = local.Config.WithDefaults()

	var out []Finding
	for _, r := range Rules() {
		id := r.ID()
		if len(opt.Enable) > 0 && !slices.Contains(opt.Enable, id) || slices.Contains(opt.Disable, id) {
			continue
		}
		for _, f := range r.Check(&local) {
			if f.Rule == "" {
				f.Rule = id
			}
			if f.Severity >= opt.MinSeverity {
				out = append(out, f)
			}
		}
	}
	slices.SortStableFunc(out, compareFindings)
	return out, nil
}

func checkIDs(what string, ids []string) error {
	for _, id := range ids {
		if _, ok := Lookup(id); !ok {
			return fmt.Errorf("analysis: unknown rule %q in %s list (valid rules: %s)", id, what, strings.Join(IDs(), ", "))
		}
	}
	return nil
}

func compareFindings(a, b Finding) int {
	if c := cmp.Compare(b.Severity, a.Severity); c != 0 {
		return c
	}
	switch az, bz := a.Time.IsZero(), b.Time.IsZero(); {
	case az != bz:
		if az {
			return 1
		}
		return -1
	case !az:
		if c := a.Time.Compare(b.Time); c != 0 {
			return c
		}
	}
	return cmp.Or(
		strings.Compare(a.Rule, b.Rule),
		strings.Compare(a.CallID, b.CallID),
		strings.Compare(a.Title, b.Title),
	)
}
