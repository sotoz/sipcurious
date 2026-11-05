package analysis

import (
	"fmt"
	"strings"

	"github.com/sotoz/sipcurious/internal/report"
)

// Table renders findings as a report table: Severity, Rule, Call-ID, Time
// and Title, plus the Detail, Hint and Packets columns as Extra columns.
func Table(fs []Finding) report.Table {
	t := report.Table{
		Title: "Findings",
		Columns: []report.Column{
			{Name: "Severity", Key: "severity", Style: func(v any) report.Style {
				s, _ := v.(string)
				return report.SeverityStyle(s)
			}},
			{Name: "Rule", Key: "rule"},
			{Name: "Call-ID", Key: "call_id"},
			{Name: "Time", Key: "time", Kind: report.Time},
			{Name: "Title", Key: "title"},
			{Name: "Detail", Key: "detail", Extra: true},
			{Name: "Hint", Key: "hint", Extra: true},
			{Name: "Packets", Key: "packets", Extra: true},
		},
		Rows: make([][]any, 0, len(fs)),
	}
	for _, f := range fs {
		t.Rows = append(t.Rows, []any{f.Severity.String(), f.Rule, f.CallID, f.Time, f.Title, f.Detail, f.Hint, packetList(f.Packets)})
	}
	return t
}

// packetList renders refs as "file:index, file:index".
func packetList(refs []Ref) string {
	var b strings.Builder
	for i, r := range refs {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s:%d", r.File, r.Index)
	}
	return b.String()
}

// Counts is the number of findings per severity.
type Counts struct {
	Errors, Warnings, Infos int
}

// Total is the number of findings counted.
func (c Counts) Total() int { return c.Errors + c.Warnings + c.Infos }

// String renders the counts as "2 errors, 1 warning, 0 info".
func (c Counts) String() string {
	return fmt.Sprintf("%d %s, %d %s, %d info", c.Errors, plural(c.Errors, "error", "errors"), c.Warnings, plural(c.Warnings, "warning", "warnings"), c.Infos)
}

// Summary counts findings by severity.
func Summary(fs []Finding) Counts {
	var c Counts
	for _, f := range fs {
		switch f.Severity {
		case Error:
			c.Errors++
		case Warning:
			c.Warnings++
		default:
			c.Infos++
		}
	}
	return c
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
