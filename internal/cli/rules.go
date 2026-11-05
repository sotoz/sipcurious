package cli

import (
	"context"
	"flag"
	"io"
	"strings"

	"github.com/sotoz/sipcurious/internal/analysis"
	"github.com/sotoz/sipcurious/internal/report"
)

func init() {
	Register(Command{
		Name:    "rules",
		Group:   "Reference",
		Summary: "list the diagnostic rules of 'diagnose'; 'rules ID' explains one, --docs all",
		Usage:   "rules [--docs] [--format FORMAT] [ID]",
		Flags: func(fs *flag.FlagSet) {
			var c Common
			bindRulesFlags(fs, &c, new(bool))
		},
		Run: runRules,
	})
}

func bindRulesFlags(fs *flag.FlagSet, c *Common, docs *bool) {
	fs.BoolVar(docs, "docs", false, "print the documentation of every rule as Markdown")
	fs.StringVar(&c.Format, "format", "table", "output `FORMAT` of the list: "+strings.Join(report.Formats(), ", "))
	Alias(fs, "format", "F")
	fs.StringVar(&c.Output, "output", "", "write the result to `FILE` instead of stdout")
	Alias(fs, "output", "o")
}

func runRules(_ context.Context, env *Env, args []string) int {
	c := Common{Color: "auto"}
	var docs bool
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	bindRulesFlags(fs, &c, &docs)
	pos, err := ParseArgs(fs, args)
	if err == flag.ErrHelp {
		printCommandUsage(env.Stdout, mustLookup("rules"))
		return ExitOK
	}
	if err != nil {
		return env.Fail(Usagef("%v (see 'sipcurious help rules')", err))
	}
	if err := c.Finish(nil); err != nil {
		return env.Fail(err)
	}
	if len(pos) > 1 || (docs && len(pos) > 0) {
		return env.Fail(Usagef("usage: sipcurious rules [--docs | ID]"))
	}
	switch {
	case docs:
		return env.Fail(c.writeText(env, func(w io.Writer) error {
			_, err := io.WriteString(w, analysis.RuleDocs())
			return err
		}))
	case len(pos) == 1:
		r, ok := analysis.Lookup(pos[0])
		if !ok {
			return env.Fail(Usagef("unknown rule %q (valid: %s)", pos[0], strings.Join(analysis.IDs(), ", ")))
		}
		return env.Fail(c.writeText(env, func(w io.Writer) error {
			_, err := io.WriteString(w, ruleDoc(r))
			return err
		}))
	}
	return env.Fail(c.WriteTable(env, RuleTable()))
}

func mustLookup(name string) Command {
	cmd, _ := Lookup(name)
	return cmd
}

// ruleDoc is the Markdown of one rule: title heading and its Doc text.
func ruleDoc(r analysis.Rule) string {
	var b strings.Builder
	b.WriteString("## `" + r.ID() + "`\n\n" + r.Title() + "\n\n")
	if d, ok := r.(analysis.Documented); ok {
		if doc := strings.TrimSpace(d.Doc()); doc != "" {
			b.WriteString(doc + "\n")
		}
	}
	return b.String()
}

// RuleTable lists the registered rules: ID, severities it can report and the
// title. The severities come from the rule's documentation ("Severity: ...")
// and are "info" when it does not say.
func RuleTable() report.Table {
	t := report.Table{
		Title: "Rules",
		Columns: []report.Column{
			{Name: "Rule", Key: "rule"},
			{Name: "Severity", Key: "severity"},
			{Name: "Title", Key: "title"},
		},
	}
	for _, r := range analysis.Rules() {
		t.Rows = append(t.Rows, []any{r.ID(), severityRange(r), r.Title()})
	}
	return t
}

// severityRange lists the severities a rule documents in bold (**info**,
// **warning**, **error**) as "lowest - highest"; "" for undocumented rules.
func severityRange(r analysis.Rule) string {
	d, ok := r.(analysis.Documented)
	if !ok {
		return ""
	}
	doc := strings.ToLower(d.Doc())
	var parts []string
	for _, name := range severities {
		if strings.Contains(doc, "**"+name+"**") {
			parts = append(parts, name)
		}
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return parts[0] + " - " + parts[len(parts)-1]
}

// writeText runs fn against the --output destination (stdout by default).
func (c *Common) writeText(env *Env, fn func(io.Writer) error) error {
	out, err := c.OpenOutput(env)
	if err != nil {
		return err
	}
	werr := fn(out)
	if cerr := out.Close(); werr == nil {
		werr = cerr
	}
	return werr
}
