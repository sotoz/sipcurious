package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
)

func init() {
	Register(Command{
		Name:    "help",
		Group:   "General",
		Summary: "show help for sipcurious or one command",
		Usage:   "help [command]",
		Run:     runHelp,
	})
}

func runHelp(_ context.Context, env *Env, args []string) int {
	if len(args) == 0 {
		printGlobalUsage(env.Stdout)
		return ExitOK
	}
	cmd, ok := Lookup(args[0])
	if !ok {
		msg := fmt.Sprintf("no help for unknown command %q", args[0])
		if s := suggest(args[0]); s != "" {
			msg += fmt.Sprintf(" (did you mean %q?)", s)
		}
		env.Printf("%s", msg)
		return ExitUsage
	}
	printCommandUsage(env.Stdout, cmd)
	return ExitOK
}

// helpGroups are the headings of Command.Group in the order 'help' lists them.
var helpGroups = []string{"Inspect", "Analyze", "Share", "Reference", "General"}

func printGlobalUsage(w io.Writer) {
	fmt.Fprint(w, `sipcurious - troubleshoot SIP/VoIP calls from pcap files

Usage:
  sipcurious <command> [flags] [capture files, directories or - for stdin]
`)
	cmds := Commands()
	width := 0
	for _, c := range cmds {
		width = max(width, len(c.Name))
	}
	// Groups appear in the order of helpGroups; commands inside by name.
	// A command without (or with an unknown) group is listed under "Other".
	groups := append(slices.Clone(helpGroups), "Other")
	for _, g := range groups {
		var in []Command
		for _, c := range cmds {
			cg := c.Group
			if !slices.Contains(helpGroups, cg) {
				cg = "Other"
			}
			if cg == g {
				in = append(in, c)
			}
		}
		if len(in) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s:\n", g)
		for _, c := range in {
			fmt.Fprintf(w, "  %-*s  %s", width, c.Name, c.Summary)
			if len(c.Aliases) > 0 {
				fmt.Fprintf(w, " (alias: %s)", strings.Join(c.Aliases, ", "))
			}
			fmt.Fprintln(w)
		}
	}
	fmt.Fprint(w, `
Run 'sipcurious help <command>' for the flags of a command, and
'sipcurious fields' for the filter language used by --where.

Exit codes: 0 ok, 1 runtime error, 2 usage error, 3 findings at or above --fail-on.
Data is written to stdout; summaries, warnings and errors go to stderr.
`)
}

func printCommandUsage(w io.Writer, c Command) {
	usage := c.Usage
	if usage == "" {
		usage = c.Name
	}
	fmt.Fprintf(w, "Usage: sipcurious %s\n\n%s\n", usage, c.Summary)
	if c.Long != "" {
		fmt.Fprintf(w, "\n%s\n", strings.TrimSpace(c.Long))
	}
	if len(c.Aliases) > 0 {
		fmt.Fprintf(w, "Aliases: %s\n", strings.Join(c.Aliases, ", "))
	}
	if c.Flags == nil {
		return
	}
	fs := flag.NewFlagSet(c.Name, flag.ContinueOnError)
	c.Flags(fs)
	fmt.Fprintln(w, "\nFlags:")
	printFlags(w, fs)
}

// printFlags prints the flags of fs, short aliases joined with their long name.
func printFlags(w io.Writer, fs *flag.FlagSet) {
	for _, f := range collectFlags(fs) {
		var names []string
		for _, n := range f.Names {
			names = append(names, dashed(n))
		}
		head := strings.Join(names, ", ")
		if f.VarName != "" {
			head += " " + f.VarName
		}
		def := ""
		if f.Default != "" && f.Default != "false" && f.Default != "0" {
			def = fmt.Sprintf(" (default %s)", f.Default)
		}
		fmt.Fprintf(w, "  %s\n          %s%s\n", head, f.Usage, def)
	}
}
