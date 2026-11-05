// Package cli is the command line framework of sipcurious: a registry of
// subcommands, one shared flag vocabulary, exit codes and output plumbing.
//
// # Conventions
//
// Data goes to stdout (or to the --output file); the summary line, warnings
// and errors go to stderr, prefixed "sipcurious: ". Exit codes: ExitOK (0),
// ExitError (1, runtime failure), ExitUsage (2, bad flags/arguments/query),
// ExitFindings (3, diagnose found findings at or above --fail-on), and 130 when
// interrupted.
//
// # Adding a subcommand
//
// A subcommand is one file in this package whose init function calls Register.
// Nothing else is edited: help, "sipcurious help <cmd>", shell completion and
// the did-you-mean suggestion all read the registry. The shortest recipe,
// built on NewCommand, gives the command the common flag set (capture paths,
// --where and the filter sugar flags, --format, --extra, --utc, --color,
// --output, --limit, --no-rtp, --quiet):
//
//	type flowOpts struct{ width int }
//
//	func init() {
//		Register(NewCommand(Command{
//			Name:    "flow",
//			Summary: "draw a ladder diagram of a call",
//			Usage:   "flow [flags] CAPTURE...",
//		}, func(fs *flag.FlagSet, o *flowOpts) {
//			fs.IntVar(&o.width, "width", 100, "diagram `WIDTH`")
//		}, func(ctx context.Context, env *Env, c *Common, o *flowOpts) int {
//			q, err := c.Query() // validate flags before the expensive load
//			if err != nil {
//				return env.Fail(err)
//			}
//			ds, err := c.Open(ctx, env) // loads files, prints warnings and a summary
//			if err != nil {
//				return env.Fail(err)
//			}
//			rows := Select(ctx, ds, q, 0) // indices of matching ds.Messages
//			_ = rows
//			return env.Result(c.WriteTable(env, report.Table{ /* ... */ }))
//		}))
//	}
//
// Use Output when the command writes something other than a table (text,
// HTML documents): c.OpenOutput(env) honours --output and --color. Return
// UsageError values (via Usagef) for problems with the arguments so that they
// exit with code 2. Use FlagChoices to teach shell completion the values of a
// flag, and Command.Run directly (without NewCommand) for a command that does
// not want the common flags.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Exit codes returned by Main.
const (
	ExitOK       = 0   // success (also "no matches")
	ExitError    = 1   // runtime error: unreadable capture, write failure
	ExitUsage    = 2   // usage error: unknown command or flag, bad expression
	ExitFindings = 3   // findings at or above --fail-on (diagnose)
	ExitSignal   = 130 // interrupted
)

// Env is the process environment of a command. Tests substitute buffers.
type Env struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
	Version        string // version stamped at build time, "" if unknown
}

// Command is a registered subcommand.
type Command struct {
	Name    string
	Aliases []string
	Summary string // one line, shown in the command list
	// Group is the heading of the command in 'sipcurious help' (e.g. "Inspect");
	// commands without one are listed under "Other".
	Group string
	// Formats, when set, replaces the --format values that NewCommand offers
	// (default report.Formats()): the first is the default. Commands that
	// accept values report does not know ("ascii", "pcapng") read Common.Format
	// themselves; ReportFormat is then "".
	Formats []string
	// Long is optional extra help text printed after the summary by 'help <cmd>'.
	Long  string
	Usage string // synopsis, e.g. "calls [flags] CAPTURE..."
	// Run executes the command; args exclude the command name. It returns the
	// exit code.
	Run func(ctx context.Context, env *Env, args []string) int
	// Flags binds the command's flags to fs. It is used by help and shell
	// completion only (Run parses its own flags); NewCommand sets it.
	Flags func(fs *flag.FlagSet)
}

var (
	regMu    sync.RWMutex
	registry []Command
)

// Register adds a command. It panics on a duplicate name or alias or a missing
// Name/Run: those are programming errors found by any test run.
func Register(c Command) {
	if c.Name == "" || c.Run == nil {
		panic("cli: Register needs Name and Run")
	}
	if len(c.Formats) > 0 {
		// Completion knows flag values by name only: offer every command's.
		AddFlagChoices("format", c.Formats...)
	}
	regMu.Lock()
	defer regMu.Unlock()
	for _, name := range append([]string{c.Name}, c.Aliases...) {
		if lookupLocked(name) != nil {
			panic("cli: duplicate command " + name)
		}
	}
	registry = append(registry, c)
}

func lookupLocked(name string) *Command {
	for i := range registry {
		if registry[i].Name == name || slices.Contains(registry[i].Aliases, name) {
			return &registry[i]
		}
	}
	return nil
}

// Lookup finds a command by name or alias.
func Lookup(name string) (Command, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	if c := lookupLocked(name); c != nil {
		return *c, true
	}
	return Command{}, false
}

// Commands returns the registered commands sorted by name.
func Commands() []Command {
	regMu.RLock()
	out := slices.Clone(registry)
	regMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// UsageError is an error in how the command was invoked; it exits with 2.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// Usagef returns a UsageError.
func Usagef(format string, args ...any) error {
	return &UsageError{Msg: fmt.Sprintf(format, args...)}
}

// Printf writes to stderr with the "sipcurious: " prefix.
func (e *Env) Printf(format string, args ...any) {
	fmt.Fprintf(e.Stderr, "sipcurious: "+format+"\n", args...)
}

// Fail reports err on stderr and returns the matching exit code: 2 for a
// UsageError, 130 for an interrupt, 1 otherwise. A closed output pipe exits 1
// silently. A nil error returns 0.
func (e *Env) Fail(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, context.Canceled):
		e.Printf("interrupted")
		return ExitSignal
	case isClosedPipe(err):
		return ExitError
	}
	var ue *UsageError
	if errors.As(err, &ue) {
		e.Printf("%s", strings.ReplaceAll(err.Error(), "\n", "\n    "))
		return ExitUsage
	}
	e.Printf("%v", err)
	return ExitError
}

// Result is Fail for the common "return the outcome of a write" case.
func (e *Env) Result(err error) int { return e.Fail(err) }

func (e *Env) normalize() {
	if e.Stdout == nil {
		e.Stdout = os.Stdout
	}
	if e.Stderr == nil {
		e.Stderr = os.Stderr
	}
	if e.Stdin == nil {
		e.Stdin = os.Stdin
	}
}

// Main dispatches args (without the program name) to a command and returns the
// process exit code.
func Main(ctx context.Context, env *Env, args []string) int {
	env.normalize()
	if len(args) == 0 {
		printGlobalUsage(env.Stderr)
		return ExitUsage
	}
	name, rest := args[0], args[1:]
	switch name {
	case "-h", "-help", "--help":
		printGlobalUsage(env.Stdout)
		return ExitOK
	case "-V", "-version", "--version":
		return runVersion(ctx, env, nil)
	}
	cmd, ok := Lookup(name)
	if !ok {
		msg := fmt.Sprintf("unknown command %q", name)
		if s := suggest(name); s != "" {
			msg += fmt.Sprintf(" (did you mean %q?)", s)
		}
		env.Printf("%s; run 'sipcurious help' for the list of commands", msg)
		return ExitUsage
	}
	return cmd.Run(ctx, env, rest)
}

// suggest returns the registered name closest to s, or "".
func suggest(s string) string {
	best, bestD := "", 3
	regMu.RLock()
	defer regMu.RUnlock()
	for _, c := range registry {
		for _, n := range append([]string{c.Name}, c.Aliases...) {
			d := editDistance(s, n)
			if strings.HasPrefix(n, s) && len(s) >= 2 {
				d = 1
			}
			if d < bestD {
				best, bestD = n, d
			}
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
