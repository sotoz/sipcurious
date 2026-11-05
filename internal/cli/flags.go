package cli

import (
	"flag"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
)

// aliasMark prefixes the usage of a flag that is only another spelling of an
// existing flag, so that help prints them together and completion lists both.
// The usage text after the mark is the canonical flag name.
const aliasMark = "\x00"

// flagInfo is one logical flag: the canonical name, its aliases, and metadata.
type flagInfo struct {
	Names   []string // aliases first, canonical (long) name last
	Usage   string
	VarName string // placeholder from `back quotes` in the usage, "" for booleans
	Default string
	Bool    bool
}

func dashed(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

// collectFlags lists the logical flags of fs sorted by canonical name.
func collectFlags(fs *flag.FlagSet) []flagInfo {
	aliases := map[string][]string{}
	var out []flagInfo
	fs.VisitAll(func(f *flag.Flag) {
		if target, ok := strings.CutPrefix(f.Usage, aliasMark); ok {
			aliases[target] = append(aliases[target], f.Name)
			return
		}
		name, usage := flag.UnquoteUsage(f)
		_, isBool := f.Value.(interface{ IsBoolFlag() bool })
		if isBool {
			name = ""
		}
		out = append(out, flagInfo{Names: []string{f.Name}, Usage: usage, VarName: name, Default: f.DefValue, Bool: isBool})
	})
	for i := range out {
		canon := out[i].Names[0]
		out[i].Names = append(slices.Clone(aliases[canon]), canon)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Names[len(out[i].Names)-1] < out[j].Names[len(out[j].Names)-1]
	})
	return out
}

// Alias registers short (or alternative) names for the already defined flag
// name, sharing its value. Help and completion show them together.
func Alias(fs *flag.FlagSet, name string, aliases ...string) {
	f := fs.Lookup(name)
	if f == nil {
		panic("cli: Alias of undefined flag " + name)
	}
	for _, a := range aliases {
		fs.Var(f.Value, a, aliasMark+name)
	}
}

var (
	choicesMu sync.RWMutex
	choices   = map[string][]string{}
)

// FlagChoices declares the accepted values of the flag called name, for shell
// completion. The declaration is global by flag name because every command
// shares one flag vocabulary.
func FlagChoices(name string, values ...string) {
	choicesMu.Lock()
	choices[name] = slices.Clone(values)
	choicesMu.Unlock()
}

// AddFlagChoices adds values to the accepted values of the flag called name
// (those already declared stay). Commands whose flag of a shared name takes
// other values than the same flag of another command use it, so that shell
// completion offers the union.
func AddFlagChoices(name string, values ...string) {
	choicesMu.Lock()
	for _, v := range values {
		if !slices.Contains(choices[name], v) {
			choices[name] = append(choices[name], v)
		}
	}
	choicesMu.Unlock()
}

func flagChoices(name string) []string {
	choicesMu.RLock()
	defer choicesMu.RUnlock()
	return choices[name]
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// ParseArgs parses args into fs allowing flags before, between and after the
// positional arguments ("--" ends flag parsing; a lone "-" is positional) and
// returns the positionals. Diagnostics are not printed: the error is returned
// (flag.ErrHelp for -h/--help).
func ParseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		// Parse stops at the first positional, or right after a "--" that it
		// consumed (then everything left is positional).
		if used := len(args) - len(rest); used > 0 && args[used-1] == "--" {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}
