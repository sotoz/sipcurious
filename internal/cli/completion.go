package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

func init() {
	FlagChoices("shell", "bash", "zsh", "fish")
	Register(Command{
		Name:    "completion",
		Group:   "General",
		Summary: "print a shell completion script (bash, zsh or fish)",
		Usage:   "completion bash|zsh|fish",
		Run:     runCompletion,
	})
}

func runCompletion(_ context.Context, env *Env, args []string) int {
	if len(args) != 1 {
		return env.Fail(Usagef("usage: sipcurious completion bash|zsh|fish\n(bash: source <(sipcurious completion bash))"))
	}
	var err error
	switch args[0] {
	case "bash":
		err = writeBash(env.Stdout)
	case "zsh":
		err = writeZsh(env.Stdout)
	case "fish":
		err = writeFish(env.Stdout)
	case "-h", "--help":
		fmt.Fprintln(env.Stdout, "usage: sipcurious completion bash|zsh|fish")
		return ExitOK
	default:
		return env.Fail(Usagef("unknown shell %q (bash, zsh or fish)", args[0]))
	}
	return env.Fail(err)
}

// cmdInfo is a command with its flags resolved, for the generators.
type cmdInfo struct {
	Name    string
	Names   []string // name and aliases
	Summary string
	Flags   []flagInfo
}

func completionModel() []cmdInfo {
	var out []cmdInfo
	for _, c := range Commands() {
		ci := cmdInfo{Name: c.Name, Names: append([]string{c.Name}, c.Aliases...), Summary: c.Summary}
		if c.Flags != nil {
			fs := flag.NewFlagSet(c.Name, flag.ContinueOnError)
			c.Flags(fs)
			ci.Flags = collectFlags(fs)
		}
		out = append(out, ci)
	}
	return out
}

func (f flagInfo) spellings() []string {
	out := make([]string, len(f.Names))
	for i, n := range f.Names {
		out[i] = dashed(n)
	}
	return out
}

// takesFile reports whether the flag value is a file name.
func (f flagInfo) takesFile() bool {
	n := f.Names[len(f.Names)-1]
	return n == "file" || n == "output"
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func writeBash(w io.Writer) error {
	model := completionModel()
	var b strings.Builder
	b.WriteString("# bash completion for sipcurious; load with: source <(sipcurious completion bash)\n")
	b.WriteString("_sipcurious() {\n    local cur prev cmd i\n    COMPREPLY=()\n    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n    cmd=\"\"\n")
	b.WriteString("    for ((i = 1; i < COMP_CWORD; i++)); do\n        case \"${COMP_WORDS[i]}\" in\n            -*) ;;\n            *) cmd=\"${COMP_WORDS[i]}\"; break ;;\n        esac\n    done\n")
	var names []string
	for _, c := range model {
		names = append(names, c.Names...)
	}
	sort.Strings(names)
	fmt.Fprintf(&b, "    if [[ -z \"$cmd\" ]]; then\n        COMPREPLY=($(compgen -W %s -- \"$cur\"))\n        return 0\n    fi\n", shellQuote(strings.Join(names, " ")))
	// Value completion for flags with choices, by flag spelling.
	b.WriteString("    case \"$prev\" in\n")
	seen := map[string]bool{}
	for _, c := range model {
		for _, f := range c.Flags {
			sp := f.spellings()
			key := strings.Join(sp, "|")
			if seen[key] {
				continue
			}
			seen[key] = true
			switch ch := flagChoices(f.Names[len(f.Names)-1]); {
			case len(ch) > 0:
				fmt.Fprintf(&b, "        %s)\n            COMPREPLY=($(compgen -W %s -- \"$cur\"))\n            return 0 ;;\n", key, shellQuote(strings.Join(ch, " ")))
			case f.takesFile():
				fmt.Fprintf(&b, "        %s)\n            COMPREPLY=($(compgen -f -- \"$cur\"))\n            return 0 ;;\n", key)
			}
		}
	}
	b.WriteString("    esac\n    case \"$cmd\" in\n")
	for _, c := range model {
		var fl []string
		for _, f := range c.Flags {
			fl = append(fl, f.spellings()...)
		}
		fmt.Fprintf(&b, "        %s)\n            if [[ \"$cur\" == -* ]]; then\n                COMPREPLY=($(compgen -W %s -- \"$cur\"))\n            else\n                COMPREPLY=($(compgen -f -- \"$cur\"))\n            fi ;;\n", strings.Join(c.Names, "|"), shellQuote(strings.Join(fl, " ")))
	}
	b.WriteString("    esac\n}\ncomplete -o filenames -F _sipcurious sipcurious\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func zshEscape(s string) string {
	r := strings.NewReplacer(`'`, `'\''`, `[`, `\[`, `]`, `\]`, `:`, `\:`)
	return r.Replace(s)
}

func writeZsh(w io.Writer) error {
	model := completionModel()
	var b strings.Builder
	b.WriteString("#compdef sipcurious\n# zsh completion for sipcurious; load with: source <(sipcurious completion zsh)\n\n_sipcurious() {\n    local -a commands\n    commands=(\n")
	for _, c := range model {
		for _, n := range c.Names {
			fmt.Fprintf(&b, "        '%s:%s'\n", n, zshEscape(c.Summary))
		}
	}
	b.WriteString("    )\n    if (( CURRENT == 2 )); then\n        _describe 'command' commands\n        return\n    fi\n    case \"${words[2]}\" in\n")
	for _, c := range model {
		fmt.Fprintf(&b, "        %s)\n            _arguments -s \\\n", strings.Join(c.Names, "|"))
		for _, f := range c.Flags {
			spec := zshFlagSpec(f)
			fmt.Fprintf(&b, "                %s \\\n", spec)
		}
		b.WriteString("                '*:capture:_files'\n            ;;\n")
	}
	b.WriteString("    esac\n}\n\nif [ \"$funcstack[1]\" = \"_sipcurious\" ]; then\n    _sipcurious \"$@\"\nelse\n    compdef _sipcurious sipcurious\nfi\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func zshFlagSpec(f flagInfo) string {
	sp := f.spellings()
	desc := zshEscape(f.Usage)
	action := ""
	switch ch := flagChoices(f.Names[len(f.Names)-1]); {
	case f.Bool:
	case len(ch) > 0:
		action = ":value:(" + strings.Join(ch, " ") + ")"
	case f.takesFile():
		action = ":file:_files"
	default:
		action = ":value: "
	}
	if len(sp) == 1 {
		return fmt.Sprintf("'%s[%s]%s'", sp[0], desc, action)
	}
	return fmt.Sprintf("'(%s)'{%s}'[%s]%s'", strings.Join(sp, " "), strings.Join(sp, ","), desc, action)
}

func writeFish(w io.Writer) error {
	model := completionModel()
	var b strings.Builder
	b.WriteString("# fish completion for sipcurious; load with: sipcurious completion fish | source\n")
	b.WriteString("complete -c sipcurious -f\n")
	var all []string
	for _, c := range model {
		all = append(all, c.Names...)
	}
	for _, c := range model {
		for _, n := range c.Names {
			fmt.Fprintf(&b, "complete -c sipcurious -n '__fish_use_subcommand' -a %s -d %s\n", n, shellQuote(c.Summary))
		}
	}
	for _, c := range model {
		cond := fmt.Sprintf("'__fish_seen_subcommand_from %s'", strings.Join(c.Names, " "))
		for _, f := range c.Flags {
			var opts []string
			for _, n := range f.Names {
				if len(n) == 1 {
					opts = append(opts, "-s "+n)
				} else {
					opts = append(opts, "-l "+n)
				}
			}
			line := fmt.Sprintf("complete -c sipcurious -n %s %s -d %s", cond, strings.Join(opts, " "), shellQuote(f.Usage))
			switch ch := flagChoices(f.Names[len(f.Names)-1]); {
			case f.Bool:
			case len(ch) > 0:
				line += " -x -a " + shellQuote(strings.Join(ch, " "))
			case f.takesFile():
				line += " -r -F"
			default:
				line += " -x"
			}
			b.WriteString(line + "\n")
		}
		fmt.Fprintf(&b, "complete -c sipcurious -n %s -F\n", cond)
	}
	b.WriteString("complete -c sipcurious -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'\n")
	_ = all
	_, err := io.WriteString(w, b.String())
	return err
}
