package analysis

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Documented is implemented by rules that explain themselves: what they
// detect, which thresholds they use and why a finding matters. The text is
// Markdown and feeds RuleDocs and the generated documentation.
type Documented interface {
	Doc() string
}

var (
	regMu sync.RWMutex
	rules []Rule // sorted by ID
)

// Register adds r to the registry. It is meant to be called from init
// functions. A nil rule, an empty ID, or an ID that is already registered
// is a programming error and panics.
func Register(r Rule) {
	if r == nil {
		panic("analysis: Register of a nil rule")
	}
	id := r.ID()
	if id == "" {
		panic("analysis: Register of a rule with an empty ID")
	}
	regMu.Lock()
	defer regMu.Unlock()
	i, dup := slices.BinarySearchFunc(rules, id, func(r Rule, id string) int { return strings.Compare(r.ID(), id) })
	if dup {
		panic(fmt.Sprintf("analysis: rule %q registered twice", id))
	}
	rules = slices.Insert(rules, i, r)
}

// Rules returns a copy of the registered rules sorted by ID.
func Rules() []Rule {
	regMu.RLock()
	defer regMu.RUnlock()
	return slices.Clone(rules)
}

// Lookup returns the rule with the given ID.
func Lookup(id string) (Rule, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	i, ok := slices.BinarySearchFunc(rules, id, func(r Rule, id string) int { return strings.Compare(r.ID(), id) })
	if !ok {
		return nil, false
	}
	return rules[i], true
}

// IDs returns the IDs of all registered rules in sorted order.
func IDs() []string {
	rs := Rules()
	ids := make([]string, len(rs))
	for i, r := range rs {
		ids[i] = r.ID()
	}
	return ids
}

// RuleDocs renders every registered rule as Markdown, one level-2 section
// per rule in ID order: the ID, the one-line title and the rule's Doc text
// (rules that are not Documented only show their title).
func RuleDocs() string {
	var b strings.Builder
	for _, r := range Rules() {
		fmt.Fprintf(&b, "## `%s`\n\n%s\n\n", r.ID(), r.Title())
		if d, ok := r.(Documented); ok {
			if doc := strings.TrimSpace(d.Doc()); doc != "" {
				b.WriteString(doc)
				b.WriteString("\n\n")
			}
		}
	}
	return b.String()
}

// rule is the Rule implementation of the built-in checks.
type rule struct {
	id, title, doc string
	check          func(in *Input) []Finding
}

func (r rule) ID() string                { return r.id }
func (r rule) Title() string             { return r.title }
func (r rule) Doc() string               { return r.doc }
func (r rule) Check(in *Input) []Finding { return r.check(in) }
