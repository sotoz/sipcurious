package query

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/trace"
)

// Field is one queryable datum. Register new ones with RegisterField; the
// registry is also the source of Help and of generated documentation.
//
// Exactly one of Message and Call is set. A message field is evaluated on a
// single trace.Message (and existentially over Call.Messages inside
// Query.MatchCall); a call field is evaluated on a *call.Call (inside
// Query.MatchMessage it is evaluated on the call context passed by the caller).
// The getter returns the zero Value (null) when the datum is absent.
type Field struct {
	Name    string   // canonical name: lowercase letters, digits and underscore
	Aliases []string // alternative spellings
	Type    Type
	Doc     string   // one line, with an example value
	Values  []string // TypeEnum: the accepted values (canonical spelling)

	Message func(trace.Message) Value
	Call    func(*call.Call) Value

	// Unexported: built-in message fields are evaluated by id (no copy of the
	// message, no allocation); dynamic header fields carry their header name;
	// classes enables the 4xx shorthand.
	id      fid
	hdr     headerName
	classes bool
}

// Scope reports "message" or "call".
func (f Field) Scope() string {
	if f.Call != nil {
		return "call"
	}
	return "message"
}

var registry = struct {
	mu     sync.RWMutex
	list   []*Field
	byName map[string]*Field // normalised names and aliases
}{byName: make(map[string]*Field)}

// fieldKey normalises a field spelling for lookup: case-insensitive, and '-'
// is the same as '_' (call-id = call_id).
func fieldKey(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "-", "_"))
}

func validFieldName(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func reservedWord(s string) bool {
	switch s {
	case "and", "or", "not", "in", "header", "h":
		return true
	}
	return false
}

// RegisterField adds a field to the language. It is meant to be called from
// init functions. It panics when the field is malformed: no name or an invalid
// name (lowercase letters, digits, underscore), a reserved word (and, or, not,
// in, header, h), a name or alias already taken, an unknown Type, neither or
// both of Message and Call set, or an enum without Type TypeEnum.
func RegisterField(f Field) {
	if err := registerField(f); err != nil {
		panic("query.RegisterField: " + err.Error())
	}
}

func registerField(f Field) error {
	if !validFieldName(f.Name) {
		return fmt.Errorf("invalid field name %q", f.Name)
	}
	if f.Type < TypeString || f.Type > TypeEnum {
		return fmt.Errorf("field %s: invalid type", f.Name)
	}
	if (f.Message == nil) == (f.Call == nil) {
		return fmt.Errorf("field %s: exactly one of Message and Call must be set", f.Name)
	}
	if len(f.Values) > 0 && f.Type != TypeEnum {
		return fmt.Errorf("field %s: Values requires TypeEnum", f.Name)
	}
	names := append([]string{f.Name}, f.Aliases...)
	for _, n := range names {
		if !validFieldName(fieldKey(n)) || reservedWord(fieldKey(n)) {
			return fmt.Errorf("field %s: invalid or reserved name %q", f.Name, n)
		}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	seen := map[string]bool{}
	for _, n := range names {
		k := fieldKey(n)
		if _, dup := registry.byName[k]; dup || seen[k] {
			return fmt.Errorf("field %s: name %q already registered", f.Name, n)
		}
		seen[k] = true
	}
	f.Aliases = append([]string(nil), f.Aliases...)
	f.Values = append([]string(nil), f.Values...)
	p := &f
	registry.list = append(registry.list, p)
	for k := range seen {
		registry.byName[k] = p
	}
	return nil
}

// Fields returns a copy of the registered fields in registration order:
// built-in message fields, built-in call fields, then extensions. The dynamic
// header.<Name> / h.<Name> fields are not part of the registry (see Help).
func Fields() []Field {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	out := make([]Field, len(registry.list))
	for i, f := range registry.list {
		c := *f
		c.Aliases = append([]string(nil), f.Aliases...)
		c.Values = append([]string(nil), f.Values...)
		out[i] = c
	}
	return out
}

// lookupField resolves a word to a registered or dynamic header field.
func lookupField(word string) (*Field, bool) {
	if name, ok := headerFieldName(word); ok {
		return headerField(name, false), true
	}
	registry.mu.RLock()
	f := registry.byName[fieldKey(word)]
	registry.mu.RUnlock()
	return f, f != nil
}

// headerFieldName recognises header.<Name> and h.<Name> (prefix case-insensitive).
func headerFieldName(word string) (string, bool) {
	i := strings.IndexByte(word, '.')
	if i < 0 || i == len(word)-1 {
		return "", false
	}
	if p := word[:i]; strings.EqualFold(p, "header") || strings.EqualFold(p, "h") {
		return word[i+1:], true
	}
	return "", false
}

// headerField builds the dynamic field for one header. A string field returns
// the first value of the header ("" if absent); a presence field (bare
// "header.X") is a bool.
func headerField(name string, presence bool) *Field {
	f := &Field{Name: "header." + name, Type: TypeString, id: fHeader, hdr: newHeaderName(name)}
	f.Doc = "value of the " + name + " header (first occurrence; compact names understood)"
	if presence {
		f.Type, f.id = TypeBool, fHeaderPresent
		f.Doc = "true when the " + name + " header is present and not empty"
	}
	f.Message = func(m trace.Message) Value { return f.msgValue(&m) }
	return f
}

// suggestField returns the registered name closest to word, or "".
func suggestField(word string) string {
	if p, rest, ok := strings.Cut(word, "."); ok && rest != "" {
		for _, want := range []string{"header", "h"} {
			if !strings.EqualFold(p, want) && editDistance(strings.ToLower(p), want) <= 1 && len(p) > 1 {
				return want + "." + rest
			}
		}
	}
	key := fieldKey(word)
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	best, bestD := "", 1<<30
	for k, f := range registry.byName {
		d := editDistance(key, k)
		if d < bestD || d == bestD && f.Name < best {
			best, bestD = f.Name, d
		}
	}
	if bestD <= max(1, min(3, len(key)/3)) && bestD < len(key) {
		return best
	}
	return ""
}

// fieldNames lists canonical field names, sorted.
func fieldNames() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	out := make([]string, len(registry.list))
	for i, f := range registry.list {
		out[i] = f.Name
	}
	sort.Strings(out)
	return out
}

// editDistance is the optimal-string-alignment (restricted Damerau-Levenshtein)
// distance between a and b, in runes.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev2 := make([]int, len(rb)+1)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			v := min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				v = min(v, prev2[j-2]+1)
			}
			cur[j] = v
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(rb)]
}
