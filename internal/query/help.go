package query

import (
	"fmt"
	"strings"
)

const helpLanguage = `FILTER EXPRESSIONS

A filter is a boolean expression over messages and calls:

  from ~ alice and status >= 500
  method in (INVITE, BYE) and src in 10.0.0.0/8
  duration > 30s and not has_media
  "a=sendonly"

Combining
  a and b, a && b       both must hold (binds tighter than or)
  a or b, a || b        either holds
  not a, !a             negation (binds tightest); keywords are case-insensitive
  ( ... )               grouping

Conditions
  field                 a boolean field is true:      has_sdp, is_request
  field OP value        compare:                      status = 486
  field in (v1, v2)     any of the values (or one):   method in (INVITE, BYE)
  field not in (...)    none of them
  word, "some text"     substring search in the raw message, e.g.  INVITE  or  "Call-ID: 12"

Operators
  =  ==     equal (text: whole value, ignoring case; addr: inside the CIDR)
  !=        not equal                     !~        does not contain
  ~         contains (text)               =~        matches the Go (RE2) regexp
  <  <=  >  >=   ordering (int, float, duration, time)
  in        any of a list; ranges as 100..199 for numbers, durations and times

Values
  Bare words need no quotes unless they contain spaces, parentheses, commas or
  operator characters; "double" or 'single' quotes may be used anywhere (\" and \\
  escape inside; other backslashes stay as written, so regexps need no doubling).
  int         486   (status and final_code also take a class: 4xx)
  float       3.5
  duration    250ms  3s  1m30s  (a bare number is seconds)
  time        2024-05-01T10:00:00Z   "2024-05-01 10:00:00" (UTC)   2024-05-01   10:30   10:30:15
              HH:MM[:SS] is a time of day on the day of the message (or call start)
  addr        10.0.0.1  10.0.0.0/8  2001:db8::/32   (= and in use CIDR matching)
  bool        true  false
  null        a datum that is absent (status of a request, pdd of an unanswered call)
              matches no comparison, so != / !~ / not in are true for it

Text matching ignores case unless the case-sensitive option is set.
Header fields: header.Name or h.Name is the first value of any header
(compact forms such as i, f, t, v are understood): h.P-Asserted-Identity ~ 4930
A bare header.Name is true when that header is present.

Scopes
  Message fields are evaluated per message. When selecting calls, a message
  field is true if ANY message of the call matches it; each condition is judged
  on its own ("from ~ alice and status >= 500" = the call has both).
  Call fields (state, duration, mos, ...) describe the whole call; when
  filtering single messages they are read from the call the message belongs to
  (and are false when no call is known).
`

// Help returns the reference of the filter language followed by a table of
// every registered field (name, aliases, type, description with an example).
func Help() string {
	var b strings.Builder
	b.WriteString(helpLanguage)
	fs := Fields()
	for _, scope := range []string{"message", "call"} {
		b.WriteString("\n")
		if scope == "message" {
			b.WriteString("MESSAGE FIELDS\n\n")
		} else {
			b.WriteString("CALL FIELDS\n\n")
		}
		w := 0
		for _, f := range fs {
			if f.Scope() == scope {
				w = max(w, len(fieldHead(f)))
			}
		}
		for _, f := range fs {
			if f.Scope() != scope {
				continue
			}
			fmt.Fprintf(&b, "  %-*s  %-8s  %s\n", w, fieldHead(f), f.Type, f.Doc)
			if len(f.Values) > 0 {
				fmt.Fprintf(&b, "  %-*s  %-8s  values: %s\n", w, "", "", strings.Join(f.Values, ", "))
			}
		}
		if scope == "message" {
			fmt.Fprintf(&b, "  %-*s  %-8s  %s\n", w, "header.<Name>", "string", "first value of any header: header.Subject ~ urgent, h.X-Account = 4711")
		}
	}
	return b.String()
}

func fieldHead(f Field) string {
	if len(f.Aliases) == 0 {
		return f.Name
	}
	return f.Name + " (" + strings.Join(f.Aliases, ", ") + ")"
}
