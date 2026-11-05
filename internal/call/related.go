package call

import (
	"slices"
	"strings"
)

const maxCorrelationKeys = 32 // distinct values remembered per call

// correlate fills Call.Related: the Call-IDs of the other calls that carry the
// same value in any of the named headers. A value is split at ';' and every
// piece contributes its text after an optional "name=" prefix, so the Cisco
// style "Session-ID: <local>;remote=<remote>" links the legs whose local and
// remote IDs cross over, and plain values (X-CID: 1234) match as a whole.
// Comparison is case-insensitive. Related lists follow the order of calls and
// never include the call itself.
func correlate(calls []Call, headers []string) {
	names := make([]string, 0, len(headers))
	for _, h := range headers {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			names = append(names, h)
		}
	}
	if len(names) == 0 {
		return
	}
	byKey := make(map[string][]int32)
	keysOf := make([][]string, len(calls))
	for i := range calls {
		var keys []string
		for j := range calls[i].Messages {
			m := &calls[i].Messages[j]
			for _, h := range names {
				v := rawHeader(m, h)
				for v != "" {
					var piece string
					piece, v, _ = strings.Cut(v, ";")
					if _, after, ok := strings.Cut(piece, "="); ok {
						piece = after
					}
					piece = strings.ToLower(strings.Trim(strings.TrimSpace(piece), `"`))
					if piece == "" || len(keys) >= maxCorrelationKeys || slices.Contains(keys, piece) {
						continue
					}
					keys = append(keys, piece)
				}
			}
		}
		keysOf[i] = keys
		for _, k := range keys {
			byKey[k] = append(byKey[k], int32(i))
		}
	}
	var seen []int32
	for i := range calls {
		seen = seen[:0]
		for _, k := range keysOf[i] {
			for _, j := range byKey[k] {
				if int(j) != i && !slices.Contains(seen, j) {
					seen = append(seen, j)
				}
			}
		}
		if len(seen) == 0 {
			continue
		}
		slices.Sort(seen)
		rel := make([]string, len(seen))
		for n, j := range seen {
			rel[n] = calls[j].CallID
		}
		calls[i].Related = rel
	}
}
