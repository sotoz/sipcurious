package flow

import "slices"

// span is a layout constraint: lane b must be at least need units to the
// right of lane a (a < b).
type span struct{ a, b, need int }

// solveGaps returns the n-1 distances between adjacent lanes. Each gap is at
// least min[k]; spans are then satisfied shortest first by widening every gap
// inside a span equally. Deterministic; cost is O(len(spans) * lanes).
func solveGaps(min []int, spans []span) []int {
	gaps := slices.Clone(min)
	if len(gaps) == 0 {
		return gaps
	}
	// Keep the largest need per lane pair.
	slices.SortFunc(spans, func(x, y span) int {
		if d := (x.b - x.a) - (y.b - y.a); d != 0 {
			return d
		}
		if x.a != y.a {
			return x.a - y.a
		}
		return y.need - x.need
	})
	for _, s := range spans {
		if s.a < 0 || s.b > len(gaps) || s.a >= s.b {
			continue
		}
		sum := 0
		for _, g := range gaps[s.a:s.b] {
			sum += g
		}
		if deficit := s.need - sum; deficit > 0 {
			n := s.b - s.a
			add, extra := deficit/n, deficit%n
			for k := s.a; k < s.b; k++ {
				gaps[k] += add
				if k-s.a < extra {
					gaps[k]++
				}
			}
		}
	}
	return gaps
}
