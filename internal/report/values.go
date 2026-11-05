package report

import (
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"
)

// tableTimeLayout is the timestamp layout of the human formats.
const tableTimeLayout = "2006-01-02T15:04:05.000Z07:00"

// vkind is the normalised type of a cell value.
type vkind uint8

const (
	vNil vkind = iota
	vStr
	vInt
	vUint
	vFloat
	vDur
	vTime
	vBool
)

// value is a cell after type normalisation.
type value struct {
	k    vkind
	bits uint8 // float width: 32 or 64
	s    string
	n    int64 // vInt, vDur (ns), vUint (reinterpreted), vBool (0/1)
	f    float64
	t    time.Time
}

func strValue(s string) value { return value{k: vStr, s: s} }

// normalize maps a cell to its canonical form. Missing values (see Table)
// become vNil.
func normalize(v any) value {
	switch x := v.(type) {
	case nil:
		return value{}
	case string:
		return value{k: vStr, s: x}
	case int:
		return value{k: vInt, n: int64(x)}
	case int64:
		return value{k: vInt, n: x}
	case float64:
		return floatValue(x, 64)
	case time.Duration:
		return value{k: vDur, n: int64(x)}
	case time.Time:
		if x.IsZero() {
			return value{}
		}
		return value{k: vTime, t: x}
	case bool:
		if x {
			return value{k: vBool, n: 1}
		}
		return value{k: vBool}
	case int32:
		return value{k: vInt, n: int64(x)}
	case int16:
		return value{k: vInt, n: int64(x)}
	case int8:
		return value{k: vInt, n: int64(x)}
	case uint:
		return value{k: vUint, n: int64(uint64(x))}
	case uint64:
		return value{k: vUint, n: int64(x)}
	case uint32:
		return value{k: vUint, n: int64(x)}
	case uint16:
		return value{k: vUint, n: int64(x)}
	case uint8:
		return value{k: vUint, n: int64(x)}
	case float32:
		return floatValue(float64(x), 32)
	case []byte:
		return value{k: vStr, s: string(x)}
	case netip.Addr:
		if !x.IsValid() {
			return value{}
		}
		return value{k: vStr, s: x.String()}
	case netip.AddrPort:
		if !x.IsValid() {
			return value{}
		}
		return value{k: vStr, s: x.String()}
	}
	return normalizeSlow(v)
}

func floatValue(f float64, bits uint8) value {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return value{}
	}
	return value{k: vFloat, f: f, bits: bits}
}

// normalizeSlow handles named types, errors, Stringers and anything else.
func normalizeSlow(v any) value {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		if rv.IsNil() {
			return value{}
		}
	}
	switch x := v.(type) {
	case error:
		return value{k: vStr, s: x.Error()}
	case fmt.Stringer:
		return value{k: vStr, s: x.String()}
	}
	switch rv.Kind() {
	case reflect.String:
		return value{k: vStr, s: rv.String()}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if rv.Type() == reflect.TypeFor[time.Duration]() {
			return value{k: vDur, n: rv.Int()}
		}
		return value{k: vInt, n: rv.Int()}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value{k: vUint, n: int64(rv.Uint())}
	case reflect.Float32:
		return floatValue(rv.Float(), 32)
	case reflect.Float64:
		return floatValue(rv.Float(), 64)
	case reflect.Bool:
		if rv.Bool() {
			return value{k: vBool, n: 1}
		}
		return value{k: vBool}
	}
	return value{k: vStr, s: fmt.Sprint(v)}
}

// appendHuman appends the human readable form of v, sanitised for mode m.
// Only strings can contain anything unsafe; every other kind renders to
// characters that are inert in all modes.
func appendHuman(dst []byte, v value, o Options, m mode) []byte {
	switch v.k {
	case vStr:
		return appendSanitized(dst, v.s, m)
	case vInt:
		return strconv.AppendInt(dst, v.n, 10)
	case vUint:
		return strconv.AppendUint(dst, uint64(v.n), 10)
	case vFloat:
		return appendFloatHuman(dst, v.f)
	case vDur:
		return appendDuration(dst, time.Duration(v.n))
	case vTime:
		return o.zone(v.t).AppendFormat(dst, tableTimeLayout)
	case vBool:
		return strconv.AppendBool(dst, v.n != 0)
	}
	return dst
}

// appendFloatHuman appends f rounded to at most three decimals, trailing
// zeros removed.
func appendFloatHuman(dst []byte, f float64) []byte {
	start := len(dst)
	dst = strconv.AppendFloat(dst, f, 'f', 3, 64)
	end := len(dst)
	for end > start && dst[end-1] == '0' {
		end--
	}
	if end > start && dst[end-1] == '.' {
		end--
	}
	dst = dst[:end]
	if string(dst[start:]) == "-0" {
		dst = append(dst[:start], '0')
	}
	return dst
}

// appendMachine appends the typed machine form of a non-string, non-nil v:
// numbers as plain decimals, durations as milliseconds, times as RFC3339Nano
// in the zone selected by o, booleans as true/false. It is the form shared by
// CSV and JSON.
func appendMachine(dst []byte, v value, o Options) []byte {
	switch v.k {
	case vInt:
		return strconv.AppendInt(dst, v.n, 10)
	case vUint:
		return strconv.AppendUint(dst, uint64(v.n), 10)
	case vFloat:
		return appendFloat(dst, v.f, int(v.bits))
	case vDur:
		return appendMillis(dst, time.Duration(v.n))
	case vTime:
		return o.zone(v.t).AppendFormat(dst, time.RFC3339Nano)
	case vBool:
		return strconv.AppendBool(dst, v.n != 0)
	}
	return dst
}

// appendMillis appends d as an exact decimal number of milliseconds.
func appendMillis(dst []byte, d time.Duration) []byte {
	u := uint64(d)
	if d < 0 {
		dst = append(dst, '-')
		u = -u
	}
	dst = strconv.AppendUint(dst, u/1e6, 10)
	frac := u % 1e6
	if frac == 0 {
		return dst
	}
	var b [7]byte
	b[0] = '.'
	for i := 6; i >= 1; i-- {
		b[i] = byte('0' + frac%10)
		frac /= 10
	}
	n := 7
	for b[n-1] == '0' {
		n--
	}
	return append(dst, b[:n]...)
}

// FormatDuration renders d for people: the unit adapts to the magnitude and
// the value is rounded to a sensible resolution.
//
//	0s  250ns  1.5µs  12.345ms  250ms  1.5s  59.999s  1m30s  1m30.5s  1m05s  2h03m
//
// Below one second the result has at most three decimals of the unit; from
// one second to one minute millisecond resolution; from one minute to one
// hour 100 ms resolution; from one hour on whole minutes ("25h00m", never days).
// Negative durations get a leading "-".
func FormatDuration(d time.Duration) string {
	return string(appendDuration(make([]byte, 0, 16), d))
}

func appendDuration(dst []byte, d time.Duration) []byte {
	if d == 0 {
		return append(dst, '0', 's')
	}
	u := uint64(d)
	if d < 0 {
		dst = append(dst, '-')
		u = -u
	}
	// Round at the resolution of the tier. Rounding can promote to the next
	// tier (999.9996ms -> 1s), whose resolution is coarser, so repeat until
	// stable.
	for {
		res := resolution(u)
		r := roundUint(u, res)
		if resolution(r) == res {
			u = r
			break
		}
		u = r
	}
	switch {
	case u < uint64(time.Microsecond):
		dst = strconv.AppendUint(dst, u, 10)
		return append(dst, 'n', 's')
	case u < uint64(time.Millisecond):
		dst = appendScaled(dst, u, 1e3)
		return append(dst, "µs"...)
	case u < uint64(time.Second):
		dst = appendScaled(dst, u, 1e6)
		return append(dst, 'm', 's')
	case u < uint64(time.Minute):
		dst = appendScaled(dst, u, 1e9)
		return append(dst, 's')
	case u < uint64(time.Hour):
		m := u / uint64(time.Minute)
		s := u % uint64(time.Minute)
		dst = strconv.AppendUint(dst, m, 10)
		dst = append(dst, 'm')
		if s/1e9 < 10 {
			dst = append(dst, '0')
		}
		dst = appendScaled(dst, s, 1e9)
		return append(dst, 's')
	}
	h := u / uint64(time.Hour)
	m := u % uint64(time.Hour) / uint64(time.Minute)
	dst = strconv.AppendUint(dst, h, 10)
	dst = append(dst, 'h')
	if m < 10 {
		dst = append(dst, '0')
	}
	dst = strconv.AppendUint(dst, m, 10)
	return append(dst, 'm')
}

// resolution is the rounding unit, in ns, for a magnitude.
func resolution(u uint64) uint64 {
	switch {
	case u >= uint64(time.Hour):
		return uint64(time.Minute)
	case u >= uint64(time.Minute):
		return uint64(100 * time.Millisecond)
	case u >= uint64(time.Second):
		return uint64(time.Millisecond)
	case u >= uint64(time.Millisecond):
		return uint64(time.Microsecond)
	}
	return 1
}

// roundUint rounds u to the nearest multiple of res, saturating instead of
// overflowing.
func roundUint(u, res uint64) uint64 {
	if res == 1 {
		return u
	}
	half := res / 2
	if u > math.MaxUint64-half {
		return u
	}
	return (u + half) / res * res
}

// appendScaled appends u/unit as a decimal with trailing zeros removed.
func appendScaled(dst []byte, u, unit uint64) []byte {
	dst = strconv.AppendUint(dst, u/unit, 10)
	frac := u % unit
	if frac == 0 {
		return dst
	}
	digits := 0
	for x := unit; x > 1; x /= 10 {
		digits++
	}
	var b [10]byte
	b[0] = '.'
	for i := digits; i >= 1; i-- {
		b[i] = byte('0' + frac%10)
		frac /= 10
	}
	n := digits + 1
	for b[n-1] == '0' {
		n--
	}
	return append(dst, b[:n]...)
}

// FormatTime renders t as RFC 3339 with millisecond precision, in UTC if utc
// is set and in the local zone otherwise (the format of table timestamps).
// The zero time renders as "".
func FormatTime(t time.Time, utc bool) string {
	if t.IsZero() {
		return ""
	}
	if utc {
		t = t.UTC()
	} else {
		t = t.Local()
	}
	return t.Format(tableTimeLayout)
}

// Truncate shortens s to at most n runes. If it is cut, the last rune is an
// ellipsis "…", so the result still has n runes. It never splits a UTF-8
// sequence; invalid bytes count as one rune each and are kept as they are.
// n <= 0 gives "".
func Truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n { // at most n runes: every rune takes at least one byte
		return s
	}
	count, cut := 0, 0
	for i := 0; i < len(s); {
		if count == n-1 {
			cut = i
		}
		_, w := utf8.DecodeRuneInString(s[i:])
		i += w
		count++
		if count > n {
			return s[:cut] + "…"
		}
	}
	return s
}

// StatusStyle maps a SIP response code to a style: 1xx Dim, 2xx Good, 4xx and
// 5xx/6xx Warn and Bad respectively; 3xx, the routine authentication
// challenges 401 and 407, 487 (Request Terminated, the normal answer to a
// CANCEL) and anything outside 100-699 get None.
func StatusStyle(code int) Style {
	switch {
	case code == 401, code == 407, code == 487:
		return None
	case code >= 100 && code < 200:
		return Dim
	case code >= 200 && code < 300:
		return Good
	case code >= 400 && code < 500:
		return Warn
	case code >= 500 && code < 700:
		return Bad
	}
	return None
}

// SeverityStyle maps a finding severity name ("info", "warning", "error",
// case-insensitive; "warn" and "err" are accepted) to a style: Dim, Warn and
// Bad. Unknown names give None.
func SeverityStyle(name string) Style {
	switch lower(name) {
	case "info":
		return Dim
	case "warning", "warn":
		return Warn
	case "error", "err":
		return Bad
	}
	return None
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// ShouldColor reports whether w is a place where ANSI colors are welcome: the
// NO_COLOR environment variable (any non-empty value, see no-color.org) and
// TERM=dumb turn colors off, otherwise w must be an *os.File that is a
// terminal (a character device other than the null device). It is what a CLI
// uses for "--color auto".
func ShouldColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok || f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(fi, null) {
		return false
	}
	return true
}
