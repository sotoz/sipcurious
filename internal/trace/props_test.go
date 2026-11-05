package trace

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
)

// TestInfo checks Info against its definition on random messages.
func TestInfo(t *testing.T) {
	r := rand.New(rand.NewPCG(31, 32))
	reasons := []string{"", "OK", "Busy Here", "日本語", "a\nb", " "}
	methods := []string{"", "INVITE", "bye", "\xff"}
	for range 2000 {
		m := Message{
			IsRequest:  r.IntN(2) == 0,
			Method:     methods[r.IntN(len(methods))],
			StatusCode: r.IntN(1200) - 100,
			Reason:     reasons[r.IntN(len(reasons))],
		}
		want := m.Method
		if !m.IsRequest {
			want = fmt.Sprint(m.StatusCode)
			if m.Reason != "" {
				want += " " + m.Reason
			}
		}
		if got := m.Info(); got != want {
			t.Fatalf("Info(%+v) = %q, want %q", m, got, want)
		}
	}
}

func TestAddrs(t *testing.T) {
	m := Message{
		Src: netip.MustParseAddr("2001:db8::1"), SrcPort: 5060,
		Dst: netip.MustParseAddr("10.0.0.1"), DstPort: 65535,
	}
	if got := m.SrcAddr().String(); got != "[2001:db8::1]:5060" {
		t.Errorf("SrcAddr = %q", got)
	}
	if got := m.DstAddr().String(); got != "10.0.0.1:65535" {
		t.Errorf("DstAddr = %q", got)
	}
	var zero Message
	if zero.SrcAddr().IsValid() || zero.DstAddr().IsValid() {
		t.Errorf("zero message must have invalid endpoints")
	}
	if a, b := zero.SrcAddr(), (Message{SrcPort: 1}).SrcAddr(); a == b {
		t.Errorf("ports must be part of the endpoint identity")
	}
}

func FuzzInfo(f *testing.F) {
	f.Add(true, "INVITE", 0, "")
	f.Add(false, "INVITE", 486, "Busy Here")
	f.Add(false, "", -5, "\x00\xff")
	f.Fuzz(func(t *testing.T, req bool, method string, code int, reason string) {
		m := Message{IsRequest: req, Method: method, StatusCode: code, Reason: reason}
		got := m.Info()
		if req && got != method {
			t.Fatalf("request Info = %q, want %q", got, method)
		}
		if !req && got != fmt.Sprint(code) && got != fmt.Sprint(code)+" "+reason {
			t.Fatalf("response Info = %q", got)
		}
	})
}
