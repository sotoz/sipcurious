package rtp

import (
	"math"
	"testing"
	"time"
)

func TestQuality(t *testing.T) {
	// Analytic expectations (see the formulas in Quality):
	//   d = 40 ms + 2 x jitter, Id = 0.024 d (+0.11 (d-177.3) beyond 177.3 ms),
	//   Ie_eff = Ie + (95-Ie) Ppl/(Ppl+Bpl), R = 93.2 - Id - Ie_eff.
	tests := []struct {
		name   string
		codec  string
		loss   float64
		jitter time.Duration
		r      float64
	}{
		{"G.711 clean", "PCMU", 0, 0, 93.2 - 0.024*40},
		{"PCMA is G.711", "PCMA", 0, 0, 93.2 - 0.024*40},
		{"unknown codec is G.711", "", 0, 0, 93.2 - 0.024*40},
		{"G.711 10% loss", "PCMU", 10, 0, 93.2 - 0.024*40 - 95*10/(10+25.1)},
		{"G.711 jitter 20ms", "PCMU", 0, 20 * time.Millisecond, 93.2 - 0.024*80},
		{"G.711 long delay", "PCMU", 0, 100 * time.Millisecond, 93.2 - 0.024*240 - 0.11*(240-177.3)},
		{"G.729 clean", "G729", 0, 0, 93.2 - 0.024*40 - 11},
		{"G.729 5% loss", "g729", 5, 0, 93.2 - 0.024*40 - (11 + 84*5/(5+19.0))},
		{"GSM clean", "GSM", 0, 0, 93.2 - 0.024*40 - 20},
		{"G.723.1 clean", "G723", 0, 0, 93.2 - 0.024*40 - 15},
		{"codec with clock suffix", "G729/8000", 0, 0, 93.2 - 0.024*40 - 11},
		{"total loss", "PCMU", 100, 0, 93.2 - 0.024*40 - 95*100/(100+25.1)},
	}
	for _, tc := range tests {
		r, mos := Quality(tc.codec, tc.loss, tc.jitter)
		if math.Abs(r-tc.r) > 1e-9 {
			t.Errorf("%s: R = %.6f, want %.6f", tc.name, r, tc.r)
		}
		want := 1 + 0.035*tc.r + tc.r*(tc.r-60)*(100-tc.r)*7e-6
		if math.Abs(mos-want) > 1e-9 {
			t.Errorf("%s: MOS = %.6f, want %.6f", tc.name, mos, want)
		}
	}
}

func TestQualityBounds(t *testing.T) {
	r, mos := Quality("PCMU", 0, 0)
	if mos < 4.3 || mos > 4.5 {
		t.Errorf("clean G.711 MOS = %.3f (R=%.1f), want ~4.4", mos, r)
	}
	// Extreme inputs clamp: R in 0..100, MOS in 1..4.5.
	for _, c := range []struct {
		codec string
		loss  float64
		jit   time.Duration
	}{
		{"PCMU", 100, time.Hour}, {"GSM", 100, 0}, {"PCMU", -5, -time.Second}, {"PCMU", 1e9, 0}, {"G729", math.NaN(), 0},
	} {
		r, mos := Quality(c.codec, c.loss, c.jit)
		if math.IsNaN(r) || math.IsNaN(mos) || r < 0 || r > 100 || mos < 1 || mos > 4.5 {
			t.Errorf("Quality(%q, %v, %v) = %v, %v out of range", c.codec, c.loss, c.jit, r, mos)
		}
	}
	if _, mos := Quality("PCMU", 100, time.Hour); mos != 1 {
		t.Errorf("worst case MOS = %v, want 1", mos)
	}
	// Monotonic: more loss or jitter is never better; G.729 is never better than G.711 at equal loss.
	prev := 5.0
	for loss := 0.0; loss <= 50; loss++ {
		_, m := Quality("PCMU", loss, 0)
		if m > prev {
			t.Fatalf("MOS rises with loss at %v%%", loss)
		}
		prev = m
	}
	prev = 5
	for j := time.Duration(0); j < time.Second; j += 10 * time.Millisecond {
		_, m := Quality("PCMU", 0, j)
		if m > prev {
			t.Fatalf("MOS rises with jitter at %v", j)
		}
		prev = m
	}
	_, g711 := Quality("PCMU", 2, 0)
	_, g729 := Quality("G729", 2, 0)
	if g729 >= g711 {
		t.Errorf("G.729 MOS %.2f should be below G.711 %.2f", g729, g711)
	}
}
