package rtp

import (
	"strings"
	"time"
)

// E-model assumptions (all documented here because the result is an estimate).
//
//   - Ro - Is = 93.2: the G.107 default for everything but the codec, delay
//     and loss terms (no noise, no echo, no advantage factor).
//   - One-way delay d = baseDelay + 2 x jitter. baseDelay stands for
//     packetisation, algorithmic delay and the minimum playout buffer. Network
//     propagation delay cannot be seen from one capture point and is NOT
//     included. 2 x jitter models an adaptive playout buffer sized to twice the
//     RFC 3550 interarrival jitter so that late packets are rare; late loss
//     is therefore not added to the network loss.
//   - Id uses the Cole/Rosenbluth piecewise-linear approximation of the G.107
//     delay curve: 0.024 d + 0.11 (d - 177.3) H(d - 177.3), d in ms.
//   - Loss is random (BurstR = 1); bursty loss is rated better than it feels.
const (
	eModelRo     = 93.2
	baseDelayMs  = 40.0
	jitterBufMul = 2.0
	burstR       = 1.0
)

// impairment returns the equipment impairment factor Ie and the packet-loss
// robustness factor Bpl of a codec (ITU-T G.113 appendix I where a value
// exists there; the others are approximations marked below). Codec names are
// compared case-insensitively; a "/clock" suffix is ignored. Unknown or empty
// names, and codecs that are not impaired like G.711, are rated as G.711 with
// packet loss concealment: Ie 0, Bpl 25.1.
func impairment(codec string) (ie, bpl float64) {
	name := strings.ToUpper(codec)
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name = name[:i]
	}
	switch name {
	case "G729", "G729A", "G729B", "G729AB", "G.729", "G.729A":
		return 11, 19.0 // G.113: G.729A + VAD
	case "GSM", "GSM-FR":
		return 20, 10.0 // G.113: GSM-FR
	case "G723", "G7231", "G723.1", "G.723.1":
		return 15, 16.1 // G.113: G.723.1 6.3 kbit/s
	case "G726", "G726-32", "G.726", "G728", "G.728":
		return 7, 25.1 // G.113: ADPCM 32 kbit/s and LD-CELP 16 kbit/s Ie; Bpl assumed G.711-like
	case "ILBC":
		return 11, 32.0 // approximation (iLBC 30 ms frames, 13.3 kbit/s)
	case "OPUS":
		return 8, 20.0 // approximation: wideband speech at 24-32 kbit/s, PLC on, FEC off
	case "SPEEX":
		return 10, 20.0 // approximation
	case "AMR", "AMR-WB", "AMR-NB":
		return 8, 20.0 // approximation (12.2 kbit/s AMR-NB .. 12.65 kbit/s AMR-WB)
	default:
		// PCMU, PCMA, G722 (no narrow-band Ie is defined; wideband is rated as
		// G.711), L16, CN, unknown dynamic payload types.
		return 0, 25.1 // G.113: G.711 with PLC (G.722 approximated by the same)
	}
}

// Quality returns an estimate of the R factor (0-100) and the listening
// quality MOS (1.0-4.5) of one stream from the packet loss percentage and the
// mean RFC 3550 interarrival jitter, using a simplified ITU-T G.107 E-model:
//
//	R   = 93.2 - Id - Ie_eff
//	MOS = 1 + 0.035 R + 7e-6 R (R-60)(100-R)      (0 < R < 100; 1 for R <= 0, 4.5 for R >= 100; result clamped to 1..4.5)
//
// Ie_eff = Ie + (95-Ie) Ppl / (Ppl + Bpl) with Ie and Bpl from the codec
// (see impairment). Id is derived from the assumed playout delay (see the
// constants above).
//
// This is an estimate from network-level observations of one capture point:
// it knows nothing about real delay, echo, speech level, the receiver's actual
// jitter buffer or the codec's real bitrate. Use it to rank and compare
// streams, not as a measured MOS.
func Quality(codec string, lossPct float64, jitter time.Duration) (rFactor, mos float64) {
	ie, bpl := impairment(codec)
	ppl := min(max(lossPct, 0), 100)
	if lossPct != lossPct { // NaN
		ppl = 0
	}
	ieEff := ie + (95-ie)*ppl/(ppl/burstR+bpl)

	d := baseDelayMs + jitterBufMul*max(float64(jitter), 0)/float64(time.Millisecond)
	id := 0.024 * d
	if d > 177.3 {
		id += 0.11 * (d - 177.3)
	}

	r := min(max(eModelRo-id-ieEff, 0), 100)
	return r, rToMOS(r)
}

// rToMOS converts an R factor to MOS (ITU-T G.107 annex B), clamped to 1.0..4.5.
func rToMOS(r float64) float64 {
	switch {
	case r <= 0:
		return 1
	case r >= 100:
		return 4.5
	}
	// The cubic dips marginally below 1 for R below about 6.5: clamp.
	return min(max(1+0.035*r+r*(r-60)*(100-r)*7e-6, 1), 4.5)
}
