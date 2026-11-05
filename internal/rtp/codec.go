package rtp

// codecEntry is one row of the static payload type table (RFC 3551 table 4/5).
type codecEntry struct {
	name string
	rate int
}

// staticCodecs maps the statically assigned payload types to name and RTP
// clock rate. It is read-only. Audio entries are those of RFC 3551 section 6
// (G722 advertises 8000 for historical reasons although it samples at
// 16 kHz, RFC 3551 4.5.2; L16 is 44100 Hz here for the one- and two-channel
// assignments), video entries section 7.
var staticCodecs = [35]codecEntry{
	0:  {"PCMU", 8000},
	3:  {"GSM", 8000},
	4:  {"G723", 8000},
	5:  {"DVI4", 8000},
	6:  {"DVI4", 16000},
	7:  {"LPC", 8000},
	8:  {"PCMA", 8000},
	9:  {"G722", 8000},
	10: {"L16", 44100},
	11: {"L16", 44100},
	12: {"QCELP", 8000},
	13: {"CN", 8000},
	14: {"MPA", 90000},
	15: {"G728", 8000},
	16: {"DVI4", 11025},
	17: {"DVI4", 22050},
	18: {"G729", 8000},
	25: {"CelB", 90000},
	26: {"JPEG", 90000},
	28: {"nv", 90000},
	31: {"H261", 90000},
	32: {"MPV", 90000},
	33: {"MP2T", 90000},
	34: {"H263", 90000},
}

// payloadTypeCN is the static comfort-noise payload type (RFC 3389).
const payloadTypeCN = 13

// CodecName returns the encoding name and RTP clock rate of a statically
// assigned payload type (RFC 3551). Dynamic payload types (96..127) and
// unassigned ones return ("", 0): their meaning is only known from SDP.
func CodecName(pt uint8) (name string, clockRate int) {
	if int(pt) < len(staticCodecs) {
		e := staticCodecs[pt]
		return e.name, e.rate
	}
	return "", 0
}

// candidateRates are the clock rates jitter is tracked for on every stream:
// the rates real RTP payload formats use (RFC 3551 and the later audio/video
// formats: 12000 and 24000 for some Opus/EVS profiles, 11025 and 22050 for
// DVI4, 44100 for L16, 48000 for Opus, 90000 for video). The rate of a stream is
// only chosen when its results are read, so SDP hints can arrive late.
var candidateRates = [...]int{8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 90000}

// nRates is len(candidateRates).
const nRates = len(candidateRates)

// invRate holds 1/rate (seconds per timestamp tick) for candidateRates.
var invRate = func() (t [nRates]float64) {
	for i, r := range candidateRates {
		t[i] = 1 / float64(r)
	}
	return t
}()

// rateIndex returns the index of rate in candidateRates, or -1.
func rateIndex(rate int) int {
	for i, r := range candidateRates {
		if r == rate {
			return i
		}
	}
	return -1
}

// staticRateIdx maps a payload type to the candidate index of its static
// clock rate, or -1 for dynamic and unassigned payload types (unknown rate).
var staticRateIdx = func() (t [128]int8) {
	for i := range t {
		t[i] = -1
	}
	for pt, e := range staticCodecs {
		if e.rate != 0 {
			t[pt] = int8(rateIndex(e.rate))
		}
	}
	return t
}()
