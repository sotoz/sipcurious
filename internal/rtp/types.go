// Package rtp detects RTP/RTCP flows in a capture and computes per-stream
// quality metrics (loss, jitter, gaps, E-model MOS estimate).
package rtp

import (
	"net/netip"
	"time"
)

// Key identifies one RTP stream: a unidirectional flow with one SSRC.
type Key struct {
	Src, Dst netip.AddrPort
	SSRC     uint32
}

// Stream is the summary of one RTP stream.
type Stream struct {
	Key
	File       string // capture file the stream was seen in
	FirstIndex int    // 1-based packet number of the first packet in File

	Start, End time.Time // first and last packet time

	PayloadType uint8  // most frequent payload type (telephone-event packets excluded)
	Codec       string // "PCMU", "PCMA", "G722", "G729", "opus", ... ("" if unknown dynamic PT)
	ClockRate   int    // Hz used for jitter computation

	Packets    uint64 // RTP packets seen
	Bytes      uint64 // payload bytes (headers excluded)
	Expected   uint64 // packets expected from the sequence number range
	Lost       int64  // Expected - Packets (can be negative when duplicates arrive)
	Duplicates uint64
	Reordered  uint64
	LossPct    float64 // 100 * max(Lost,0) / Expected

	JitterMean time.Duration // mean RFC 3550 interarrival jitter
	JitterMax  time.Duration // maximum of the running jitter estimate
	MaxGap     time.Duration // largest gap between consecutive packets

	DTMFEvents int // RFC 4733 telephone-event: number of distinct events

	RFactor float64 // E-model R factor (0-100), 0 if not computed
	MOS     float64 // E-model estimated MOS-LQ (1.0-4.5), 0 if not computed

	RTCP RTCPSummary

	CallID string // filled when the stream is correlated to a call (call.Attach)
	Leg    string // "caller->callee" / "callee->caller" once correlated, else ""
}

// Duration is End - Start.
func (s Stream) Duration() time.Duration { return s.End.Sub(s.Start) }

// RTCPSummary aggregates the RTCP sender/receiver reports seen for a stream's SSRC.
type RTCPSummary struct {
	Reports         int
	MaxFractionLost float64       // percent, highest value reported
	MaxJitter       time.Duration // highest jitter reported
	PacketsLost     int64         // last cumulative packets lost reported
}
