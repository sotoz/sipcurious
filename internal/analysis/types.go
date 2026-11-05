// Package analysis runs pluggable diagnostic rules over calls, messages and
// RTP streams and reports findings a VoIP engineer can act on.
package analysis

import (
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// Severity ranks a finding.
type Severity int

const (
	Info Severity = iota
	Warning
	Error
)

func (s Severity) String() string {
	switch s {
	case Warning:
		return "warning"
	case Error:
		return "error"
	}
	return "info"
}

// Finding is one diagnosed problem or notable observation.
type Finding struct {
	Rule     string // rule ID, e.g. "sip-retransmissions"
	Severity Severity
	CallID   string    // "" for capture-wide findings
	Time     time.Time // when it happened (zero if not applicable)
	Title    string    // one line, e.g. "INVITE retransmitted 6 times without response"
	Detail   string    // explanation with the evidence (addresses, codes, numbers)
	Hint     string    // what to check next
	Packets  []Ref     // the packets that prove it
}

// Ref points at a packet in a capture file.
type Ref struct {
	File  string
	Index int
}

// Input is everything a rule may look at.
type Input struct {
	Messages []trace.Message // all SIP messages, chronological
	Calls    []call.Call     // built with RTP already attached
	Streams  []rtp.Stream    // all RTP streams, including uncorrelated ones
	Config   Config
}

// Config holds the thresholds rules use. Zero values mean "use the default"
// (see DefaultConfig).
type Config struct {
	SlowPDD        time.Duration // PDD above this is reported (default 3s)
	SlowSetup      time.Duration // INVITE->200 above this (default 10s)
	MinRetransmits int           // report a request retransmitted at least this often (default 2)
	MinMOS         float64       // RTP stream MOS below this (default 3.6)
	MaxLossPct     float64       // RTP loss above this percent (default 1.0)
	MaxJitter      time.Duration // RTP jitter above this (default 30ms)
	MaxMediaGap    time.Duration // gap inside a stream above this (default 1s)
	LongCall       time.Duration // informational (default 0 = off)
}

// Rule is one diagnostic check. Rules are registered with Register (usually
// from an init function) and selected by ID on the command line.
type Rule interface {
	ID() string    // stable kebab-case identifier
	Title() string // one line description for `rules` listing
	Check(in *Input) []Finding
}
