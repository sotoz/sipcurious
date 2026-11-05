package analysis

import "time"

// Default thresholds, see DefaultConfig.
const (
	DefaultSlowPDD        = 3 * time.Second
	DefaultSlowSetup      = 10 * time.Second
	DefaultMinRetransmits = 2
	DefaultMinMOS         = 3.6
	DefaultMaxLossPct     = 1.0
	DefaultMaxJitter      = 30 * time.Millisecond
	DefaultMaxMediaGap    = time.Second
)

// DefaultConfig returns the documented default thresholds: PDD 3s, setup
// 10s, 2 retransmissions, MOS 3.6, loss 1%, jitter 30ms, media gap 1s and
// long-call reporting off.
func DefaultConfig() Config {
	return Config{
		SlowPDD:        DefaultSlowPDD,
		SlowSetup:      DefaultSlowSetup,
		MinRetransmits: DefaultMinRetransmits,
		MinMOS:         DefaultMinMOS,
		MaxLossPct:     DefaultMaxLossPct,
		MaxJitter:      DefaultMaxJitter,
		MaxMediaGap:    DefaultMaxMediaGap,
	}
}

// WithDefaults returns c with every zero (or negative) threshold replaced by
// its default. LongCall has no default: zero keeps it off.
func (c Config) WithDefaults() Config {
	d := DefaultConfig()
	if c.SlowPDD <= 0 {
		c.SlowPDD = d.SlowPDD
	}
	if c.SlowSetup <= 0 {
		c.SlowSetup = d.SlowSetup
	}
	if c.MinRetransmits <= 0 {
		c.MinRetransmits = d.MinRetransmits
	}
	if c.MinMOS <= 0 {
		c.MinMOS = d.MinMOS
	}
	if c.MaxLossPct <= 0 {
		c.MaxLossPct = d.MaxLossPct
	}
	if c.MaxJitter <= 0 {
		c.MaxJitter = d.MaxJitter
	}
	if c.MaxMediaGap <= 0 {
		c.MaxMediaGap = d.MaxMediaGap
	}
	if c.LongCall < 0 {
		c.LongCall = 0
	}
	return c
}
