package pcaptest

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// SampleStart is the capture start time of every demo sample.
var SampleStart = time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

// Sample is one demo capture under testdata/samples. Build is deterministic.
type Sample struct {
	// File is the file name, ".pcapng" selects pcapng.
	File string
	// Build constructs the capture.
	Build func() *Builder
}

// Samples returns the demo captures in a stable order. Facts about each one
// are documented in testdata/samples/README.md.
func Samples() []Sample {
	return []Sample{
		{"basic-call.pcap", sampleBasicCall},
		{"busy-and-reject.pcap", sampleBusyAndReject},
		{"cancelled-call.pcap", sampleCancelled},
		{"no-answer-retransmits.pcap", sampleNoAnswer},
		{"auth-register.pcap", sampleAuthRegister},
		{"bad-media.pcap", sampleBadMedia},
		{"missing-ack.pcap", sampleMissingACK},
		{"nat-problem.pcap", sampleNAT},
		{"b2bua-two-legs.pcap", sampleB2BUA},
		{"hold-resume.pcap", sampleHold},
		{"tcp-sip.pcap", sampleTCP},
		{"ipv6-vlan.pcap", sampleIPv6VLAN},
		{"features-sll-nanos.pcap", sampleFeatures},
		{"mixed-busy-hour.pcapng", func() *Builder { b, _ := MixedBusyHour(); return b }},
	}
}

// WriteSamples writes every sample into dir.
func WriteSamples(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("pcaptest: %w", err)
	}
	for _, s := range Samples() {
		if err := s.Build().WriteFile(filepath.Join(dir, s.File)); err != nil {
			return err
		}
	}
	return nil
}

func at(s int) time.Time { return SampleStart.Add(time.Duration(s) * time.Second) }

func sampleBasicCall() *Builder {
	b := New(SampleStart, 1001)
	b.Call(CallOptions{From: "alice", To: "bob", TalkTime: 5 * time.Second, RingTime: 2 * time.Second,
		Caller: netip.MustParseAddrPort("10.0.1.10:5060"), Callee: netip.MustParseAddrPort("10.0.2.20:5060"),
		CallerRTP: RTPOptions{SSRC: 0x1a2b3c01, Port: 16384}, CalleeRTP: RTPOptions{SSRC: 0x1a2b3c02, Port: 18000}})
	return b
}

func sampleBusyAndReject() *Builder {
	b := New(SampleStart, 1002)
	b.Call(CallOptions{Start: at(0), From: "alice", To: "bob", Outcome: Busy})
	b.Call(CallOptions{Start: at(5), From: "carol", To: "dave", Outcome: Rejected, RejectCode: 603, RingTime: time.Second})
	b.Call(CallOptions{Start: at(10), From: "erin", To: "nobody", Outcome: Rejected, RejectCode: 404})
	return b
}

func sampleCancelled() *Builder {
	b := New(SampleStart, 1003)
	b.Call(CallOptions{From: "alice", To: "bob", Outcome: Cancelled, RingTime: 4 * time.Second, Reason: "SIP;cause=200;text=\"Call completed elsewhere\""})
	return b
}

func sampleNoAnswer() *Builder {
	b := New(SampleStart, 1004)
	b.Call(CallOptions{Start: at(0), From: "alice", To: "bob", Outcome: Unreachable,
		Callee: netip.MustParseAddrPort("10.0.2.99:5060")})
	b.Call(CallOptions{Start: at(2), From: "carol", To: "dave", Outcome: Unreachable, Topology: Proxy,
		Callee: netip.MustParseAddrPort("10.0.2.98:5060")})
	return b
}

func sampleAuthRegister() *Builder {
	b := New(SampleStart, 1005)
	b.Register(RegisterOptions{Start: at(0), User: "alice"})
	b.Register(RegisterOptions{Start: at(2), User: "carol", Attempts: 5, FailCode: 403, Interval: 2 * time.Second,
		Client: netip.MustParseAddrPort("10.0.1.30:5060")})
	return b
}

func sampleBadMedia() *Builder {
	b := New(SampleStart, 1006)
	b.Call(CallOptions{Start: at(0), From: "alice", To: "bob", TalkTime: 6 * time.Second,
		CallerRTP: RTPOptions{SSRC: 0xbad00001},
		CalleeRTP: RTPOptions{SSRC: 0xbad00002, LossPct: 8, JitterMs: 60, Gap: Gap{At: 2 * time.Second, For: 2 * time.Second}}})
	b.Call(CallOptions{Start: at(10), From: "carol", To: "dave", TalkTime: 6 * time.Second,
		Callee:    netip.MustParseAddrPort("10.0.2.21:5060"),
		CallerRTP: RTPOptions{SSRC: 0xbad00003},
		CalleeRTP: RTPOptions{Silent: true}})
	b.Call(CallOptions{Start: at(20), From: "erin", To: "frank", TalkTime: 6 * time.Second,
		Callee:    netip.MustParseAddrPort("10.0.2.22:5060"),
		CallerRTP: RTPOptions{Silent: true}, CalleeRTP: RTPOptions{Silent: true}})
	return b
}

func sampleMissingACK() *Builder {
	b := New(SampleStart, 1007)
	b.Call(CallOptions{From: "alice", To: "bob", MissingACK: true})
	return b
}

func sampleNAT() *Builder {
	b := New(SampleStart, 1008)
	b.Call(CallOptions{From: "alice", To: "bob", NATed: true, TalkTime: 4 * time.Second, Topology: Proxy,
		CallerRTP: RTPOptions{SSRC: 0x4a700001}, CalleeRTP: RTPOptions{SSRC: 0x4a700002}})
	return b
}

func sampleB2BUA() *Builder {
	b := New(SampleStart, 1009)
	b.Call(CallOptions{From: "alice", To: "bob", Topology: B2BUA, XCID: "SBC-7f3a91c2", TalkTime: 4 * time.Second,
		CallerRTP: RTPOptions{SSRC: 0xb2b00001}, CalleeRTP: RTPOptions{SSRC: 0xb2b00002}})
	return b
}

func sampleHold() *Builder {
	b := New(SampleStart, 1010)
	b.Call(CallOptions{Start: at(0), From: "alice", To: "bob", Hold: true, HoldAt: 2 * time.Second, HoldFor: 2 * time.Second,
		TalkTime: 6 * time.Second, Codec: "G729"})
	b.Call(CallOptions{Start: at(15), From: "carol", To: "dave", Hold: true, HoldZeroIP: true, HoldAt: 2 * time.Second,
		HoldFor: 2 * time.Second, TalkTime: 6 * time.Second, Codec: "G729", Callee: netip.MustParseAddrPort("10.0.2.21:5060")})
	return b
}

func sampleTCP() *Builder {
	b := New(SampleStart, 1011)
	b.Call(CallOptions{Start: at(0), From: "alice", To: "bob", Transport: "TCP", TCPSplit: true, TCPCoalesce: true,
		TalkTime: 2 * time.Second})
	b.Options(OptionsOptions{Start: at(8), Transport: "TCP", Count: 2, Interval: 5 * time.Second})
	return b
}

func sampleIPv6VLAN() *Builder {
	b := New(SampleStart, 1012)
	b.SetLink(LinkOptions{IPv6: true, VLAN: 100})
	b.Register(RegisterOptions{Start: at(0)})
	b.Call(CallOptions{Start: at(2), From: "alice", To: "bob", Topology: Proxy, TalkTime: 3 * time.Second})
	b.Options(OptionsOptions{Start: at(10), Count: 2, Interval: 5 * time.Second})
	return b
}

// sampleFeatures covers the remaining generator features: Linux cooked
// capture with nanosecond timestamps, early media, delayed offer, DTMF
// (RFC 4733), RTCP, a Reason header and a callee hang-up.
func sampleFeatures() *Builder {
	b := New(SampleStart, 1014)
	b.SetLink(LinkOptions{SLL: true, Nanos: true})
	b.Call(CallOptions{Start: at(0), From: "alice", To: "bob", EarlyMedia: true, RingTime: 2 * time.Second, TalkTime: 6 * time.Second,
		HangUpBy: "callee", Reason: "Q.850;cause=16;text=\"Normal call clearing\"",
		CallerRTP: RTPOptions{SSRC: 0xfea70001, DTMF: "123#", DTMFAt: time.Second, RTCP: true},
		CalleeRTP: RTPOptions{SSRC: 0xfea70002, RTCP: true}})
	b.Call(CallOptions{Start: at(15), From: "carol", To: "dave", DelayedOffer: true, Codec: "PCMA", TalkTime: 4 * time.Second,
		Callee:    netip.MustParseAddrPort("10.0.2.21:5060"),
		CallerRTP: RTPOptions{SSRC: 0xfea70003}, CalleeRTP: RTPOptions{SSRC: 0xfea70004}})
	return b
}

// MixedStats are the planned counts of the mixed busy hour capture, handed
// out so tests can compare them with independent measurements.
type MixedStats struct {
	// Calls is the number of INVITE calls (caller leg Call-IDs).
	Calls int
	// ByOutcome counts calls per outcome name.
	ByOutcome map[string]int
}

var mixedCallerUAs = []string{
	"Yealink SIP-T46S 66.85.0.5", "Polycom/6.4.3.0188 PolycomVVX-VVX_450", "Grandstream GXP2170 1.0.11.74",
	"snom-D785/10.1.168.0", "Linphone Desktop/5.0.12 (Qt/5.15.2)", "Cisco-CP-8845/12.8.1", "Zoiper rv2.10.19.2",
}

var mixedCalleeUAs = []string{
	"Asterisk PBX 20.5.0", "FreeSWITCH-mod_sofia/1.10.11", "OpenSIPS (3.4.2 - x86_64/linux)", "3CXPhoneSystem 20.0.1 (1034)",
}

// MixedBusyHour builds the mixed busy hour capture: about 150 calls with
// random outcomes from several user agents over ten minutes, a few
// registrations and keep-alives. Media is a short burst per call. It is
// deterministic.
func MixedBusyHour() (*Builder, MixedStats) {
	const calls = 150
	b := New(SampleStart, 1013)
	rng := rand.New(rand.NewPCG(1013, 7))
	st := MixedStats{ByOutcome: map[string]int{}}
	pick := func(list []string) string { return list[rng.IntN(len(list))] }
	users := []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"}
	for i := range 3 {
		b.Register(RegisterOptions{Start: SampleStart.Add(time.Duration(i) * time.Second), User: users[i],
			Client: netip.MustParseAddrPort(fmt.Sprintf("10.0.1.%d:5060", 10+i)), ClientUA: pick(mixedCallerUAs)})
	}
	for i := range 6 {
		b.Options(OptionsOptions{Start: SampleStart.Add(time.Duration(i*100) * time.Second), Count: 1,
			Client: netip.MustParseAddrPort("10.0.0.1:5060"), Server: netip.MustParseAddrPort(fmt.Sprintf("10.0.3.%d:5060", 10+i%3))})
	}
	for i := range calls {
		o := CallOptions{
			Start:     SampleStart.Add(time.Duration(i)*4*time.Second + time.Duration(rng.IntN(3000))*time.Millisecond),
			From:      users[rng.IntN(len(users))],
			To:        users[rng.IntN(len(users))],
			Caller:    netip.MustParseAddrPort(fmt.Sprintf("10.0.1.%d:5060", 10+rng.IntN(40))),
			Callee:    netip.MustParseAddrPort(fmt.Sprintf("10.0.2.%d:5060", 10+rng.IntN(40))),
			CallerUA:  pick(mixedCallerUAs),
			CalleeUA:  pick(mixedCalleeUAs),
			Codec:     []string{"PCMU", "PCMA", "PCMU", "G729", "opus"}[rng.IntN(5)],
			TalkTime:  time.Duration(3+rng.IntN(25)) * time.Second,
			RingTime:  time.Duration(500+rng.IntN(5000)) * time.Millisecond,
			Compact:   true,
			CallerRTP: RTPOptions{MaxPackets: 3},
			CalleeRTP: RTPOptions{MaxPackets: 3},
		}
		if o.From == o.To {
			o.To = users[(rng.IntN(len(users)-1)+1+indexOf(users, o.From))%len(users)]
		}
		switch rng.IntN(25) {
		case 0, 1:
			o.Topology = Proxy
		case 2:
			o.Topology = B2BUA
		}
		if rng.IntN(25) == 0 {
			o.Transport = "TCP"
		}
		name := "answered"
		switch r := rng.IntN(100); {
		case r < 38:
			if rng.IntN(10) == 0 {
				o.Auth = 407
				name = "answered+auth"
			}
			if rng.IntN(12) == 0 {
				o.HangUpBy = "callee"
			}
			if rng.IntN(15) == 0 {
				o.Hold = true
				o.TalkTime = 7 * time.Second
				name = "answered+hold"
			}
		case r < 56:
			o.Outcome, name = Busy, "busy-486"
		case r < 66:
			o.Outcome, name = Cancelled, "cancelled"
		case r < 76:
			o.Outcome, o.RejectCode, name = Rejected, 404, "rejected-404"
		case r < 83:
			o.Outcome, name = ServerError, "server-error-503"
		case r < 90:
			o.Outcome, o.RejectCode, name = Rejected, 603, "rejected-603"
		case r < 95:
			o.Outcome, o.Topology, name = Unreachable, Proxy, "unreachable-408"
			o.Retransmits = 3
		default:
			o.Outcome, name = NoAnswer, "no-answer-cancel"
			o.RingTime = 20 * time.Second
		}
		b.Call(o)
		st.Calls++
		st.ByOutcome[name]++
	}
	return b, st
}

func indexOf(l []string, s string) int {
	for i, v := range l {
		if v == s {
			return i
		}
	}
	return 0
}
