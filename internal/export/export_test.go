package export_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/capture"
	"github.com/sotoz/sipcurious/internal/export"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/sip"
	"github.com/sotoz/sipcurious/internal/trace"
)

const samples = "../../testdata/samples/"

// load reads paths with the SIP and RTP handlers and returns the calls with
// their streams attached.
func load(t testing.TB, paths ...string) ([]call.Call, []rtp.Stream) {
	t.Helper()
	res, err := capture.Read(context.Background(), paths, capture.Options{Handlers: []capture.Factory{sip.NewHandler(sip.ParseOptions{}), rtp.NewHandler(rtp.HandlerOptions{})}})
	if err != nil {
		t.Fatal(err)
	}
	var msgs []trace.Message
	for _, h := range capture.HandlersOf[*sip.Handler](res) {
		msgs = append(msgs, h.Messages()...)
	}
	var streams []rtp.Stream
	for _, h := range capture.HandlersOf[*rtp.Handler](res) {
		streams = append(streams, h.Streams()...)
	}
	calls := call.Build(msgs, call.Options{})
	call.Attach(calls, streams)
	return calls, streams
}

// frames returns the sha256 of every record's frame plus its timestamp.
func frames(t testing.TB, path string) []string {
	t.Helper()
	var out []string
	err := capture.ReadRaw(context.Background(), path, func(p capture.RawPacket) bool {
		out = append(out, fmt.Sprintf("%d %d %x", p.Time.UnixNano(), p.OrigLen, sha256.Sum256(p.Data)))
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// pick returns the frames of path whose index is in want, in file order.
func pick(t testing.TB, path string, want func(int) bool) []string {
	t.Helper()
	var out []string
	_ = capture.ReadRaw(context.Background(), path, func(p capture.RawPacket) bool {
		if want(p.Index) {
			out = append(out, fmt.Sprintf("%d %d %x", p.Time.UnixNano(), p.OrigLen, sha256.Sum256(p.Data)))
		}
		return true
	})
	return out
}

func write(t testing.TB, inputs []string, sel export.Selector, opt export.Options) (string, export.Stats) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out."+string(opt.Format))
	var buf bytes.Buffer
	st, err := export.Write(context.Background(), &buf, inputs, sel, opt)
	if err != nil {
		t.Fatal(err)
	}
	if int64(buf.Len()) != st.Bytes {
		t.Errorf("Stats.Bytes = %d, output has %d", st.Bytes, buf.Len())
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return out, st
}

// normMsg clears what legitimately changes on export.
func normMsg(m trace.Message) trace.Message {
	m.File, m.Index = "", 0
	return m
}

func normStreams(ss []rtp.Stream) []rtp.Stream {
	out := append([]rtp.Stream(nil), ss...)
	for i := range out {
		out[i].File, out[i].FirstIndex = "", 0
	}
	return out
}

// TestRoundTripCalls exports every call of the demo captures separately and
// checks the result against the original.
func TestRoundTripCalls(t *testing.T) {
	for _, name := range []string{"basic-call.pcap", "bad-media.pcap", "mixed-busy-hour.pcapng", "tcp-sip.pcap", "ipv6-vlan.pcap", "features-sll-nanos.pcap"} {
		t.Run(name, func(t *testing.T) {
			in := samples + name
			calls, _ := load(t, in)
			if name == "mixed-busy-hour.pcapng" && len(calls) > 6 {
				calls = calls[:6] // keep the test quick; the whole-file case below covers the rest
			}
			for i := range calls {
				c := calls[i]
				t.Run(c.CallID, func(t *testing.T) {
					opt := export.Options{Format: export.PCAPNG}
					out, st := write(t, []string{in}, export.SelectCalls([]call.Call{c}, true), opt)

					got, _ := load(t, out)
					var mine *call.Call
					for j := range got {
						if got[j].CallID == c.CallID {
							mine = &got[j]
						}
					}
					if mine == nil {
						t.Fatalf("call %s missing from export", c.CallID)
					}
					if len(mine.Messages) != len(c.Messages) {
						t.Fatalf("%d messages, want %d", len(mine.Messages), len(c.Messages))
					}
					last := 0
					for j := range c.Messages {
						a, b := normMsg(mine.Messages[j]), normMsg(c.Messages[j])
						if !reflect.DeepEqual(a, b) {
							t.Errorf("message %d differs:\n got %+v\nwant %+v", j, a, b)
						}
						if idx := mine.Messages[j].Index; idx < last || idx > st.Written {
							t.Errorf("message %d index %d (previous %d, written %d)", j, idx, last, st.Written)
						}
						last = mine.Messages[j].Index
					}
					if a, b := normStreams(mine.Streams), normStreams(c.Streams); !reflect.DeepEqual(a, b) {
						t.Errorf("streams differ:\n got %+v\nwant %+v", a, b)
					}

					// frames: the output is exactly the selected original frames
					sel := map[int]bool{}
					for _, m := range c.Messages {
						sel[m.Index] = true
					}
					tcp := c.Messages[0].Transport == "TCP" // whole connections are exported
					mediaPkts := 0
					for _, s := range c.Streams {
						mediaPkts += int(s.Packets)
					}
					if st.SIP != len(sel) || st.Flows < mediaPkts || st.Written != st.SIP+st.Flows {
						t.Errorf("stats %+v: want SIP=%d Flows>=%d", st, len(sel), mediaPkts)
					}
					outFrames := frames(t, out)
					if len(outFrames) != st.Written {
						t.Fatalf("output has %d records, Stats.Written = %d", len(outFrames), st.Written)
					}
					orig := map[string]int{}
					for _, f := range frames(t, in) {
						orig[f]++
					}
					for _, f := range outFrames {
						if orig[f] == 0 {
							t.Fatalf("output frame not found in input: %s", f)
						}
					}
					sipOnly := pick(t, in, func(i int) bool { return sel[i] })
					j := 0
					for _, f := range outFrames {
						if j < len(sipOnly) && f == sipOnly[j] {
							j++
						}
					}
					if j != len(sipOnly) {
						t.Errorf("SIP frames are not an in-order subsequence of the output (%d of %d)", j, len(sipOnly))
					}

					// without media only the SIP messages remain
					out2, st2 := write(t, []string{in}, export.SelectCalls([]call.Call{c}, false), opt)
					if tcp {
						if st2.Written < len(sel) || st2.SIP != len(sel) {
							t.Errorf("no-media tcp stats %+v, want >= %d", st2, len(sel))
						}
					} else {
						if st2.Written != len(sel) || st2.Flows != 0 {
							t.Errorf("no-media stats %+v, want %d SIP", st2, len(sel))
						}
						if got := frames(t, out2); !reflect.DeepEqual(got, sipOnly) {
							t.Errorf("no-media frames differ")
						}
					}
				})
			}
		})
	}
}

func TestWholeCaptureAllCalls(t *testing.T) {
	in := samples + "mixed-busy-hour.pcapng"
	calls, streams := load(t, in)
	out, st := write(t, []string{in}, export.SelectCalls(calls, true), export.Options{})
	got, gotStreams := load(t, out)
	if len(got) != len(calls) {
		t.Fatalf("%d calls, want %d", len(got), len(calls))
	}
	for i := range calls {
		if got[i].CallID != calls[i].CallID || len(got[i].Messages) != len(calls[i].Messages) {
			t.Errorf("call %d: %s/%d msgs, want %s/%d", i, got[i].CallID, len(got[i].Messages), calls[i].CallID, len(calls[i].Messages))
		}
	}
	// Streams not correlated to any call are not exported.
	attached := 0
	for _, c := range calls {
		attached += len(c.Streams)
	}
	if len(gotStreams) < attached || len(gotStreams) > len(streams) {
		t.Errorf("%d streams exported, %d attached, %d in input", len(gotStreams), attached, len(streams))
	}
	if st.Interfaces != 1 {
		t.Errorf("interfaces = %d, want 1", st.Interfaces)
	}
}

func TestMultipleInputsMerged(t *testing.T) {
	a, b := samples+"basic-call.pcap", samples+"bad-media.pcap"
	ca, _ := load(t, a)
	cb, _ := load(t, b)
	sel := export.SelectCalls(append(append([]call.Call(nil), ca...), cb...), true)

	for _, f := range []export.Format{export.PCAPNG, export.PCAP} {
		t.Run(string(f), func(t *testing.T) {
			out, st := write(t, []string{a, b}, sel, export.Options{Format: f, Nanos: true})
			if st.Inputs != 2 {
				t.Errorf("inputs = %d", st.Inputs)
			}
			// time order
			var prev time.Time
			n := 0
			if err := capture.ReadRaw(context.Background(), out, func(p capture.RawPacket) bool {
				if p.Time.Before(prev) {
					t.Errorf("record %d goes back in time", p.Index)
				}
				prev = p.Time
				n++
				return true
			}); err != nil {
				t.Fatal(err)
			}
			if n != st.Written {
				t.Errorf("records = %d, written = %d", n, st.Written)
			}
			wantIf := 2
			if f == export.PCAP {
				wantIf = 1
			}
			if st.Interfaces != wantIf {
				t.Errorf("interfaces = %d, want %d", st.Interfaces, wantIf)
			}
			got, _ := load(t, out)
			if len(got) != len(ca)+len(cb) {
				t.Errorf("%d calls, want %d", len(got), len(ca)+len(cb))
			}
			// multiset of frames equals both inputs' selected frames
			want := map[string]int{}
			for _, p := range []string{a, b} {
				for _, f := range frames(t, p) {
					want[f]++
				}
			}
			for _, f := range frames(t, out) {
				if want[f] == 0 {
					t.Fatalf("unknown frame %s", f)
				}
			}
		})
	}
}

func TestLinkTypesAndTimestamps(t *testing.T) {
	eth, sll := samples+"basic-call.pcap", samples+"features-sll-nanos.pcap"
	ce, _ := load(t, eth)
	cs, _ := load(t, sll)
	sel := export.SelectCalls(append(append([]call.Call(nil), ce...), cs...), false)

	// pcapng keeps one interface per (file, link type)
	out, st := write(t, []string{eth, sll}, sel, export.Options{})
	if st.Interfaces != 2 {
		t.Errorf("interfaces = %d, want 2", st.Interfaces)
	}
	lts := map[layers.LinkType]bool{}
	_ = capture.ReadRaw(context.Background(), out, func(p capture.RawPacket) bool { lts[p.LinkType] = true; return true })
	if !lts[layers.LinkTypeEthernet] || !lts[layers.LinkTypeLinuxSLL] || len(lts) != 2 {
		t.Errorf("link types %v", lts)
	}
	// nanosecond timestamps survive in pcapng
	if got, want := frames(t, out), 0; len(got) == want {
		t.Fatal("no frames")
	}
	sub := map[string]bool{}
	for _, f := range frames(t, sll) {
		sub[f] = true
	}
	found := 0
	for _, f := range frames(t, out) {
		if sub[f] {
			found++
		}
	}
	if found == 0 {
		t.Error("no SLL frame with identical timestamp, length and bytes in the output")
	}

	// classic pcap cannot mix link types
	var buf bytes.Buffer
	if _, err := export.Write(context.Background(), &buf, []string{eth, sll}, sel, export.Options{Format: export.PCAP}); err == nil || !strings.Contains(err.Error(), "link type") {
		t.Errorf("mixed link types in pcap: err = %v", err)
	}

	// classic pcap: microsecond truncation unless Nanos
	p1, _ := write(t, []string{sll}, export.SelectCalls(cs, false), export.Options{Format: export.PCAP})
	p2, _ := write(t, []string{sll}, export.SelectCalls(cs, false), export.Options{Format: export.PCAP, Nanos: true})
	orig := frames(t, sll)
	origSet := map[string]bool{}
	for _, f := range orig {
		origSet[f] = true
	}
	for _, f := range frames(t, p2) {
		if !origSet[f] {
			t.Fatalf("nanosecond pcap frame differs from input: %s", f)
		}
	}
	trunc := 0
	_ = capture.ReadRaw(context.Background(), p1, func(p capture.RawPacket) bool {
		if p.Time.Nanosecond()%1000 != 0 {
			t.Errorf("microsecond pcap has nanoseconds: %v", p.Time)
		}
		trunc++
		return true
	})
	if trunc == 0 {
		t.Error("empty output")
	}
}

func TestFlowSelection(t *testing.T) {
	in := samples + "basic-call.pcap"
	_, streams := load(t, in)
	if len(streams) != 2 {
		t.Fatalf("%d streams", len(streams))
	}
	s := streams[0]
	for _, tc := range []struct {
		name string
		sel  export.Selector
		want int
	}{
		{"one direction", export.Selector{Flows: []export.Flow{{Src: s.Src, Dst: s.Dst}}}, int(s.Packets)},
		{"window", export.Selector{Flows: []export.Flow{{Src: s.Src, Dst: s.Dst, From: s.Start, To: s.Start}}}, 1},
		{"other file never matches", export.Selector{Flows: []export.Flow{{File: "nope", Src: s.Src, Dst: s.Dst}}}, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			st, err := export.Write(context.Background(), &buf, []string{in}, tc.sel, export.Options{})
			if tc.want < 0 {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if st.Flows < tc.want || st.Written != st.Flows {
				t.Errorf("stats %+v, want >= %d media", st, tc.want)
			}
		})
	}
	// both directions
	var buf bytes.Buffer
	one, _ := export.Write(context.Background(), &buf, []string{in}, export.Selector{Flows: []export.Flow{{Src: s.Src, Dst: s.Dst}}}, export.Options{})
	buf.Reset()
	both, _ := export.Write(context.Background(), &buf, []string{in}, export.Selector{Flows: []export.Flow{{Src: s.Src, Dst: s.Dst}}, AnyDirection: true}, export.Options{})
	if both.Written <= one.Written {
		t.Errorf("AnyDirection wrote %d, one direction %d", both.Written, one.Written)
	}
}

func TestErrors(t *testing.T) {
	in := samples + "basic-call.pcap"
	ctx := context.Background()
	var buf bytes.Buffer

	if _, err := export.Write(ctx, &buf, []string{"-"}, export.Selector{}, export.Options{}); !errors.Is(err, export.ErrNotSeekable) {
		t.Errorf("stdin: err = %v", err)
	}
	if _, err := export.Write(ctx, &buf, []string{filepath.Join(t.TempDir(), "missing.pcap")}, export.Selector{}, export.Options{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: err = %v", err)
	}
	if st, err := export.Write(ctx, &buf, []string{in}, export.Selector{}, export.Options{}); !errors.Is(err, export.ErrNoPackets) || buf.Len() != 0 || st.Written != 0 {
		t.Errorf("empty selection: err = %v, %d bytes", err, buf.Len())
	}
	sel := export.Selector{Packets: map[export.Ref]struct{}{{File: "other.pcap", Index: 1}: {}}}
	if _, err := export.Write(ctx, &buf, []string{in}, sel, export.Options{}); err == nil {
		t.Error("record of an unknown file: want error")
	}
	sel = export.Selector{Packets: map[export.Ref]struct{}{{File: in, Index: 999999}: {}, {File: in, Index: 1}: {}}}
	st, err := export.Write(ctx, &buf, []string{in}, sel, export.Options{})
	if err != nil || st.Written != 1 || st.Missing != 1 {
		t.Errorf("missing record: %+v %v", st, err)
	}
	if _, err := export.Write(ctx, &buf, []string{in}, sel, export.Options{Format: "pdf"}); err == nil {
		t.Error("unknown format: want error")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := export.Write(cctx, &bytes.Buffer{}, []string{in}, export.Selector{Flows: []export.Flow{{Src: mustAP("10.0.1.10:16384"), Dst: mustAP("10.0.2.20:18000")}}}, export.Options{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v", err)
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]export.Format{"": export.PCAPNG, "pcapng": export.PCAPNG, "pcap": export.PCAP} {
		if got, err := export.ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := export.ParseFormat("x"); err == nil {
		t.Error("want error")
	}
}

// TestExternalTools checks the output with tcpdump and tshark when present.
func TestExternalTools(t *testing.T) {
	in := samples + "bad-media.pcap"
	calls, _ := load(t, in)
	c := calls[len(calls)-1]
	for _, f := range []export.Format{export.PCAPNG, export.PCAP} {
		out, st := write(t, []string{in}, export.SelectCalls([]call.Call{c}, true), export.Options{Format: f})
		if p, err := exec.LookPath("tcpdump"); err == nil {
			b, err := exec.Command(p, "-nn", "-r", out).CombinedOutput()
			if err != nil {
				t.Fatalf("tcpdump -r %s: %v\n%s", f, err, b)
			}
			if n := strings.Count(string(b), "\n"); n < st.Written || strings.Contains(string(b), "truncated") {
				t.Errorf("tcpdump %s: %d lines for %d packets\n%.300s", f, n, st.Written, b)
			}
		} else {
			t.Log("tcpdump not found")
		}
		if p, err := exec.LookPath("tshark"); err == nil {
			b, err := exec.Command(p, "-r", out, "-T", "fields", "-e", "frame.number").CombinedOutput()
			if err != nil {
				t.Fatalf("tshark -r %s: %v\n%s", f, err, b)
			}
			if n := len(strings.Fields(string(b))); n != st.Written {
				t.Errorf("tshark %s: %d frames, want %d\n%.300s", f, n, st.Written, b)
			}
			b, _ = exec.Command(p, "-r", out, "-Y", "sip", "-T", "fields", "-e", "sip.Call-ID").CombinedOutput()
			for _, id := range strings.Fields(string(b)) {
				if id != c.CallID {
					t.Errorf("tshark %s: foreign Call-ID %q in export", f, id)
				}
			}
			if n := len(strings.Fields(string(b))); n != len(c.Messages) {
				t.Errorf("tshark %s: %d SIP messages, want %d", f, n, len(c.Messages))
			}
		} else {
			t.Log("tshark not found")
		}
	}
}

func mustAP(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// rawEach calls fn with the record number of every record of path.
func rawEach(path string, fn func(int)) error {
	return capture.ReadRaw(context.Background(), path, func(p capture.RawPacket) bool { fn(p.Index); return true })
}
