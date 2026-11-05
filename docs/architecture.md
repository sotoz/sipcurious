# Architecture

sipcurious answers "what happened to this call and why" from a pcap, fast on multi-GB captures, and is built from small replaceable parts.
Everything is pure Go (no cgo, no libpcap); the only third-party dependency is `github.com/gopacket/gopacket`.

## Layers

Dependencies point down only. Commands and rules never parse bytes; parsers never know about commands.

```mermaid
flowchart TD
  main["cmd/sipcurious<br/>main(): signals, version, exit code"] --> cli
  cli["internal/cli<br/>command registry, common flags, exit codes, output plumbing"] --> engine
  cli --> report
  cli --> flow
  cli --> export
  cli --> analysis
  cli --> stats
  cli --> query
  engine["internal/engine<br/>Load(): files -> Dataset{Messages, Streams, Calls()}"] --> capture
  engine --> sip
  engine --> rtp
  engine --> call
  analysis["internal/analysis<br/>rule registry, Run, Q.850/status knowledge"] --> call
  stats["internal/stats<br/>Compute: SIP/call/RTP summary"] --> call
  flow["internal/flow<br/>ladder diagrams: ASCII, Mermaid, SVG"] --> call
  export["internal/export<br/>trimmed pcap of selected calls"] --> capture
  export --> call
  query["internal/query<br/>filter language + field registry"] --> call
  report["internal/report<br/>Table/Section/Document + writers"]
  analysis --> report
  stats --> report
  flow --> report
  call["internal/call<br/>Call model: grouping, state machine, timings, SDP/RTP correlation"] --> sdp
  call --> rtp
  call --> trace
  sdp["internal/sdp<br/>SDP parser"]
  rtp["internal/rtp<br/>RTP/RTCP detection, stream stats, MOS (a capture.Handler)"] --> capture
  sip["internal/sip<br/>SIP parser + TCP reassembly (a capture.Handler)"] --> capture
  sip --> trace
  capture["internal/capture<br/>pcap/pcapng/gzip/stdin, L2-L4 decode, Handler pipeline"]
  trace["internal/trace<br/>Message model + header accessors"]
```

`internal/pcaptest` (deterministic pcap generator) is test support: only `*_test.go` files and `internal/pcaptest/cmd/gensamples` import it.

## Data flow

```
 file(s) --> capture.Read ---------------------------> handlers (one set per file)
              per file: read record, decode L2..L4,       sip.Handler  -> []trace.Message
              reassemble IP fragments, hand Packet        rtp.Handler  -> []rtp.Stream
              to handlers in priority order                (your handler here)
                                                                |
        engine.Load: merge files, sort messages by time <-------+
                |
                v
        engine.Dataset{Messages, Streams}
                |  Calls() (lazy, once)
                v
        call.Build(messages) -> []call.Call ; call.Attach(calls, streams)
                |
   +------------+-------------+--------------+---------------+
   v            v             v              v               v
 query      analysis.Run   stats.Compute   flow.Write*    export.Write
 (filters)  (Findings)     (Summary)       (ladders)      (trimmed pcap)
   \____________\_____________\______________/                /
                         report.Table / Section / Document   (copies raw records)
                         -> table, csv, json, ndjson, markdown, html
```

1. `capture.Read` opens every path (a file, gzip, or `-` for stdin), detects pcap versus pcapng by magic, decodes each record down to a transport payload (`capture.Packet`) and offers it to the handlers created for that file. Handlers are tried in registration order and the first one returning `true` consumes the packet; unconsumed packets are counted as `Skipped`.
2. `engine.Load` registers `sip.NewHandler` and, unless RTP is off, `rtp.NewHandler`. SIP is registered first (priority order). It concatenates the per-file messages and streams and sorts them by capture time (stable: equal times keep file order, then packet order).
3. `Dataset.Calls()` runs `call.Build` (grouping by Call-ID, state machine, timings, media from SDP) and `call.Attach` (RTP streams to calls) once, on first use, and caches the result. Pure signalling commands that do not need call fields never trigger it.
4. Commands filter with `query`, then render through `report`. The same `Dataset` feeds `analysis.Run`, `stats.Compute`, `flow` and `export`.

## Packages and key types

| Package | Role | Key API |
|---|---|---|
| `trace` | The one message model shared by everybody | `Message{File, Index, Time, Src/Dst(+Port), Transport, IsRequest, Method, RequestURI, StatusCode, Reason, CallID, From, To, Contact, CSeq, Via, Raw, HeaderEnd}`; accessors `Header`, `Headers`, `Body`, `SDP`, `Branch`, `FromTag`, `ToTag`, `Info` |
| `capture` | Container formats, link/IP/transport decode, concurrency, handler pipeline; knows no protocol | `Read(ctx, paths, Options{Handlers})`, `Handler`, `Finisher`, `Factory`, `Packet`, `Result`, `HandlersOf[T]`, `ReadRaw` (undecoded records, used by export) |
| `sip` | SIP parser and the handler that finds messages (UDP/SCTP datagrams, TCP stream reassembly framed by Content-Length) | `Parse`, `NewHandler(ParseOptions{Bodies})`, `(*Handler).Messages()` |
| `rtp` | RTP/RTCP detection on any UDP port, loss/jitter/gap/DTMF per stream, E-model MOS estimate | `NewHandler`, `(*Handler).Streams()`, `Stream`, `Quality`, `ParseHeader`, `IsRTCP`, `CodecName` |
| `sdp` | SDP parser (never panics, returns what it parsed) | `Parse`, `Session`, `Media`, `Media.Endpoint` |
| `call` | One `Call` per Call-ID: kind, state, final code, PDD/ring/setup/talk times, ended-by, retransmissions, user agents, negotiated media, correlated streams | `Build`, `Attach`, `Call`, `Kind`, `State`, `Media`, `Options.CorrelateHeaders` |
| `query` | Filter language compiled to closures; fields are a registry | `Parse`, `Query.MatchMessage/MatchCall/NeedsCalls`, `And`, `Field`, `RegisterField`, `Fields`, `Help` |
| `analysis` | Diagnostic rules (registry) producing `Finding`s, thresholds in `Config`, built-in SIP status and Q.850 knowledge | `Rule`, `Register`, `Run`, `Finding`, `Config`, `DefaultConfig`, `Table`, `RuleDocs`, `Status`, `Q850` |
| `stats` | Capture-wide summary (ASR, ACD, percentiles, peaks, top-N, RTP quality) | `Compute(Input)`, `Summary.Sections`, `Summary.KeyValues` |
| `flow` | Ladder diagrams from one shared model | `WriteASCII`, `WriteMermaid`, `SVG` |
| `report` | Generic typed tables and the HTML document builder | `Table`, `Column`, `Section`, `Write`, `WriteSections`, `Document`, `WriteHTML`, `Format`, `Options{Extra, UTC, Color}` |
| `export` | Write a new pcap/pcapng with the selected calls and their media, byte for byte | `SelectCalls`, `Write`; inputs must be seekable files (read twice) |
| `engine` | The single place that composes capture + handlers + call | `Load`, `Dataset`, `Options{RTP, Bodies, CorrelateHeaders, Stdin}` |
| `cli` | Command registry and shared flags | `Register`, `NewCommand`, `Common`, `Env`, `Select`, `Main`, exit codes |

### Commands and what they use

Every command is one file in `internal/cli` (usage: [usage.md](usage.md); worked examples: [cookbook.md](cookbook.md)).

| Command | File | Builds on |
|---|---|---|
| `messages`, `show` | `messages.go`, `show.go` | `query` over `Dataset.Messages`; RTP is not loaded unless the filter needs call fields |
| `calls` | `calls.go` | `Dataset.Calls()`, `query.MatchCall`, sorting |
| `flow` | `flow.go` | `flow.WriteASCII` / `WriteMermaid` / `SVG` over the selected calls |
| `diagnose`, `rules` | `diagnose.go`, `rules.go` | `analysis.Run` with `Config` thresholds, `analysis.RuleDocs` |
| `rtp` | `rtp.go` | `Dataset.Streams`, `call.Attach` correlation |
| `stats` | `stats.go` | `stats.Compute`, `Summary.Sections` |
| `export` | `export.go` | `export.SelectCalls` / `Write` (re-reads the raw records of the input files; stdin is spooled first) |
| `report` | `report.go` | `analysis` + `stats` + `flow` + `report.Document` |
| `fields`, `completion`, `version`, `help` | `fields.go`, `completion.go`, `version.go`, `help.go` | `query.Help`, the command registry |

## Concurrency and memory model

- **Files in parallel, packets in order.** `capture.Read` runs one goroutine per input file (at most `GOMAXPROCS` at a time). Inside a file one goroutine decodes and calls the handlers sequentially, so handlers need no locks. `Factory` is called once per file and each handler instance only ever sees its own file; handlers must not share mutable state across files. Results are merged after the read (`HandlersOf[T]`).
- **Zero-allocation hot path.** Ethernet/VLAN/SLL/SLL2/Null/Raw link layers, IPv4/IPv6 and UDP/TCP are decoded by hand-written code into one reused `Packet`; only exotic cases fall back to gopacket. `Packet` and its `Payload` are only valid during `Handle`: copy what you keep.
- **One allocation per SIP message.** `Message.Raw` is a single string; `CallID`, `From`, `To`, `Contact`, `CSeq`, `Via` are substrings of it (only folded multi-line headers are copied). Other headers are found on demand by scanning `Raw` (`Message.Header`). `call.Build` copies the messages once into a shared backing array, grouped per call, so a `Call` is a slice of it.
- **Bodies.** By default only SDP bodies (and multipart) are kept in `Raw` (`sip.BodySDP`); `BodyAll` and `BodyNone` exist. A message is cut at 64 KiB.
- **RTP is streaming.** Per stream the handler keeps counters and the RFC 3550 recurrences (about 0.7 KB per validated stream); packets are never stored. Candidate flows that have not yet reached 5 plausibly continuous packets live in two bounded generations (default 4096), so a capture full of random UDP stays bounded. With `--no-rtp` (or when the query needs no call fields) the RTP handler is not registered at all and RTP datagrams are just counted as skipped.
- **TCP is bounded.** The SIP handler reassembles per direction of each connection (at most 1024 tracked, least recently used flushed), only follows a stream after a SIP start line was seen (TLS/HTTP cost nothing), and caps a message at 64 KiB.
- **Call building** is O(n) for time-ordered input and O(n log n) otherwise; the per-call analysis runs on `GOMAXPROCS` workers. `Dataset.Calls()` is computed once and shared: callers must not modify the result.
- **Cancellation.** Every long loop checks the context; `Ctrl-C` cancels, exits 130 and a second `Ctrl-C` kills at once.
- **Export** reads each input twice (pass 1 decodes concurrently and keeps one bit per record; pass 2 streams the chosen raw records), hence regular files only.

## Performance

Measured with the package benchmarks, on an Apple M6 (12 cores), Go 1.27.3, darwin/arm64, `-benchtime 3x` (three iterations each, so expect run-to-run noise of 10-30 %):

```
go test -run '^$' -bench . -benchmem -benchtime 3x ./internal/capture ./internal/rtp ./internal/call ./internal/query
```

| Benchmark | Workload | Result |
|---|---|---|
| `capture.BenchmarkReadNoop` | 1M-packet Ethernet pcap (80 % 172-byte UDP, 15 % SIP over UDP, 5 % other), handler consumes nothing | 32.6 ms = **30.6 M pkts/s**, 15 allocs total |
| `capture.BenchmarkReadSIP` | same file, SIP handler | 128.7 ms = **7.8 M pkts/s**, 150 054 allocs (one per SIP message plus slice growth) |
| `capture.BenchmarkGopacketBaseline` | same file decoded with gopacket layers | 278.6 ms = 3.6 M pkts/s, 12.3 M allocs |
| `rtp.BenchmarkHandle1MPackets200Streams` | 1M RTP packets over 200 streams | 40.9 ms = **40.9 ns/pkt**, 239 allocs total |
| `call.BenchmarkBuild1M` | 1M messages, time ordered / shuffled | 155.9 ms (6.4 M msgs/s) / 448.9 ms (2.2 M msgs/s) |
| `call.BenchmarkAttach` | 40 000 streams attached to calls | 21.2 ms |
| `query.BenchmarkMatchMessage1M` | 1M messages, compiled filter | 18.2 ms = 54.9 M msgs/s, **0 allocs** |
| `query.BenchmarkParse` | compile one expression | 4.1 us, 46 allocs |

These are in-memory/page-cache numbers; with a cold disk the file read dominates. They show the design target: reading and filtering are limited by I/O, not by CPU. The benchmark captures are generated on the fly, so the numbers can be reproduced on any machine; compare ratios, not absolutes, across hardware.

## Extension recipes

Every extension point is a registry or an interface; adding one never edits existing code (except the registering file itself). The examples below were compiled with `go vet` and run as scratch tests/commands against this tree.

### 1. A new protocol: `capture.Handler`

A handler consumes decoded packets of one file. Return `true` to consume the packet (later handlers never see it), `false` to pass it on. Implement `Finish()` (`capture.Finisher`) if you buffer state until the end of the file.

```go
package capture_test

import (
	"bytes"
	"context"

	"github.com/sotoz/sipcurious/internal/capture"
)

// stunHandler counts STUN Binding requests (UDP, magic cookie 0x2112A442).
type stunHandler struct{ Requests int }

// Handle implements capture.Handler.
func (h *stunHandler) Handle(p *capture.Packet) bool {
	b := p.Payload // only valid during this call: copy what you keep
	if p.Transport != "UDP" || len(b) < 20 || b[0]&0xC0 != 0 ||
		!bytes.Equal(b[4:8], []byte{0x21, 0x12, 0xA4, 0x42}) {
		return false // not ours: the next handler (or "skipped") gets it
	}
	if b[0] == 0x00 && b[1] == 0x01 { // Binding Request
		h.Requests++
	}
	return true
}

func countSTUN(paths []string) (int, error) {
	factory := func(file string) capture.Handler { return &stunHandler{} } // one per file
	res, err := capture.Read(context.Background(), paths,
		capture.Options{Handlers: []capture.Factory{factory}})
	if err != nil {
		return 0, err
	}
	total := 0
	for _, h := range capture.HandlersOf[*stunHandler](res) { // in file order
		total += h.Requests
	}
	return total, nil
}
```

To make the protocol part of every command, append your factory to the list in `engine.Load` and expose the result on `engine.Dataset` (see how `rtp` is wired: `capture.HandlersOf[*rtp.Handler](res)`). Put it after SIP when it could be confused with SIP. The `trace.Message` model is SIP-specific; a protocol with its own data model should carry its own types, like `rtp.Stream`.

### 2. A new diagnostic: `analysis.Rule`

A rule is a pure function of `*analysis.Input` (messages, calls with media already attached, streams, thresholds). Register it from `init`; rule selection by ID, the rule list and the generated rule documentation (`analysis.RuleDocs`) read the registry. A rule that also implements `Documented` (`Doc() string`, Markdown) appears with its explanation in `analysis.RuleDocs()`.

```go
package analysis

import (
	"fmt"

	"github.com/sotoz/sipcurious/internal/call"
)

type noUA struct{}

func (noUA) ID() string    { return "no-user-agent" } // stable kebab-case
func (noUA) Title() string { return "Call without User-Agent or Server header" }

// Doc is optional; it feeds RuleDocs.
func (noUA) Doc() string {
	return "Reports INVITE calls where no message carries a User-Agent or Server header."
}

func (noUA) Check(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if c.Kind != call.KindCall || len(c.UserAgents) > 0 {
			continue
		}
		out = append(out, Finding{
			Rule: "no-user-agent", Severity: Info, CallID: c.CallID, Time: c.Start,
			Title:   fmt.Sprintf("no User-Agent/Server header in %d messages", len(c.Messages)),
			Detail:  "Neither side identified itself.",
			Hint:    "Check whether an SBC strips the header.",
			Packets: []Ref{{File: c.Messages[0].File, Index: c.Messages[0].Index}}, // proof
		})
	}
	return out
}

func init() { Register(noUA{}) }
```

Existing rules (`internal/analysis/*.go`) use a small `rule` struct with `id/title/doc/check` fields and shared helpers (`refSet` for packet references, `parties`, `dur`); copy one of them (for example `no_response.go`) when adding a rule inside the package. Put thresholds in `analysis.Config` (zero means default, see `WithDefaults`) instead of constants, and add a test with a `pcaptest` scenario.

### 3. A new filter field: `query.RegisterField`

A field is a name, a type and a getter returning `query.Value`. Message getters see one `trace.Message`; call getters see a `*call.Call`. Return the zero `Value` (null) when the datum is absent: null matches no comparison, so `!=`, `!~` and `not in` are true for it. The field then exists in the language, in `--where`, in `sipcurious fields` and in shell completion, with no parser change. The getter must not allocate on the hot path (messages are filtered at tens of millions per second).

```go
package query

import "github.com/sotoz/sipcurious/internal/trace"

func init() {
	RegisterField(Field{
		Name:    "cseq_num",
		Aliases: []string{"cseqno"},
		Type:    TypeInt,
		Doc:     "sequence number of CSeq: cseq_num > 100", // one line with an example
		Message: func(m trace.Message) Value {
			if m.CSeq == "" {
				return Value{} // null
			}
			return IntValue(int64(m.CSeqNumber()))
		},
	})
}
```

`Parse("cseq_num >= 100 and method = INVITE", Options{})` now works. A call-level field sets `Call: func(*call.Call) Value` instead (exactly one of `Message`/`Call`). Enums set `Type: TypeEnum` and `Values`. `RegisterField` panics on a malformed field (bad or duplicate name, both getters), which any test run finds.

### 4. A new command: `cli.Command`

One file in `internal/cli` whose `init` calls `Register`. Help, `sipcurious help <cmd>`, shell completion and the did-you-mean suggestion all read the registry; nothing else is edited. `NewCommand` gives the command the common flags (capture paths, `--where` and the filter sugar flags, `--format`, `--extra`, `--utc`, `--color`, `--output`, `--limit`, `--no-rtp`, `--quiet`), parses them, validates them and hands `run` a `*Common`. This is a complete command:

```go
package cli

import (
	"context"
	"flag"
	"time"

	"github.com/sotoz/sipcurious/internal/report"
)

type slowOpts struct{ min time.Duration }

func init() {
	Register(NewCommand(Command{
		Name:    "slow",
		Summary: "list calls whose setup took longer than --min",
		Usage:   "slow [flags] CAPTURE...",
	}, func(fs *flag.FlagSet, o *slowOpts) {
		fs.DurationVar(&o.min, "min", 3*time.Second, "report setup times above `DURATION`")
	}, func(ctx context.Context, env *Env, c *Common, o *slowOpts) int {
		q, err := c.Query() // validate flags before the expensive load
		if err != nil {
			return env.Fail(err) // UsageError -> exit 2
		}
		ds, err := c.Open(ctx, env) // loads files, prints warnings and the summary line
		if err != nil {
			return env.Fail(err)
		}
		t := report.Table{
			Title: "Slow setups",
			Columns: []report.Column{
				{Name: "Call-ID", Key: "call_id", Kind: report.String},
				{Name: "Setup", Key: "setup", Kind: report.Duration},
			},
		}
		calls := ds.Calls()
		for i := range calls {
			if cl := &calls[i]; cl.SetupTime > o.min && q.MatchCall(cl) {
				t.Rows = append(t.Rows, []any{cl.CallID, cl.SetupTime})
			}
		}
		c.Infof(env, "%s", plural(len(t.Rows), "slow call"))
		return env.Result(c.WriteTable(env, t)) // honours --format/--extra/--utc/--limit/--output
	}))
}
```

Running it: `sipcurious slow --utc --min 2s testdata/samples/mixed-busy-hour.pcapng` printed `51 slow calls` and a `Slow setups` table. Conventions:

- Data to stdout (or `--output`), everything else to stderr via `env.Fail`, `c.Infof`, `env.Printf`. Never print diagnostics to stdout.
- Argument problems are `Usagef(...)` errors (exit 2); runtime failures are plain errors (exit 1); `diagnose` uses exit 3 for findings at or above `--fail-on`.
- A command that produces something other than a table (text, an HTML document) uses `c.OpenOutput(env)` or `c.WriteWith`; a command that wants different flags sets `Command.Run` itself instead of using `NewCommand`.
- `c.Open` takes tweak functions to adjust the engine options, e.g. `func(o *engine.Options) { o.RTP = o.RTP && q.NeedsCalls() }` for commands that only need RTP when the filter does.
- Teach completion the values of a flag with `FlagChoices(name, values...)`.

### 5. A new output format: `report`

A format is a `report.Format` constant and one writer function that renders a `Table`; every command that writes tables gets it, because `--format` takes its valid names from `report.Formats()`. Three small edits in `internal/report`:

1. In `types.go`: add `FormatTSV Format = "tsv"` to the constants, append it to `allFormats`, add `case FormatTSV: writeTSV(s, t, o)` to `Write`, and list it next to `FormatCSV, FormatNDJSON` in `WriteSections` if it cannot hold several tables.
2. Write the writer, appending to the buffered `sink` and calling `maybeFlush` at record boundaries (so output is streamed in 32 KiB chunks):

```go
package report

// writeTSV renders t as tab separated values: the visible columns only, with
// the same human formatting as the text table.
func writeTSV(s *sink, t Table, o Options) {
	cols := visible(t, o) // hides Extra columns unless o.Extra
	for n, j := range cols {
		if n > 0 {
			s.buf = append(s.buf, '\t')
		}
		s.buf = appendSanitized(s.buf, t.Columns[j].Name, modeText)
	}
	s.buf = append(s.buf, '\n')
	for _, row := range t.Rows {
		for n, j := range cols {
			if n > 0 {
				s.buf = append(s.buf, '\t')
			}
			s.buf = appendHuman(s.buf, normalize(cell(row, j)), o, modeText)
		}
		s.buf = append(s.buf, '\n')
		s.maybeFlush()
	}
}
```

3. Add the format to the tests that pin `Formats()`.

With these edits, `sipcurious calls -F tsv testdata/samples/basic-call.pcap` printed a tab-separated header and row. Always sanitise untrusted text with `appendSanitized` (captures are hostile input; control characters and invalid UTF-8 must not reach a terminal or a spreadsheet) and keep the output deterministic.

## Cross-cutting rules

- stdlib + gopacket only. No cgo. Go 1.27. `gofmt` and `go vet` clean; `go test -race` clean.
- No global mutable state except registries filled in `init` (commands, rules, query fields).
- Errors are wrapped with context; no panics on hostile input (the parsers are fuzzed).
- Deterministic output (golden-testable); times are UTC internally and converted at the edge.
- Every exported identifier has a doc comment; every package has a package comment.
- Ground truth for real captures comes from tcpdump/tshark, never from sipcurious itself.
