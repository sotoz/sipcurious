# Repository Guidelines

## Project Overview

`sipcurious` v2 is a fast, modular Go CLI for troubleshooting SIP/VoIP calls from pcap and pcapng files: "what happened to this call and why", on multi-GB captures, in one command. Module `github.com/sotoz/sipcurious`, Go 1.27, GPL v3, pure Go (no cgo, no libpcap), one third-party dependency (`github.com/gopacket/gopacket`).

Commands are subcommands: `calls`, `messages`, `show`, `flow`, `diagnose`, `rtp`, `stats`, `export`, `report`, `rules`, `fields`, `completion`, `version`, `help`. **`sipcurious help` is the authoritative list; `sipcurious help <command>` the authoritative flags.** Do not duplicate flag lists in docs by hand ([docs/usage.md](docs/usage.md) is generated from that output: regenerate its command sections when a flag changes).

## Architecture & Data Flow

Layers depend downward only (diagram and package table: [docs/architecture.md](docs/architecture.md)).

```
cmd/sipcurious -> cli -> engine -> capture (+ sip, rtp handlers) -> trace
                   |        \-> call (+ sdp, rtp) -> query / analysis / stats / flow / export -> report
```

- `capture.Read` reads files in parallel (one goroutine per file), decodes L2-L4 and offers each `capture.Packet` to the per-file `Handler`s in priority order (first `true` wins). It knows no protocol.
- `sip.Handler` yields `[]trace.Message` (UDP/SCTP datagram = message; TCP is reassembled and framed by Content-Length). `rtp.Handler` yields `[]rtp.Stream` (streaming per-stream stats, no packet storage).
- `engine.Load` composes both handlers, merges files by time and returns a `Dataset`; `Dataset.Calls()` lazily runs `call.Build` + `call.Attach` once.
- Commands filter with `query`, then feed `analysis.Run`, `stats.Compute`, `flow`, `export`, and render everything through `report` (`table`, `csv`, `json`, `ndjson`, `markdown`, `html`).
- Data on stdout (or `--output`); summary, warnings and errors on stderr prefixed `sipcurious: `. Exit codes: 0 ok (also "no matches"), 1 runtime error, 2 usage error, 3 findings at or above `--fail-on`, 130 interrupted.

## Key Directories

| Path | Purpose |
|---|---|
| `cmd/sipcurious/` | `main()` only: signals, version, exit code |
| `internal/cli/` | command registry, common flags, one file per command (`calls.go`, `messages.go`, ...) |
| `internal/engine/` | `Load` -> `Dataset{Messages, Streams, Calls()}` |
| `internal/capture/`, `sip/`, `rtp/`, `sdp/` | readers and protocol parsers; `sip` and `rtp` are `capture.Handler`s |
| `internal/trace/` | the shared `Message` model |
| `internal/call/` | `Call` model: kind/state/timings/media, `Build`, `Attach` |
| `internal/query/`, `analysis/`, `stats/`, `flow/`, `export/`, `report/` | filters, diagnostics, statistics, ladders, trimmed pcaps, tables/HTML |
| `internal/pcaptest/` | deterministic pcap generator (tests and demos only); `cmd/gensamples` writes `testdata/samples` |
| `testdata/samples/` | 14 synthetic demo captures with exact documented facts (`README.md`) |
| `testdata/realworld/` | 50 real third-party and derived captures, provenance in `testdata/README.md` |
| `testdata/aaa.pcap` | the original real capture (691 packets, 81 SIP messages, 6 Call-IDs) |
| `docs/` | `usage.md` (command reference), `cookbook.md` (scenarios with real output), `architecture.md`, `query.md`, `capture-formats.md`, `definitions.md` |
| `.github/workflows/ci.yml`, `release.yml` | CI: `gofmt -l`, `go vet`, `go test -race` on Linux, macOS, Windows; release: on a `v*` tag cross-compiles with `make dist` and publishes archives + `SHA256SUMS` |

## Development Commands

```sh
make all                       # vet, test, build
make build                     # ./sipcurious with version stamped via -ldflags
make dist                      # ./dist: tar.gz/zip per linux|darwin|windows x amd64|arm64 + SHA256SUMS (PLATFORMS="linux/amd64" to narrow)
go build -o /tmp/sipcurious ./cmd/sipcurious
go vet ./... && go test ./...
go test -race ./internal/capture ./internal/sip
go test -run '^$' -bench . -benchmem -benchtime 3x ./internal/capture ./internal/rtp ./internal/call ./internal/query
go test ./internal/sip -run '^$' -fuzz FuzzParse -fuzztime 20s     # fuzz targets: sip, sdp, rtp, query, capture, report, call, analysis, flow, stats
go run ./internal/pcaptest/cmd/gensamples                          # regenerate testdata/samples (byte-compared by a test)
/tmp/sipcurious calls --utc testdata/samples/basic-call.pcap
/tmp/sipcurious messages -w 'status >= 500' testdata/samples/*.pcap
/tmp/sipcurious help
```

Requires Go 1.27+. Never run `go mod tidy` or edit `go.mod` casually: stdlib + gopacket only.

## Code Conventions & Common Patterns

- `gofmt` and `go vet` clean; no other linter. Every package has a package comment, every exported identifier a doc comment.
- **Extension points are registries/interfaces; adding one never edits existing code** (full compiling recipes in [docs/architecture.md](docs/architecture.md)):
  - new protocol -> `capture.Handler` (+ `Factory`), wired in `engine.Load`;
  - new diagnostic -> `analysis.Rule`, `analysis.Register` from `init` (optional `Doc()` for generated docs);
  - new filter field -> `query.RegisterField` from `init` (null `Value` when absent);
  - new command -> one file in `internal/cli` with `Register(NewCommand(...))`; help, completion and did-you-mean pick it up;
  - new output format -> constant + writer in `internal/report` (`Write`, `Formats()`).
- No global mutable state except those registries. Options travel as structs.
- Errors are wrapped with context (`fmt.Errorf("%s: %w", path, err)`); only `main` exits. Argument errors are `cli.Usagef` (exit 2). No panics on hostile input.
- Output is deterministic and sanitised: captures are untrusted, so all text goes through `report` writers (control characters and invalid UTF-8 never reach terminal, HTML, Markdown or CSV). Times are UTC internally and converted at the edge (`--utc`).
- **Memory and speed matter.** `trace.Message.Raw` is one string per message and `CallID/From/To/Contact/CSeq/Via` are substrings of it: never copy them; `Packet.Payload` is only valid inside `Handle`. Message-field getters in `query` must not allocate. Do not retain packets in handlers; stream statistics.
- Handlers run per file on one goroutine (no locks inside); never share mutable state across files. `Dataset.Calls()` results are shared and read-only.
- Commit subjects: short, capitalized, no period.

## Important Files

| File | Role |
|---|---|
| `internal/cli/cli.go` | package doc = command extension recipe, `Register`, `Main`, exit codes |
| `internal/cli/common.go`, `calls.go` | common flags and the model command (`NewCommand`, `Query`, `Open`, `Select`, `WriteTable`) |
| `internal/engine/engine.go` | the one composition of capture + sip + rtp + call |
| `internal/capture/{handler,read,decode,reassemble}.go` | handler contracts, concurrency, hand-written decode, fragment reassembly |
| `internal/sip/handler.go`, `parse.go` | TCP stream reassembly, forgiving parser |
| `internal/call/{build,analyze,media,attach,types}.go` | call state machine, timings, SDP media, RTP correlation (definitions in `Build`'s doc comment) |
| `internal/rtp/{handler,stream,quality}.go` | detection, RFC 3550 math, E-model |
| `internal/query/{builtin,parse,compile,help}.go` | built-in fields, grammar, `Help()` text behind `sipcurious fields` |
| `internal/analysis/registry.go`, `types.go` | rule registry, `Run`, `Config` thresholds |
| `internal/report/types.go` | `Table`, formats, `Write`/`WriteSections` |
| `testdata/samples/README.md` | ground truth of the demo captures |
| `docs/definitions.md` | user-facing definitions of every metric: update with the code |

## Runtime/Tooling Preferences

- Go toolchain only. Dependencies via Go modules; update with `go get` deliberately, never `dep`.
- Standard library first; the only third-party dependency is `github.com/gopacket/gopacket` (`layers`, `pcapgo`), used as a fallback for exotic link types and for pcapng reading. Keep `CGO_ENABLED=0` builds working (`make build-linux`).
- `tshark` and `tcpdump` are optional tools used to **derive expected values for tests**; tests that call them skip when missing. Nothing is downloaded at test time.

## Testing & QA

- stdlib `testing` only; table-driven with `t.Run`; no testify, no network, deterministic, no dependence on the local time zone (use `--utc`/explicit zones).
- **Fixtures.** `testdata/samples/*` are generated by `internal/pcaptest` (fixed seeds, byte-identical; `TestSamplesMatchCommitted` compares) and their facts (packets, messages, Call-IDs, resent messages, RTP streams, loss, jitter, timings) are documented in `testdata/samples/README.md`. `testdata/realworld/*` are third-party and derived captures; `testdata/README.md` has sources, licences and what each exercises. Build ad-hoc captures in tests with `pcaptest.New(start, seed)` (`Call`, `Register`, `Options`, `Raw`, `PCAP`, `PCAPNG`).
- **Ground-truth rule.** Expected values for real captures come from `tshark`/`tcpdump`/an independent byte scan, **never from sipcurious's own output**. Where sipcurious intentionally differs from tshark (e.g. telephone-event packets excluded from jitter, streams under 5 packets not reported), the test comments say so; keep that practice and update `docs/definitions.md`.
- **Golden and property tests.** `internal/flow` keeps golden diagrams; `props_test.go` files compare against brute-force references; fuzz targets exist for every parser and writer (`go test -fuzz`; keep found crashers in `testdata/fuzz`).
- **Performance expectations** (Apple M6, `-benchtime 3x`, see `docs/architecture.md`): capture decode about 30 M pkts/s with no handler and about 8 M pkts/s with the SIP handler on a 1M-packet file; RTP about 41 ns per packet with zero steady-state allocations; `call.Build` about 6 M msgs/s for ordered input; compiled filters about 55 M msgs/s with 0 allocs. A change that makes a benchmark noticeably slower or allocate on the hot path needs a reason.
- CI runs `gofmt -l .`, `go vet ./...` and `go test -race ./...` on Linux, macOS and Windows; there is no coverage threshold. Releases are cut by pushing a `vX.Y.Z` tag (`.github/workflows/release.yml`).
- After a behaviour change update the matching doc: `docs/query.md` examples carry real match counts, `docs/definitions.md` carries the metric definitions, `docs/usage.md` and `docs/cookbook.md` quote real output (re-run the commands), `CHANGELOG.md` the user-visible change.

## Pitfalls

- **`status` and `method` of a response**: `method` is taken from the CSeq, so `method = INVITE` also matches `200 OK` to the INVITE. Use `is_request` to restrict.
- **Query scopes**: in `calls`, message-field conditions are existential per call and judged independently; call fields in `messages` come from the message's call. Negation applies to the existential result (`not status >= 500` = no 5xx at all).
- **Null semantics**: absent data (pdd of an unanswered call, status of a request) matches no comparison, so `!=`, `!~`, `not in` are true for it.
- **RTP needs 5 packets** to become a stream and correlates to calls only through SDP endpoints; `--no-rtp` or a query without call fields skips RTP entirely.
- **TCP/TLS/WebSocket**: SIP over TCP is reassembled; TLS and WebSocket SIP are not decoded (see `docs/capture-formats.md`).
- **Export needs seekable files** (inputs are read twice); stdin must be spooled by the caller.
- **Time**: table output uses the local zone unless `--utc`; tests and docs use `--utc`.
- **Sibling packages are shared contracts** (`trace`, `capture` handler types, `call` types): a change ripples through every command; update all callers, do not add shims or aliases.
- Do not hand-edit generated parts of docs (`docs/query.md` reference section is the output of `sipcurious fields`).
