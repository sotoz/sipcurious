# sipcurious

[![CI](https://github.com/sotoz/sipcurious/actions/workflows/ci.yml/badge.svg)](https://github.com/sotoz/sipcurious/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

**Sipcurious answers "what happened to this call, and why?" from a pcap.** It reads SIP and RTP from pcap/pcapng files (also gzipped, or from stdin), groups the messages into calls, measures the media, runs diagnostic rules and prints the answer as tables, ladder diagrams, a one-page report or a trimmed pcap you can send to the vendor. One static binary, pure Go (no libpcap, no tshark), fast enough for multi-GB captures.

## Quickstart (60 seconds)

Install, with one of:

```sh
go install github.com/sotoz/sipcurious/cmd/sipcurious@latest          # needs Go 1.27+
```

```sh
git clone https://github.com/sotoz/sipcurious && cd sipcurious        # from source
make build                                                            # ./sipcurious (or: go build -o sipcurious ./cmd/sipcurious)
```

Or download a prebuilt binary (linux, macOS, windows; amd64 and arm64) from the [releases page](https://github.com/sotoz/sipcurious/releases), verify it against `SHA256SUMS` and unpack it:

```sh
tar xzf sipcurious_v2.0.0_linux_amd64.tar.gz && sudo install sipcurious_*/sipcurious /usr/local/bin/
```

Then, on any capture (the repository ships demo captures in `testdata/samples`):

```sh
sipcurious calls trace.pcap                  # one row per call: state, result, PDD, talk time, MOS
sipcurious diagnose trace.pcap               # what is wrong, worst first
sipcurious flow --callid 0jv0hk3er8 trace.pcap   # the ladder diagram of one call
tcpdump -i eth0 -w - port 5060 | sipcurious calls -   # straight from a live capture
```

Shell completion: `source <(sipcurious completion bash)` (zsh and fish: [docs/usage.md](docs/usage.md#shell-completion)).

## What it answers

| You ask | Command | What you get |
|---|---|---|
| **Which calls failed, and why?** | `calls --failed`, `diagnose`, `messages --status 4xx` | state and final response per call; findings with evidence, a hint and packet numbers; 21 rules: failed, unanswered, retransmissions, auth loops, register flapping, missing ACK, 488/SDP mismatch, loops, forking, slow setup... |
| **Is the audio bad?** | `rtp --bad`, `calls --sort mos`, `diagnose` | per-stream loss, jitter, max gap, reordering, DTMF and an estimated MOS; one-way audio, no audio and NAT suspicion detected from SDP versus actual RTP |
| **Show me the call flow** | `flow` | ASCII, Mermaid or SVG ladder with timings, retransmissions, SDP codecs and the RTP streams; `show` for full message text |
| **How is the system doing?** | `stats` | ASR/ACD, PDD/setup/talk percentiles, peak concurrent calls and CPS, failure classes, top callers/callees, user agents, codecs |
| **Give me a clean pcap for the vendor** | `export` | a new pcap/pcapng with only the SIP and RTP of the matching calls, byte for byte |
| **Give me a one-pager** | `report` | one self-contained HTML (or Markdown) file: summary, findings, calls, a ladder per call |
| **Find one thing in a huge capture** | `messages`, `--where` | a typed filter language: `from ~ alice and status >= 500`, `duration > 30s and not has_media`, CIDR, regex, any header |
| **Gate my pipeline** | `diagnose --fail-on error` | exit code 3 when a finding at that severity exists |

Also: pcap, pcapng, gzip, stdin, directories and globs (merged by time); Ethernet, VLAN/Q-in-Q, Linux cooked, raw IP, IP-in-IP/GRE; IPv4/IPv6 with fragment reassembly; SIP over UDP, TCP (reassembled) and SCTP on any port; `table`, `csv`, `json`, `ndjson`, `markdown`, `html` output everywhere.

## Examples

All outputs are real, from the demo captures in [`testdata/samples`](testdata/samples/README.md) (`--utc` pins the time zone).

**Which calls failed?**

```
$ sipcurious calls --utc --failed testdata/samples/busy-and-reject.pcap
sipcurious: read 1 file, 13 packets, 13 SIP messages, 0 RTP streams in 0s
sipcurious: 3 calls matched
Calls
Start                     Duration  Kind  State   Result         From   To           PDD  Setup  Talk  Codec  MOS  Call-ID
2026-03-04T10:00:00.000Z  48.528ms  call  failed  486 Busy Here  alice  bob     44.471ms               PCMU        p98a67hlvnj047u3@10.0.1.10
2026-03-04T10:00:05.000Z    1.007s  call  failed  603 Decline    carol  dave    43.789ms               PCMU        k4c4no2o3jug0m0o@10.0.1.10
2026-03-04T10:00:10.000Z  47.693ms  call  failed  404 Not Found  erin   nobody  43.711ms               PCMU        gvpckwvdgxqtbev0@10.0.1.10
```

**What is wrong?** (the summary goes to stderr, the findings to stdout)

```
$ sipcurious diagnose --utc testdata/samples/bad-media.pcap
sipcurious: read 1 file, 803 packets, 21 SIP messages, 3 RTP streams in 0s
sipcurious: 3 errors, 0 warnings, 0 info (3 calls checked)
Findings
Severity  Rule           Call-ID                     Time                      Title
error     media-quality  gjsqxqhsuw6y4rox@10.0.1.10  2026-03-04T10:00:02.114Z  Poor media quality callee->caller: MOS 1.7, loss 39.3%, gap 1.965s
error     one-way-media  3ysto1i3gfo77fpr@10.0.1.10  2026-03-04T10:00:12.018Z  One-way audio: only caller->callee RTP captured, nothing callee->caller
error     no-media       ybfuxqgimm86dtek@10.0.1.10  2026-03-04T10:00:22.003Z  Call erin -> frank answered but no RTP was captured (PCMU, telephone-event)
```

**Why? Add `--extra`** for the evidence, a hint and the packet numbers (excerpt):

```
$ sipcurious diagnose --utc --extra -q testdata/samples/nat-problem.pcap
vfj72cutpqa46bgf@192.168.1.50  alice -> bob  completed 200 OK
  WARNING nat-suspected  2026-03-04T10:00:00.000Z  NAT suspected for alice -> bob: Contact <sip:alice@192.168.1.50:5060> in INVITE from a public source
          Contact <sip:alice@192.168.1.50:5060> in INVITE from public 203.0.113.10, Via 192.168.1.50 in INVITE from public 203.0.113.10, SDP audio 192.168.1.50/14284 in INVITE from public 203.0.113.10, ... (+1 more).
          hint: Private addresses leak to the public side, so in-dialog requests and media will go to unreachable addresses: enable rport/received handling, NAT keep-alives ...
```

**The ladder**, with the media streams:

```
$ sipcurious flow --utc -q testdata/samples/basic-call.pcap
Call-ID: 0jv0hk3er8amef7w@10.0.1.10
From: "Alice" <sip:alice@example.com>;tag=dqwwxy7m3n -> To: "Bob" <sip:bob@example.com>
Time: 2026-03-04T10:00:00.000Z  duration 7.011s  7 msgs
State: completed  Result: 200 OK  PDD 0.052s  setup 2.003s  talk 5.004s  ended by caller (BYE)
UA: Yealink SIP-T46S 66.85.0.5; Asterisk PBX 20.5.0

  10.0.1.10:5060                              10.0.2.20:5060
     (Yealink)                                  (Asterisk)
         |                                           |
         |----------------- INVITE ----------------->|         +0.000s
         |<--------------- 100 Trying ---------------|         +0.004s
         |<-------------- 180 Ringing ---------------|         +0.052s
         |<----------------- 200 OK -----------------|         +2.003s  (gap 1.951s)
         |------------------ ACK ------------------->|         +2.007s
         |<~ RTP PCMU 250 pkts, loss 0.0%, MOS 4.39 ~|         +2.013s
         |~ RTP PCMU 250 pkts, loss 0.0%, MOS 4.39 ~>|         +2.017s
         |------------------ BYE ------------------->|         +7.007s  (gap 5.000s)
         |<----------------- 200 OK -----------------|         +7.011s
         |                                           |
```

`-F mermaid` renders in GitHub and GitLab, `-F svg -o call.svg` makes an image.

**Is the audio bad?**

```
$ sipcurious rtp --utc -q --bad testdata/samples/bad-media.pcap
RTP streams
Start                     Duration  Src              Dst              SSRC        Codec  Packets  Lost  Loss%    Jitter  JitterMax  MaxGap   MOS  DTMF  Call-ID                     Leg
2026-03-04T10:00:02.114Z    6.173s  10.0.2.20:14714  10.0.1.10:47810  0xBAD00002  PCMU       182   118  39.33  26.552ms   38.131ms  1.965s  1.74        gjsqxqhsuw6y4rox@10.0.1.10  callee->caller
```

**How is the system doing?** (`stats`, excerpt of a 10-minute busy hour)

```
$ sipcurious stats --utc -q --no-rtp --top 3 testdata/samples/mixed-busy-hour.pcapng
overview
Metric                   Value
Duration                 10m18.8s
SIP messages             1100
Call-IDs                 164
INVITE attempts          155
Answered                 67
ASR %                    43.2
Adjusted ASR %           63.2
ACD                      13.962s
Peak concurrent calls    5 at 2026-03-04T10:05:23.914Z
Peak INVITEs per second  2 at 2026-03-04T10:05:54.896Z
...
failures
Kind  State   Code  Reason               Count  Sample Call-ID
call  failed   486  Busy Here               24  k3zyy0d7mv4ts2pz@10.0.1.46
call  failed   404  Not Found               18  a7ehy2aknvjipafe@10.0.1.38
call  failed   503  Service Unavailable     13  75y9xpwqsd921vsb@10.0.1.27
...
```

**A clean pcap for the vendor** (the original packets of one call, SIP and its RTP, byte for byte):

```
$ sipcurious export --callid bnvcw0zf0i6ci9es -o one.pcapng testdata/samples/b2bua-two-legs.pcap
sipcurious: read 1 file, 816 packets, 14 SIP messages, 4 RTP streams in 0s
sipcurious: 1 call matched
sipcurious: exported 408 packets (7 SIP, 401 media) of 1 call to one.pcapng, 103244 bytes
```

**The one-page report** (`report -o report.html`, no screenshot here): a single self-contained HTML file without external resources. From top to bottom: a summary block (capture span, packets, SIP messages, calls, ASR, ACD, peak concurrency, PDD p95, RTP streams, mean MOS, calls without media), the findings table sorted worst first, the calls table, one section per call with the call facts and its ladder diagram as an inline SVG including the RTP streams, and the full statistics sections; the tables have a filter box. `-F markdown` produces the same content as Markdown with text ladders, ready to paste into a ticket:

```
$ sipcurious report --utc -F markdown -o report.md testdata/samples/bad-media.pcap
sipcurious: report: 3 calls, 3 errors, 0 warnings, 0 info
```

More scenarios (NAT, registration loops, B2BUA legs, hold, TCP, IPv6, capacity, CI): [docs/cookbook.md](docs/cookbook.md).

## Commands

`sipcurious help` is the authoritative list, `sipcurious help <command>` the flags of one command; the full reference is [docs/usage.md](docs/usage.md).

| Command | Purpose |
|---|---|
| `calls` (`dialogs`) | one row per call (Call-ID): kind, state, result, PDD, setup, talk, codec, MOS |
| `messages` (`search`, `grep`) | one row per SIP message; `--count`, `--unique` |
| `show` | full text of the matching messages; `--headers-only`, `--sdp-only` |
| `flow` (`ladder`) | ladder diagram per call: ASCII, Mermaid, SVG |
| `diagnose` (`check`) | diagnostic rules, worst findings first; `--fail-on` for CI |
| `rtp` (`streams`) | RTP streams: codec, loss, jitter, gaps, MOS, DTMF |
| `stats` | ASR/ACD, timings, peak concurrency and CPS, methods, codes, failures, top-N |
| `export` | new pcap/pcapng with only the packets of the matching calls |
| `report` | self-contained HTML or Markdown troubleshooting report |
| `rules` | list the diagnostic rules; `rules ID` explains one; `--docs` prints all as Markdown |
| `fields` | the filter language and the fields usable in `--where` |
| `completion` | shell completion script for bash, zsh, fish |
| `version`, `help` | version and build info; help |

Every capture command takes `FILE...`, directories, shell globs or `-` (stdin) and the common flags: `--where/-w`, `--from`, `--to`, `--callid`, `--uri`, `--method`, `--status`, `--src-ip`, `--dst-ip`, `--since`, `--until`, `--format/-F`, `--output/-o`, `--utc`, `--color`, `--limit`, `--no-rtp`, `--quiet/-q`. Data goes to stdout; the summary and errors to stderr. Exit codes: 0 ok (also "no matches"), 1 runtime error, 2 usage error, 3 findings at or above `--fail-on`.

## Documentation

| Document | Contents |
|---|---|
| [docs/usage.md](docs/usage.md) | every command and flag, input handling, output formats, colour, environment, completion, piping recipes, exit codes |
| [docs/cookbook.md](docs/cookbook.md) | 17 troubleshooting scenarios with real output: one-way audio, NAT, registration loops, 486/603/404, missing ACK, B2BUA legs, hold, TCP, IPv6, capacity, vendor export, report, CI, jq |
| [docs/query.md](docs/query.md) | the `--where` filter language with examples |
| [docs/definitions.md](docs/definitions.md) | how every metric is defined: states, PDD/setup/talk, ASR/ACD, loss, jitter, MOS, correlation |
| [docs/capture-formats.md](docs/capture-formats.md) | supported containers, link types, tunnels, TCP/fragments, what is not supported |
| [docs/architecture.md](docs/architecture.md) | layers, concurrency, performance, how to add a protocol, rule, field, command or format |
| [testdata/samples/README.md](testdata/samples/README.md) | the demo captures and their verified facts |
| [CHANGELOG.md](CHANGELOG.md) | release notes and the migration from v1 |

## Limitations

- **Read-only, offline:** files and stdin; no live capture (pipe `tcpdump -w -`).
- **No TLS/SRTP decryption, no WebSocket SIP:** encrypted signalling is not found; decrypt first. SRTP headers are measured, the payload is opaque. See [docs/capture-formats.md](docs/capture-formats.md#what-is-not-supported).
- **Media quality is an estimate at the capture point:** the MOS is an E-model estimate from loss, jitter and codec, good for ranking streams, not a measurement of what the user heard. RTP needs 5 continuous packets to count as a stream and is matched to calls through the SDP endpoints (no SDP in the capture, no correlation).
- **B2BUA/SBC legs are separate calls** (one Call-ID per leg); correlate them with a header such as `X-CID` through `--where`.
- **Non-SIP VoIP** (H.323, MGCP, SCCP, IAX2) is ignored.
- The diagnostic rules are heuristics: read the evidence and the hint, not just the title.

## Contributing

Pull requests are welcome.

```sh
make all        # go vet, go test, build: must pass
make cover      # coverage report
make dist       # cross-compiled release artifacts into ./dist (set PLATFORMS=... to narrow)
gofmt -l .      # must print nothing
```

- Standard library plus `gopacket` only; keep `CGO_ENABLED=0` builds working. Do not run `go mod tidy` or edit `go.mod` without a reason.
- **Fixtures:** tests are deterministic and offline. The synthetic captures in `testdata/samples` come from `internal/pcaptest` (`go run ./internal/pcaptest/cmd/gensamples`; a test compares them byte for byte) and their facts come from tshark/tcpdump, never from sipcurious itself. `testdata/realworld` holds real third-party captures with provenance in [testdata/README.md](testdata/README.md). `tshark` and `tcpdump` are optional: tests that use them skip when they are missing.
- **Extending:** a new diagnostic rule, filter field, command, output format or protocol is one file against a registry, without touching existing code; compiling recipes are in [docs/architecture.md](docs/architecture.md#extension-recipes). Update [docs/definitions.md](docs/definitions.md) and [CHANGELOG.md](CHANGELOG.md) with the behaviour change; conventions and pitfalls are in [AGENTS.md](AGENTS.md).

## License

Copyright Sotiris Gkanouris 2018. Licensed under the GNU General Public License v3, see [LICENSE](LICENSE).
