# Usage reference

The command reference below is derived from the real output of `sipcurious help` and `sipcurious help <command>` (the binary is the authority: if this page and `help` disagree, `help` wins). Examples run on the demo captures in `testdata/samples`.

- [Synopsis](#synopsis)
- [Input handling](#input-handling)
- [Common flags](#common-flags)
- [Commands](#commands)
- [Output formats](#output-formats)
- [Colour](#colour)
- [Time](#time)
- [Exit codes](#exit-codes)
- [Environment variables](#environment-variables)
- [Shell completion](#shell-completion)
- [Piping recipes](#piping-recipes)

## Synopsis

```
sipcurious - troubleshoot SIP/VoIP calls from pcap files

Usage:
  sipcurious <command> [flags] [capture files, directories or - for stdin]

Inspect:
  calls       list the calls (one row per Call-ID) with state, timings and media quality (alias: dialogs)
  flow        draw a ladder diagram (ASCII, Mermaid or SVG) of every matching call (alias: ladder)
  messages    list the SIP messages matching the filters, one row each (alias: search, grep)
  show        print the matching SIP messages as full text

Analyze:
  diagnose    run the diagnostic rules (failed calls, retransmissions, NAT, media quality, ...) and list the findings (alias: check)
  rtp         list the RTP streams with codec, loss, jitter, gaps and MOS (alias: streams)
  stats       capture-wide statistics: ASR/ACD, timings, SIP methods and codes, failures, RTP quality

Share:
  export      write a new pcap/pcapng with only the packets (SIP and media) of the matching calls
  report      write one self-contained troubleshooting report (HTML or Markdown): summary, findings, calls with ladders

Reference:
  fields      print the filter language and the fields usable in --where
  rules       list the diagnostic rules of 'diagnose'; 'rules ID' explains one, --docs all

General:
  completion  print a shell completion script (bash, zsh or fish)
  help        show help for sipcurious or one command
  version     print the version, Go version and VCS revision

Run 'sipcurious help <command>' for the flags of a command, and
'sipcurious fields' for the filter language used by --where.

Exit codes: 0 ok, 1 runtime error, 2 usage error, 3 findings at or above --fail-on.
Data is written to stdout; summaries, warnings and errors go to stderr.
```

The command name must come first. `sipcurious <command> --help` and `sipcurious help <command>` are equivalent; an unknown command or flag exits with code 2 and suggests the closest match.

## Input handling

Captures are given as positional arguments or with `-f/--file` (repeatable; both can be mixed).

| Input | Behaviour |
|---|---|
| a file | pcap (micro/nanosecond, either byte order) or pcapng, detected by magic number, not by extension |
| gzip file | `.gz` or any gzip stream, detected by the `1f 8b` magic, decompressed on the fly |
| a directory | walked recursively for `*.pcap`, `*.pcapng`, `*.cap`, `*.pcap.gz`, `*.pcapng.gz` in lexical order |
| shell glob | expanded by your shell: `sipcurious calls trunk-a/*.pcap` |
| `-` | standard input (pcap, pcapng or gzip): `tcpdump -w - ... \| sipcurious calls -` |
| several of the above | read in parallel (one goroutine per file) and merged by capture time |

- `export` reads its inputs twice, so it first spools standard input to a temporary file (you need disk space for the whole stream); every other command reads stdin once.
- A capture cut off mid-record is read up to the cut and a warning is printed; the exit code stays 0.
- SIP is recognised by content on any port (UDP, TCP with stream reassembly, SCTP), IPv4 and IPv6; TLS and WebSocket SIP cannot be decoded. See [capture-formats.md](capture-formats.md) for link types, tunnels, fragments and limitations.
- RTP/RTCP are detected on any UDP port without SDP help and correlated to calls through the SDP endpoints. `--no-rtp` skips the media analysis entirely (much faster on big captures; `calls` then shows no MOS). Commands that need no call data skip it automatically.
- Data goes to stdout (or `-o FILE`); the summary line, warnings and errors go to stderr with a `sipcurious: ` prefix. `-q` silences the summary and warnings.

## Common flags

Every capture command accepts these (the descriptions are the ones printed by `help`; in `flow`, `stats`, `export` and `report` some of them have a command-specific meaning, noted in the command sections):

| Flag | Meaning |
|---|---|
| `--callid TEXT` | Call-ID contains TEXT |
| `--case-sensitive` | match text case-sensitively |
| `--color string` | colorize output: auto, always or never (default auto) |
| `--dst-ip IP` | destination IP or CIDR |
| `--extra` | show the extra columns |
| `-f, --file FILE` | capture FILE (repeatable; same as a positional argument) |
| `-F, --format FORMAT` | output FORMAT: table, csv, json, ndjson, markdown, html (default table) |
| `--from TEXT` | From header contains TEXT |
| `--limit N` | show at most N rows (0 = all) |
| `--method METHOD` | SIP METHOD (INVITE, BYE, ...; responses match by their CSeq method) |
| `--no-rtp` | skip RTP analysis (faster; no media quality) |
| `-o, --output FILE` | write the result to FILE instead of stdout |
| `-q, --quiet` | no summary line or warnings on stderr |
| `--since TIME` | only messages at or after TIME (RFC 3339, 'YYYY-MM-DD HH:MM:SS' or HH:MM[:SS]) |
| `--src-ip IP` | source IP or CIDR |
| `--status CODE` | response status CODE or class (486, 4xx) |
| `--to TEXT` | To header contains TEXT |
| `--until TIME` | only messages at or before TIME (same formats as --since) |
| `--uri TEXT` | Request-URI contains TEXT |
| `--utc` | print times in UTC instead of the local zone |
| `-w, --where EXPR` | filter EXPR, e.g. 'status >= 500 and from ~ alice' (see 'sipcurious fields') |

Notes:

- All filter flags (`--from`, `--to`, `--callid`, `--uri`, `--method`, `--status`, `--src-ip`, `--dst-ip`, `--since`, `--until`, `-w/--where`) are **ANDed**. `--from`, `--to`, `--callid`, `--uri` are case-insensitive substring matches on the whole header value unless `--case-sensitive`.
- `--where` takes the full filter language: [query.md](query.md) or `sipcurious fields`. Message-level conditions select a call when any of its messages matches; call-level fields (`state`, `duration`, `mos`, ...) describe the whole call.
- `--since/--until` accept RFC 3339 (`2026-03-04T10:00:05Z`), `YYYY-MM-DD HH:MM:SS`, or a bare time of day `HH:MM[:SS]` (on the day of the message).
- `--status` takes a code (`486`) or a class (`4xx`).
- `--limit N` caps the rows shown (0 = all). The summary line still counts everything matched.
- `--extra` adds columns to the table output (for `messages`: Src, Dst, Contact, URI, File#Index, UA); CSV/JSON always carry all columns. For `diagnose` it switches the table to a per-call report.
- `-o FILE` writes the result to `FILE` instead of stdout (required by `export` and `report`).

## Commands

### `messages`

```
sipcurious messages [flags] CAPTURE...
```

list the SIP messages matching the filters, one row each
Aliases: search, grep

Command-specific flags (plus the [common flags](#common-flags)):

| Flag | Meaning |
|---|---|
| `--count` | print only the number of matching messages |
| `--unique` | only the first matching message of every Call-ID |

### `show`

```
sipcurious show [flags] CAPTURE...
```

print the matching SIP messages as full text

Command-specific flags (plus the [common flags](#common-flags)):

| Flag | Meaning |
|---|---|
| `--headers-only` | omit the message bodies |
| `--sdp-only` | print only the SDP of messages that carry one |

### `calls`

```
sipcurious calls [flags] CAPTURE...
```

list the calls (one row per Call-ID) with state, timings and media quality
Aliases: dialogs

Command-specific flags (plus the [common flags](#common-flags)):

| Flag | Meaning |
|---|---|
| `--answered` | only answered calls (answered or completed) |
| `--failed` | only calls that failed or got no response |
| `--kind KIND` | only calls of this KIND: call, registration, subscription, message, options, other |
| `--sort FIELD` | sort by FIELD: start, duration, pdd, setup, mos (duration, pdd and setup longest first, mos worst first) (default start) |
| `--state STATE` | only calls in this STATE: in-setup, no-response, cancelled, redirected, failed, answered, completed, ok |
| `--top N` | keep only the first N calls after sorting |

### `flow`

```
sipcurious flow [flags] CAPTURE...
```

draw a ladder diagram (ASCII, Mermaid or SVG) of every matching call
Aliases: ladder

Command-specific flags (plus the [common flags](#common-flags)):

| Flag | Meaning |
|---|---|
| `--absolute` | label arrows with the time of day instead of the offset from the call start |
| `-F, --format FORMAT` | output FORMAT: ascii, mermaid, svg (default ascii) |
| `--max-label N` | cut arrow labels to N characters (0 = default 48) |
| `--media` | add the correlated RTP streams (needs RTP analysis, so not with --no-rtp) (default true) |
| `--sdp` | annotate messages with SDP codecs and media address |
| `--sort FIELD` | sort calls by FIELD: start, duration, pdd, setup, mos (default start) |
| `--top N` | draw only the first N calls after sorting |

### `stats`

```
sipcurious stats [flags] CAPTURE...
```

capture-wide statistics: ASR/ACD, timings, SIP methods and codes, failures, RTP quality

Command-specific flags (plus the [common flags](#common-flags)):

| Flag | Meaning |
|---|---|
| `-F, --format FORMAT` | output FORMAT: table, json, markdown, html (default table) |
| `--top N` | keep at most N rows in every section (0 = the built-in ten) |

### `diagnose`

```
sipcurious diagnose [flags] CAPTURE...
```

run the diagnostic rules (failed calls, retransmissions, NAT, media quality, ...) and list the findings

Runs every rule of 'sipcurious rules' over the capture and lists the findings,
worst first. The default table has one row per finding: Severity, Rule, Call-ID,
Time and Title. With --extra the table format switches to a report grouped per
call (the call first, then each finding with its explanation, hint and packet
numbers indented below it); the machine formats (csv, json, ndjson) always
carry Detail, Hint and Packets. The summary line goes to stderr.

--where and the other filters select calls: findings of matching calls are
shown, and so are the capture-wide ones unless --calls-only is given.

Exit codes: 0 ok, 1 error, 2 usage, 3 with --fail-on when a finding of that
severity or worse exists.
Aliases: check

Command-specific flags (plus the [common flags](#common-flags)):

| Flag | Meaning |
|---|---|
| `--calls-only` | with a call filter, also drop the capture-wide findings |
| `--disable IDS` | do not run these rules, comma separated IDS |
| `--fail-on SEVERITY` | exit with code 3 when a finding has at least this SEVERITY: warning, error, never (default never) |
| `--long-call DUR` | report calls talking longer than DUR (0 = off) (default 0s) |
| `--max-gap DUR` | report streams with a gap between packets above DUR (default 1s) |
| `--max-jitter DUR` | report streams with a mean jitter above DUR (default 30ms) |
| `--max-loss PCT` | report streams with packet loss above PCT percent (default 1) |
| `--min-mos F` | report streams with a MOS below F (default 3.6) |
| `--min-retransmits N` | report requests retransmitted at least N times (default 2) |
| `--min-severity SEVERITY` | hide findings below this SEVERITY: info, warning, error (default info) |
| `--rules IDS` | run only these rules, comma separated IDS (see 'sipcurious rules') |
| `--slow-pdd DUR` | report a post-dial delay above DUR (default 3s) |
| `--slow-setup DUR` | report a call setup (INVITE to 200 OK) above DUR (default 10s) |

### `rtp`

```
sipcurious rtp [flags] CAPTURE...
```

list the RTP streams with codec, loss, jitter, gaps and MOS
Aliases: streams

Command-specific flags (plus the [common flags](#common-flags)):

| Flag | Meaning |
|---|---|
| `--bad` | only streams breaching the quality thresholds (--min-mos, --max-loss, --max-jitter, --max-gap) |
| `--max-gap DUR` | report streams with a gap between packets above DUR (default 1s) |
| `--max-jitter DUR` | report streams with a mean jitter above DUR (default 30ms) |
| `--max-loss PCT` | report streams with packet loss above PCT percent (default 1) |
| `--min-mos F` | report streams with a MOS below F (default 3.6) |
| `--min-packets N` | hide streams with fewer than N packets |
| `--sort FIELD` | sort by FIELD: start, mos, loss, jitter (mos worst first, loss and jitter highest first) (default start) |
| `--uncorrelated` | also list streams that belong to no call (when filtering by call with --where) |

### `export`

```
sipcurious export [flags] -o OUT.pcapng CAPTURE...
```

write a new pcap/pcapng with only the packets (SIP and media) of the matching calls

Command-specific flags (plus the [common flags](#common-flags)):

| Flag | Meaning |
|---|---|
| `-F, --format FORMAT` | output FORMAT: pcapng, pcap (default pcapng) |
| `--no-media` | leave the RTP/RTCP out, export the signalling only |

### `report`

```
sipcurious report [flags] -o REPORT.html CAPTURE...
```

write one self-contained troubleshooting report (HTML or Markdown): summary, findings, calls with ladders

Command-specific flags (plus the [common flags](#common-flags)):

| Flag | Meaning |
|---|---|
| `-F, --format FORMAT` | output FORMAT: html, markdown (default html) |
| `--generated RFC3339` | generation time RFC3339 shown in the report (default: $SIPCURIOUS_NOW, else now) |
| `--long-call DUR` | report calls talking longer than DUR (0 = off) (default 0s) |
| `--max-calls N` | describe at most N calls in detail; the rest is summarised (0 = no calls) (default 200) |
| `--max-gap DUR` | report streams with a gap between packets above DUR (default 1s) |
| `--max-jitter DUR` | report streams with a mean jitter above DUR (default 30ms) |
| `--max-loss PCT` | report streams with packet loss above PCT percent (default 1) |
| `--min-mos F` | report streams with a MOS below F (default 3.6) |
| `--min-retransmits N` | report requests retransmitted at least N times (default 2) |
| `--slow-pdd DUR` | report a post-dial delay above DUR (default 3s) |
| `--slow-setup DUR` | report a call setup (INVITE to 200 OK) above DUR (default 10s) |
| `--title TITLE` | report TITLE (default SIP troubleshooting report) |

### Notes per command

**`messages`** — one row per SIP message, with `Timestamp  Info  Call-ID  From  To`. `--count` prints just the number on stdout (script-friendly), `--unique` keeps the first matching message of every Call-ID.

**`show`** — the full text of every matching message, headers and body, preceded by `#<packet> file time src -> dst`. Pair it with `--sdp-only` to compare offer/answer, or `--headers-only` for readable signalling.

**`calls`** — one row per Call-ID with Kind, State, final Result, From/To, PDD, Setup, Talk, Codec and the worst MOS of the call. States are `in-setup`, `no-response`, `cancelled`, `redirected`, `failed`, `answered`, `completed` (answered and ended with BYE) and `ok` (non-INVITE transactions). `--failed` is "failed or no-response"; `--answered` is "answered or completed". Definitions of every column: [definitions.md](definitions.md).

**`flow`** — `ascii` (default, for the terminal), `mermaid` (paste into GitHub/GitLab/Markdown) or `svg` (standalone image; use with `-o`). `--sdp` annotates codecs and media addresses, `--absolute` labels arrows with the time of day, `--media=false` hides the RTP lines, `--max-label N` shortens labels. One diagram per matching call: combine with `--top`/`--sort` or `-w` to avoid thousands of diagrams.

**`stats`** — capture-wide ASR/ACD, PDD/ring/setup/talk percentiles, peak concurrent calls and peak INVITEs per second, methods, status codes, transports, user agents, call states, failures, top callers/callees, codecs, worst RTP streams. `--top N` sets the rows per section (default 10). JSON is an object with one array per section (`overview`, `sip_methods`, ...).

**`diagnose`** — the full description is in its section above. Rule thresholds are flags (`--slow-pdd`, `--slow-setup`, `--max-loss`, `--max-jitter`, `--max-gap`, `--min-mos`, `--min-retransmits`, `--long-call`); `--rules` and `--disable` select rules by ID. `sipcurious rules` lists all of them, `sipcurious rules media-quality` explains one, `sipcurious rules --docs` prints every rule as Markdown.

**`rtp`** — one row per RTP stream with codec, packets, loss, jitter, max gap, MOS, DTMF digits, and the owning Call-ID and leg. MOS is an E-model estimate at the capture point: use it to rank streams, not as a measurement ([definitions.md](definitions.md)). `--bad` applies the same thresholds as `diagnose`.

**`export`** — writes a new capture with only the packets of the matching calls: the SIP messages and (unless `--no-media`) their correlated RTP/RTCP, byte for byte (original timestamps, link types). Standard input is spooled to a temporary file first. The output extension does not matter, `-F pcap|pcapng` decides.

**`report`** — one self-contained file: summary, findings, calls table and, per call, the ladder diagram, then the statistics sections. `html` has no external resources (one inline SVG ladder per call, inline JavaScript only for the table filter boxes); `markdown` embeds the ladders as text. `--max-calls` bounds the detail, `--title` sets the title, `--generated`/`$SIPCURIOUS_NOW` pin the generation time for reproducible output.

**`rules`**, **`fields`**, **`completion`**, **`version`** — reference commands; they read no capture.

```
sipcurious rules [--docs] [--format FORMAT] [ID]
sipcurious fields
sipcurious completion bash|zsh|fish
sipcurious version
```

`rules -F json` is the machine-readable rule list (`rule`, `severity`, `title`).

## Output formats

| Command | `--format` values (default first) |
|---|---|
| `messages`, `calls`, `rtp` | `table`, `csv`, `json`, `ndjson`, `markdown`, `html` |
| `diagnose` | `table`, `csv`, `json`, `ndjson`, `markdown`, `html` (machine formats also carry `detail`, `hint`, `packets`) |
| `stats` | `table`, `json`, `markdown`, `html` |
| `flow` | `ascii`, `mermaid`, `svg` |
| `show` | `text` only (any other `--format` is a usage error, exit 2) |
| `export` | `pcapng`, `pcap` |
| `report` | `html`, `markdown` |
| `rules` | `table`, `csv`, `json`, `ndjson`, `markdown`, `html` |

- `json` is one array; `ndjson` one object per line (streaming friendly); `csv` has a header row. Field names are lower snake case (`call_id`, `duration_ms`, `pdd_ms`, `file_index`); JSON/CSV keep the full captured precision and the table keeps milliseconds.
- Everything that came from the capture is sanitised: control characters and invalid UTF-8 never reach the terminal, HTML, Markdown or CSV (a malicious Call-ID cannot inject escape sequences).
- `markdown` and `html` tables are meant to be pasted into tickets or wikis.

## Colour

`--color auto|always|never` (default `auto`). Colour is applied to table output (header names bold; states, severities and MOS green/red) and to `show` (header names bold); CSV, JSON, ndjson, ladders and exports are never coloured. `auto` colours only when stdout is a terminal. `NO_COLOR` (any non-empty value) and `TERM=dumb` disable `auto`; `--color always` overrides them. Use `--color always` with `less -R` to page coloured output.

## Time

Table output prints times in the local zone with millisecond precision; add `--utc` to print UTC (do this in tickets and scripts, so everybody sees the same clock). Internally everything is UTC. Ladder arrows show the offset from the call start (`+2.003s`), or the time of day with `flow --absolute`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success, **including "no matches"** |
| 1 | runtime error: unreadable capture, write failure |
| 2 | usage error: unknown command or flag, bad `--where` expression, invalid value |
| 3 | `diagnose --fail-on SEVERITY`: a finding at or above that severity exists |
| 130 | interrupted (Ctrl-C) |

Real examples:

```
$ sipcurious diagnose --fail-on error -q testdata/samples/bad-media.pcap; echo "exit=$?"
...
exit=3
$ sipcurious calls --bogus
sipcurious: flag provided but not defined: -bogus (see 'sipcurious help calls')
$ sipcurious calls /nonexistent.pcap; echo "exit=$?"
sipcurious: stat /nonexistent.pcap: no such file or directory
exit=1
```

`--fail-on` accepts `warning`, `error` or `never` (default). `-q` hides the stderr summary only; the findings table is still data on stdout (send it away with `> /dev/null` or keep it as the CI log).

## Environment variables

| Variable | Effect |
|---|---|
| `NO_COLOR` | any non-empty value turns `--color auto` off ([no-color.org](https://no-color.org)) |
| `TERM=dumb` | same as `NO_COLOR` |
| `SIPCURIOUS_NOW` | RFC 3339 time used as the "Generated" time of `report` when `--generated` is not given; makes reports byte-reproducible (`SIPCURIOUS_NOW=2026-03-04T12:00:00Z`) |
| `TZ` | selects the local zone used for table output without `--utc` |

There is no configuration file.

## Shell completion

`sipcurious completion bash|zsh|fish` prints a script that completes commands, flags and the values of flags such as `--format`, `--state`, `--kind`, `--sort` and `--rules`.

**bash** (needs the `bash-completion` package):

```sh
# current shell
source <(sipcurious completion bash)
# permanent
sipcurious completion bash > ~/.local/share/bash-completion/completions/sipcurious
# or system-wide
sipcurious completion bash | sudo tee /etc/bash_completion.d/sipcurious > /dev/null
```

**zsh**:

```sh
# current shell
source <(sipcurious completion zsh)
# permanent: put it on the fpath before compinit, e.g.
mkdir -p ~/.zfunc && sipcurious completion zsh > ~/.zfunc/_sipcurious
# and in ~/.zshrc, before 'compinit':  fpath=(~/.zfunc $fpath)
```

**fish**:

```sh
sipcurious completion fish | source                                    # current shell
sipcurious completion fish > ~/.config/fish/completions/sipcurious.fish # permanent
```

Homebrew users can write the file into `$(brew --prefix)/share/zsh/site-functions/_sipcurious` or `$(brew --prefix)/etc/bash_completion.d/sipcurious`.

## Piping recipes

Data is on stdout, the summary on stderr, so pipes stay clean.

```sh
# live capture straight into the analysis (stop with Ctrl-C; tcpdump flushes with -U)
sudo tcpdump -i eth0 -U -w - 'port 5060 or udp portrange 10000-20000' | sipcurious calls -

# a gzipped capture, or several, no unpacking
sipcurious calls trace.pcap.gz other.pcapng
zcat big.pcap.gz | sipcurious diagnose -

# only the number of matching messages
sipcurious messages --count -w 'status >= 500' trace.pcap

# worst five calls by MOS, as JSON, with jq
sipcurious calls --sort mos --top 5 -F json -q trace.pcap | jq -r '.[] | [.call_id, .mos, .from, .to] | @tsv'

# failure histogram by final response (see the cookbook for the real output)
sipcurious calls -F json -q trace.pcap | jq -r '[.[]|select(.state=="failed")]|group_by(.result)|map("\(length)\t\(.[0].result)")|.[]'

# findings of severity error as CSV for a spreadsheet
sipcurious diagnose --min-severity error -F csv -q trace.pcap > findings.csv

# stream NDJSON into another tool
sipcurious messages -F ndjson -q trace.pcap | jq -c 'select(.method=="INVITE")'

# page the coloured table
sipcurious calls --color always trace.pcap | less -R

# one call as Mermaid, to paste into an issue
sipcurious flow --callid 0jv0hk3er8amef7w -F mermaid trace.pcap
```

More worked scenarios: [cookbook.md](cookbook.md).
