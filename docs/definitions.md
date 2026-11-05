# Definitions: what the numbers mean

Everything sipcurious reports is derived from what is **in the capture**. A capture is a view from one point of the network, possibly incomplete,
so every definition below says what happens when an event was not captured: the value is then zero/empty (shown as an empty cell, omitted in JSON), never a guess.
The authoritative text is the doc comments of `internal/call`, `internal/stats` and `internal/rtp` (`go doc -all ./internal/call`, ...).

## Calls

A **call** is every SIP message that shares one **Call-ID** (messages without a Call-ID are ignored). The word is used for registrations and OPTIONS too; `Kind` tells them apart.
Messages of a call are chronological (stable for equal timestamps). Several hops of one call through a proxy carry the same Call-ID and are one call.
A B2BUA or SBC creates a **new Call-ID per leg**; legs are separate calls (they can be linked by a shared header such as `X-CID`, see `Options.CorrelateHeaders` / `Call.Related`).

### Kind

Decided by the **first request** of the Call-ID:

| Kind | First request |
|---|---|
| `call` | INVITE, or an in-dialog ACK, BYE, CANCEL, PRACK, UPDATE, INFO (a call that started before the capture) |
| `registration` | REGISTER |
| `subscription` | SUBSCRIBE, NOTIFY, REFER |
| `message` | MESSAGE |
| `options` | OPTIONS (keep-alives, health checks) |
| `other` | anything else |

A Call-ID with only responses is classified by the method in the CSeq of its first response and has an empty `Method`.

### Transactions and the deciding response

Messages are matched to transactions by CSeq number, From tag and CSeq method, so responses to CANCEL, BYE, PRACK, UPDATE, INFO and re-INVITEs never influence the outcome of call set-up.
For `call` the initial transactions are the INVITEs **without a To tag** (response-only INVITE transactions stand in when no request was captured); for other kinds they are the transactions of the first request's method.
The **deciding** transaction is the latest initial one that got any response. The **final response** of a transaction is its first 2xx, otherwise its last response >= 300 (with forking the last failure is what the caller saw).
So REGISTER 401 then REGISTER 200 is `ok`, REGISTER 401 then 403 is `failed` (403), and a retry after a 401/407 that was never answered stays `failed` (401/407). `FinalCode`, `FinalReason` and `Result` ("`<code> <reason>`") describe that final response; `attempts` counts initial transactions (2 after an authentication round).

### State

| State | Meaning |
|---|---|
| `completed` | a 2xx to an INVITE was seen **and** a BYE (or a response to one) |
| `answered` | a 2xx to an INVITE was seen, no BYE: still up, or the capture ended |
| `cancelled` | the final response is 487 and a CANCEL was seen, or no final response and a CANCEL was seen |
| `failed` | any other final response >= 400 (also a 487 without a CANCEL; any other final after a CANCEL) |
| `redirected` | the final response is 3xx |
| `no-response` | the request never got any response (all retransmissions included); for non-INVITE kinds also "provisional only" |
| `in-setup` | only provisional responses were seen (even just `100 Trying`), the capture ended |
| `ok` | non-INVITE transaction (registration, options, ...) got a 2xx |

For INVITE calls the first matching rule wins: a 2xx to **any** INVITE makes the call `answered`/`completed` (first 2xx wins; a fork answering later, or a 487 from another fork, does not change it). Also `answered` when the INVITE got no response at all but an ACK for a 2xx
(a branch different from every INVITE branch) was captured. A BYE with no 2xx or final response captured is `completed` with no final code (the answer was lost or the BYE crossed it).
A capture that starts mid-call has no initial INVITE: `completed` if a BYE is seen, `cancelled` if CANCEL, otherwise `answered` (a re-INVITE or UPDATE only proves an established dialog).
`Caller` and `Callee` are the source and destination of the first initial request and are empty for calls captured mid-dialog.

`--failed` selects `failed` and `no-response`; `--answered` selects `answered` and `completed`.

### Timings

Only for INVITE calls, and zero (empty) when the events were not captured. **T0** is the first initial INVITE (not the retry after a 401/407 challenge).

| Name | From | To |
|---|---|---|
| **PDD** (post-dial delay) | T0 | first 101-199 response **other than** `100 Trying`; or the final response when that came first or no ringing was seen |
| **ring time** | that first provisional response | first 2xx, or the final response (zero without one) |
| **setup time** | T0 | first 2xx |
| **talk time** | first 2xx (`Answered`) | first BYE (`Ended`) |
| **duration** | first message of the Call-ID | last message of the Call-ID (includes retransmissions, the BYE transaction and any trailing traffic) |

The 2xx used for setup is the first one **captured**: with a proxy that sees both hops, that is the one nearest the capture point. Times are capture timestamps at the capture point, not the endpoints' clocks.
The `pdd`, `setup_time`, `ring_time`, `talk_time` filter fields are null for calls where they are zero, so `pdd > 3s` never matches an unanswered call and `pdd != 3s` is true for it (see [query.md](query.md)).

### Ended by, end method, reason

- **`end_method`**: `BYE` or `CANCEL`, empty if neither was seen.
- **`ended_by`** (who sent the first BYE) is decided from the **dialog tags**, because source addresses lie behind proxies, SBCs and NAT: the sender is the `caller` if its From tag equals the From tag of the initial INVITE (or of the first ACK/response when the INVITE was not captured), the `callee` if its From tag differs or its To tag equals the caller's tag. Without tags the exact source address:port is compared with the INVITE's source and destination, then the address alone. It stays empty when undecidable. For CANCEL it is always `caller`.
- **`reason`** is the `Reason` header (RFC 3326; several joined by ", ") of the terminating message: the first BYE, or the CANCEL (falling back to the 487), or the failure/redirect response.

### Retransmissions and missing ACK

A message is a **retransmission** when it repeats an earlier message with the same kind, method or status, CSeq, topmost Via `branch`, source and destination (for responses also the To tag and, for provisional ones, RSeq). The first copy is the original; every further copy counts. The call's `retransmissions` field is that count.
Consequences worth knowing: the same request seen on two hops (client-proxy and proxy-server) is **not** a retransmission because source/destination differ; a retransmission that crosses a different branch (a new transaction after a timeout) is not either.
`missing ACK` is set when the 2xx to the INVITE was retransmitted and no ACK for it was captured, i.e. the caller never confirmed the answer (RFC 3261 timers G/H). `forks` is the number of distinct To tags in the 101-299 responses of the deciding INVITE.

### User agents

`User-Agent` of requests and `Server` of responses (each falling back to the other header), distinct, first seen first. In the `calls` tables the extra column joins them with `; `.

## Capture-wide statistics (`internal/stats`)

An **attempt** is a call of kind `call` whose initial INVITE was captured. Calls that start mid-dialog and non-INVITE Call-IDs are never attempts. An **answered** call is an attempt in state `answered` or `completed`.

| Metric | Definition |
|---|---|
| **ASR** (answer-seizure ratio, ITU-T E.411) | 100 x answered / attempts. Cancelled, unanswered and in-setup attempts stay in the denominator |
| **Adjusted ASR** | 100 x answered / (attempts - user-caused failures); a user-caused failure is an attempt in state `failed` with final response 486, 480, 404 or 603 |
| **ACD** (average call duration) | mean **talk time** of the *completed* calls. Calls still up at the end of the capture have no known duration and are left out |
| **Peak concurrent calls** | sweep line over [answered, end] of every answered call, end = first BYE or, when none was captured, the last message of the call. Intervals that only touch do not overlap; a zero-length interval counts as one nanosecond |
| **Peak INVITE attempts per second** | largest number of attempts whose first INVITE falls into a window [t, t+1 s) starting at an attempt |
| **Percentiles** (p50/p90/p95/p99) | nearest rank: the p-th percentile of n sorted values is the value at 1-based rank ceil(p x n / 100). PDD, ring and setup time are taken over answered attempts with a positive value; talk time over completed calls |

A metric that cannot be computed is 0 (check the count next to it, e.g. attempts), never NaN.

## RTP

### Detection

No SDP is required. A UDP datagram is **RTP-like** when it has version 2, a plausible payload type (RFC 3551 static 0-18 and 25-34, dynamic 96-127), a consistent CSRC list and header extension and its second byte is not in 192..223 (that is RTCP, RFC 5761). STUN and DTLS cannot pass the version check. A flow keyed by (source, destination, **SSRC**) becomes a **stream** once it has `MinPackets` (default **5**) packets with plausibly continuous sequence numbers (each step forward at most 100); a change of SSRC on the same 4-tuple starts a new stream.
Consequences: a stream shorter than 5 packets is not reported (the 134 three-packet streams of `testdata/samples/mixed-busy-hour.pcapng` are invisible, which is why `has_media` is false for those calls); on any port, including ports that look like something else; SRTP is detected as well (the header is cleartext).
RTCP (SR/RR) is parsed and aggregated by SSRC (`Stream.RTCP`: report count, highest fraction lost, highest jitter, last cumulative loss), including RTCP multiplexed on the RTP port. Streams are unidirectional: one call normally has two.

### Per-stream numbers

Computed on the extended (wrap-aware) sequence numbers per RFC 3550 appendix A.3 / A.8:

- **packets** counts every RTP packet including duplicates and telephone-event packets; **bytes** is payload only.
- **expected / lost**: expected = highest extended sequence - first + 1; **lost = expected - received** (can be negative when duplicates arrive); **loss %** = 100 x max(lost, 0) / expected. A sender restart (two in-sequence packets after a jump of 100..65436 positions backwards or more than 3000 forward) closes the current sequence segment and opens a new one - the jump itself is neither loss nor expected. An isolated packet with a wild sequence number counts as one expected and one received packet. **DTX/comfort-noise gaps do not move sequence numbers, so they are not loss**; they show up in `max gap`.
- **duplicates, reordered** follow the same recurrence.
- **jitter** is the RFC 3550 A.8 interarrival jitter, in time, using the clock rate of the stream's payload type: SDP hint (when set), else the static table (G.722 is always 8000 as RFC 3551 prescribes), else estimated from timestamp and arrival progression and snapped to the nearest of 8000, 16000, 32000, 44100, 48000, 90000 Hz. **Mean** is the average of the running estimate; **max** is its maximum. Telephone-event packets, duplicates and stray packets are excluded; a transit step above 2 s (sender re-based its timestamps) re-baselines instead of counting.
- **max gap** is the largest interval between consecutive packets (a 2 s silence from a failed leg shows here even without sequence loss).
- **DTMF events** (RFC 4733) are the number of distinct telephone-event events; those packets are excluded from jitter/loss maths.
- **payload type / codec** is the most frequent payload type that is not telephone-event or comfort noise.

What this is **not**: jitter and loss are what arrived **at the capture point**. If you capture near the sender you measure the sender's side, not what the receiver's jitter buffer experienced; network loss after the capture point is invisible.

### Differences from tshark

The package tests compare against `tshark -q -z rtp,streams` on real captures (packets, lost, max delta equal; jitter within 2 microseconds). The intended differences are:

- **Telephone-event packets**: tshark includes them in jitter and then reports a bogus value (their timestamps jump per event); sipcurious excludes them. Example: `features-sll-nanos.pcap`, tshark mean jitter on the stream carrying DTMF is 2.29 ms (max 26.3 ms) although the audio is clean; sipcurious reports below 0.5 ms for that call (`calls -w 'jitter > 0.5ms'` matches nothing).
- **Mean jitter of the H.263 sample** (`wireshark-h263-over-rtp.pcap`): tshark 15.505 ms against 17.659 ms here (12 % apart): the same recurrence, but tshark averages the per-packet jitter including the zero-valued start. Max jitter, packet count and loss are identical.
- **Streams under 5 packets** are not reported (tshark lists a 2-packet stream in the Asterisk sample).
- **SRTCP-like** sender reports (readable first 8 bytes, encrypted rest) are counted here, tshark does not dissect them.

### MOS and R factor: an estimate

`mos` and `r_factor` are computed from the stream's loss % and mean jitter with a **simplified ITU-T G.107 E-model** (`rtp.Quality`):

```
R   = 93.2 - Id - Ie_eff
Ie_eff = Ie + (95 - Ie) * Ppl / (Ppl + Bpl)       Ppl = loss %, Ie and Bpl from the codec (G.113 where defined)
Id  = 0.024 d + 0.11 (d - 177.3) H(d - 177.3)      d = 40 ms + 2 x mean jitter
MOS = 1 + 0.035 R + 7e-6 R (R - 60)(100 - R)       clamped to 1.0 .. 4.5
```

Assumptions: no noise, no echo, no advantage factor (Ro - Is = 93.2); loss is random (burstiness is not modelled, so bursty loss is rated **better** than it feels); the one-way delay is 40 ms of packetisation/algorithmic/playout plus twice the jitter (an adaptive jitter buffer); propagation delay cannot be seen from one capture point and is **not** included; late loss is not added.
Unknown or dynamic codecs and the G.711/G.722/L16 family are rated as G.711 with packet-loss concealment (Ie 0, Bpl 25.1); G.729 (Ie 11, Bpl 19), GSM (20, 10), G.723.1, G.726/G.728, iLBC, Opus, Speex, AMR use their own factors, some of them approximations marked in the source.

Reference values the function returns (from running it):

| Codec | Loss | Mean jitter | R | MOS |
|---|---:|---:|---:|---:|
| PCMU | 0 % | 0 | 92.2 | 4.39 |
| PCMU | 1 % | 0 | 88.6 | 4.30 |
| PCMU | 5 % | 0 | 76.5 | 3.88 |
| PCMU | 10 % | 0 | 65.2 | 3.36 |
| PCMU | 0 % | 100 ms | 80.5 | 4.04 |
| G.729 | 0 % | 0 | 81.2 | 4.07 |
| G.729 | 5 % | 0 | 63.7 | 3.29 |

Use it to **rank and compare** streams inside one capture, not as a measured MOS. A stream with telephone-event only has no MOS (0 / empty). A call's `mos`, `loss` and `jitter` fields are the **worst** over the call's streams (lowest MOS, highest loss, highest mean jitter) and are null when no stream is correlated. The demo `bad-media.pcap` shows the effect: 39.3 % loss and 26.6 ms mean jitter give MOS 1.74, a clean PCMU stream 4.39.

## Correlating RTP with calls (`call.Attach`)

There is no SDP-free guess: a stream belongs to a call only through the **media endpoints announced in the call's SDP** (IP and port from `c=`/`m=`, one `Media` entry per offer/answer; delayed offer, re-INVITE, early media in 18x, multipart bodies and `UPDATE`/`PRACK` are followed).

A stream matches a call when **its source or its destination is an announced endpoint** (at any time) **and** its time span overlaps the call's media window: from the first SDP description minus `AttachSlack` (5 s) to the last message of the call plus 5 s (unbounded when the call was answered and no BYE was captured). Match quality, best first:

1. both ends are the two announced endpoints (either direction);
2. the destination is an announced endpoint (the receiver told us where it listens; the source may be NATed or asymmetric);
3. the source is an announced endpoint.

A stream is attached to **at most one call**; ties between calls are resolved by quality, then largest time overlap, then narrowest window, then the window starting closest to the stream, then the earliest call. This keeps consecutive calls that reuse the same gateway ports apart.
`leg` is `caller->callee` when the stream flows from the caller's announced endpoint toward the callee's, else `callee->caller`.

Limits:

- **No SDP, no correlation.** Streams whose call's SDP is not in the capture (call set-up before the capture started, SDP in a TLS-protected signalling stream, signalling on a different capture point) stay uncorrelated; they appear in capture-wide RTP statistics but in no call. The call then reports `has_media = false`, which is also what a real "no audio" looks like - compare with the capture-wide stream count.
- **NAT and SBC.** The SDP address is what the endpoint **announced**. A NATed phone announcing a private address (`nat-problem.pcap`: SDP `192.168.1.50`, packets from `203.0.113.10`) is matched through the receiving side's endpoint, which is why rule 2 exists; if both ends are rewritten by a middlebox that is not visible in the SDP, nothing matches. B2BUA legs are separate calls with separate endpoints (`b2bua-two-legs.pcap`: 4 streams, 2 per leg).
- **Several calls sharing one media endpoint** (gateways with fixed ports) rely on the time overlap; overlapping calls on the same ports can be mis-assigned.
- **Hold**: a hold re-INVITE is recorded (`Media.Hold`: sendonly/inactive or a `0.0.0.0` connection address) but does not split streams; silence during hold shows as a gap, not as loss.
- Streams under 5 packets are never reported, so very short media bursts never attach.

## Timestamps and time zones

- Inside the program every time is **UTC**. Captures carry absolute timestamps (pcap seconds + micro/nanoseconds, pcapng with `if_tsresol`); nanosecond precision is kept internally.
- **Table, Markdown and HTML** output prints times as RFC 3339 with milliseconds in the **local time zone** of the machine running sipcurious (`2026-03-04T11:00:00.000+01:00`); `--utc` prints UTC with a `Z` (`2026-03-04T10:00:00.000Z`). **CSV, JSON and NDJSON** carry RFC 3339 with the **full sub-second precision as captured** and drop trailing zeros; `--utc` makes the zone `Z`, otherwise it is the local zone. Use `--utc` whenever output is compared across machines or attached to a ticket.
- Durations are human readable in table/Markdown/HTML (`51.749ms`, `2.003s`, `2m44.6s`); in CSV/JSON/NDJSON they are **numbers in milliseconds** in columns named `*_ms`.
- Filters: `time`, `start`, `end` compare absolute instants; `RFC 3339` values carry their own zone, `"2026-03-04 10:00:00"` and `2026-03-04` are **UTC**, and a bare `HH:MM[:SS]` is a time of day **on the day of the message (or call start)** in UTC. `--since/--until` take the same formats.
- Capture timestamps are the capture host's clock at the capture point; comparing captures from two hosts is only as good as their clock synchronisation. Messages of several files are merged by these timestamps.
