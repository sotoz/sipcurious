# Cookbook

Troubleshooting scenarios: a problem, the commands, how to read the answer. Every output below was produced by running the binary on the demo captures in [`testdata/samples`](../testdata/samples/README.md) (facts about them, verified with tshark: [README](../testdata/samples/README.md)); long lines and tables are trimmed with `…`. Commands use `--utc` so the times match yours, and `-q` to hide the stderr summary line. Flags: [usage.md](usage.md), filter language: [query.md](query.md), metric definitions: [definitions.md](definitions.md).

The demo captures are synthetic, so the numbers are tidy; real captures show the same columns.

| # | Problem | Capture |
|---|---|---|
| [1](#1-first-look-which-calls-failed-and-why) | First look: which calls failed and why | `busy-and-reject` |
| [2](#2-one-way-audio-or-no-audio) | One-way audio, no audio | `bad-media` |
| [3](#3-private-addresses-and-nat) | Audio fails behind NAT | `nat-problem` |
| [4](#4-poor-quality-mos-loss-jitter-gaps) | Poor quality: MOS, loss, jitter | `bad-media` |
| [5](#5-registration-failures) | Registration keeps failing | `auth-register` |
| [6](#6-calls-that-ring-forever-or-never-answer) | Calls that never get an answer | `no-answer-retransmits` |
| [7](#7-486-603-404-what-do-the-rejections-mean) | 486 / 603 / 404 analysis | `busy-and-reject` |
| [8](#8-the-ack-never-arrives) | The ACK never arrives | `missing-ack` |
| [9](#9-b2bua-or-sbc-both-legs-of-one-call) | B2BUA / SBC: both legs | `b2bua-two-legs` |
| [10](#10-hold-and-resume) | Hold and resume | `hold-resume` |
| [11](#11-sip-over-tcp) | SIP over TCP | `tcp-sip` |
| [12](#12-ipv6-and-vlan) | IPv6 and 802.1Q VLAN | `ipv6-vlan` |
| [13](#13-capacity-planning-asr-peak-concurrency-and-cps) | Capacity: ASR, concurrency, CPS | `mixed-busy-hour` |
| [14](#14-extract-one-call-for-the-vendor) | Extract one call for the vendor | `b2bua-two-legs` |
| [15](#15-a-shareable-report) | One-page report | `bad-media` |
| [16](#16-ci-gate-diagnose---fail-on) | CI gate | several |
| [17](#17-automation-with-json-and-jq) | Automation with JSON and jq | `mixed-busy-hour` |

## 1. First look: which calls failed and why

You have a capture and no idea what is in it. Two commands answer most of it: `calls` for the overview, `diagnose` for the explanation.

```
$ sipcurious calls --utc -q --failed testdata/samples/busy-and-reject.pcap
Calls
Start                     Duration  Kind  State   Result         From   To           PDD  Setup  Talk  Codec  MOS  Call-ID
2026-03-04T10:00:00.000Z  48.528ms  call  failed  486 Busy Here  alice  bob     44.471ms               PCMU        p98a67hlvnj047u3@10.0.1.10
2026-03-04T10:00:05.000Z    1.007s  call  failed  603 Decline    carol  dave    43.789ms               PCMU        k4c4no2o3jug0m0o@10.0.1.10
2026-03-04T10:00:10.000Z  47.693ms  call  failed  404 Not Found  erin   nobody  43.711ms               PCMU        gvpckwvdgxqtbev0@10.0.1.10
```

`--failed` keeps calls whose state is `failed` or `no-response`; `Result` is the final response to the first request. On a big capture sort by what hurts: `--sort duration --top 10`, `--sort pdd`, `--sort mos` (see [usage.md](usage.md#calls)).

```
$ sipcurious diagnose --utc -q testdata/samples/busy-and-reject.pcap
Findings
Severity  Rule         Call-ID                     Time                      Title
warning   call-failed  p98a67hlvnj047u3@10.0.1.10  2026-03-04T10:00:00.000Z  Call alice -> bob failed: 486 Busy Here
warning   call-failed  k4c4no2o3jug0m0o@10.0.1.10  2026-03-04T10:00:05.000Z  Call carol -> dave failed: 603 Decline
warning   call-failed  gvpckwvdgxqtbev0@10.0.1.10  2026-03-04T10:00:10.000Z  Call erin -> nobody failed: 404 Not Found
```

Findings are sorted worst first. For the reasoning and the next step add `--extra`: each finding gets its evidence, a hint and the packet numbers (open them in Wireshark with `frame.number in {…}`). `sipcurious rules call-failed` explains the rule and its severities.

## 2. One-way audio or no audio

"The customer hears nothing." Run `diagnose`, then look at the RTP streams of the call.

```
$ sipcurious diagnose --utc -q testdata/samples/bad-media.pcap
Findings
Severity  Rule           Call-ID                     Time                      Title
error     media-quality  gjsqxqhsuw6y4rox@10.0.1.10  2026-03-04T10:00:02.114Z  Poor media quality callee->caller: MOS 1.7, loss 39.3%, gap 1.965s
error     one-way-media  3ysto1i3gfo77fpr@10.0.1.10  2026-03-04T10:00:12.018Z  One-way audio: only caller->callee RTP captured, nothing callee->caller
error     no-media       ybfuxqgimm86dtek@10.0.1.10  2026-03-04T10:00:22.003Z  Call erin -> frank answered but no RTP was captured (PCMU, telephone-event)
```

Two different problems:

- **`one-way-media`**: RTP flowed in one direction only. The ladder shows which, and the SDP says where the other side should have sent its media:

  ```
  $ sipcurious flow --utc -q --callid 3ysto1i3gfo77fpr testdata/samples/bad-media.pcap
  …
           |------------------ ACK ------------------->|         +2.008s
           |~ RTP PCMU 300 pkts, loss 0.0%, MOS 4.39 ~>|         +2.018s
           |------------------ BYE ------------------->|         +8.008s  (gap 6.000s)
  …
  RTP streams:
    Direction       Codec  Packets  Loss  Jitter  MOS   Flow
    caller->callee  PCMU   300      0.0%  0s      4.39  10.0.1.10:20132 -> 10.0.2.21:18574
  ```

  No `callee->caller` line: nothing was captured from `10.0.2.21:18574`. `diagnose --extra` spells out the candidates: NAT or firewall blocking the return path, wrong or private address in the callee's SDP, a muted or crashed media process, RTP sent to another address. If the capture point is not on the callee's side of the network, also capture there: media that does not cross the capture point is invisible.
- **`no-media`**: the call was answered but *no* RTP matches the SDP endpoints (`has_media` is false). Check that you captured the media interface, that the RTP ports are not filtered out by your capture filter, and that the SDP addresses are reachable (private IPs behind NAT).

To list every answered call without audio in a large capture:

```
sipcurious calls --answered -w 'not has_media' trace.pcap
```

(`has_media` is a call field: an RTP stream was correlated to the call through its SDP endpoints. Streams of calls whose INVITE was before the capture started stay uncorrelated; see [definitions.md](definitions.md#correlating-rtp-with-calls-callattach).)

## 3. Private addresses and NAT

Calls connect, but media never arrives or arrives from somewhere else.

```
$ sipcurious diagnose --utc -q --extra testdata/samples/nat-problem.pcap
vfj72cutpqa46bgf@192.168.1.50  alice -> bob  completed 200 OK
  WARNING nat-suspected  2026-03-04T10:00:00.000Z  NAT suspected for alice -> bob: Contact <sip:alice@192.168.1.50:5060> in INVITE from a public source
          Contact <sip:alice@192.168.1.50:5060> in INVITE from public 203.0.113.10, Via 192.168.1.50 in INVITE from public 203.0.113.10, SDP audio 192.168.1.50/14284 in INVITE from public 203.0.113.10, … (+1 more).
          hint: Private addresses leak to the public side, so in-dialog requests and media will go to unreachable addresses: enable rport/received handling, NAT keep-alives and SIP ALG-free NAT traversal, or put an SBC with topology hiding and media latching in front of the device.
          packets: testdata/samples/nat-problem.pcap:1, testdata/samples/nat-problem.pcap:9, …
```

The packets come from `203.0.113.10` but the Contact, Via and SDP advertise `192.168.1.50`. Confirm in the RTP streams: the callee sends its media to the private address.

```
$ sipcurious rtp --utc -q testdata/samples/nat-problem.pcap
Start                     Duration  Src                 Dst                 SSRC        Codec  Packets  …  Call-ID                        Leg
2026-03-04T10:00:02.017Z     3.98s  10.0.2.20:43158     192.168.1.50:14284  0x4A700002  PCMU       200  …  vfj72cutpqa46bgf@192.168.1.50  callee->caller
2026-03-04T10:00:02.026Z     3.98s  203.0.113.10:14284  10.0.2.20:43158     0x4A700001  PCMU       200  …  vfj72cutpqa46bgf@192.168.1.50  caller->callee
```

`10.0.2.20:43158 -> 192.168.1.50:14284` is the unroutable stream; on the real network the caller hears nothing. `flow --sdp` shows the SDP address on every INVITE and 200 hop (`[audio PCMU,PCMA,telephone-event @192.168.1.50:14284]`), which is the evidence to hand to whoever runs the NAT or the proxy.

## 4. Poor quality: MOS, loss, jitter, gaps

```
$ sipcurious rtp --utc -q --bad testdata/samples/bad-media.pcap
RTP streams
Start                     Duration  Src              Dst              SSRC        Codec  Packets  Lost  Loss%    Jitter  JitterMax  MaxGap   MOS  DTMF  Call-ID                     Leg
2026-03-04T10:00:02.114Z    6.173s  10.0.2.20:14714  10.0.1.10:47810  0xBAD00002  PCMU       182   118  39.33  26.552ms   38.131ms  1.965s  1.74        gjsqxqhsuw6y4rox@10.0.1.10  callee->caller
```

`--bad` keeps only streams that breach `--min-mos` (3.6), `--max-loss` (1 %), `--max-jitter` (30 ms) or `--max-gap` (1 s); here 39 % loss, a 1.965 s hole and MOS 1.74 in the callee-to-caller direction. Rank the calls of a whole capture by their worst MOS:

```
$ sipcurious calls --utc -q --sort mos testdata/samples/bad-media.pcap
Calls
Start                     Duration  Kind  State      Result  From   To          PDD   Setup    Talk  Codec   MOS  Call-ID
2026-03-04T10:00:00.000Z    8.011s  call  completed  200 OK  alice  bob    91.199ms  2.003s  6.004s  PCMU   1.74  gjsqxqhsuw6y4rox@10.0.1.10
2026-03-04T10:00:10.000Z    8.012s  call  completed  200 OK  carol  dave   108.58ms  2.003s  6.005s  PCMU   4.39  3ysto1i3gfo77fpr@10.0.1.10
2026-03-04T10:00:20.000Z    8.014s  call  completed  200 OK  erin   frank  67.002ms  2.003s  6.007s  PCMU         ybfuxqgimm86dtek@10.0.1.10
```

The empty MOS of the last call means "no media", not "perfect". Reading the numbers: the MOS is an E-model estimate at the **capture point**: use it to rank streams, not as a measurement. Loss seen here may have happened before the capture point (compare captures on both sides of an SBC). Jitter is the RFC 3550 mean; a large `MaxGap` with little loss is silence suppression without comfort noise, a stalled media process or a hold (case 10). Tune the thresholds to your SLA: `diagnose --min-mos 4.0 --max-jitter 20ms`.

## 5. Registration failures

```
$ sipcurious calls --utc -q --kind registration testdata/samples/auth-register.pcap
Calls
Start                     Duration  Kind          State   Result         From   To     PDD  Setup  Talk  Codec  MOS  Call-ID
2026-03-04T10:00:00.000Z  40.884ms  registration  ok      200 OK         alice  alice                                kzehd5y775y8t67n@10.0.1.10
2026-03-04T10:00:02.000Z    8.176s  registration  failed  403 Forbidden  carol  carol                                dbu0naoa5iycvlsq@10.0.1.30

$ sipcurious diagnose --utc -q testdata/samples/auth-register.pcap
Findings
Severity  Rule               Call-ID                     Time                      Title
error     auth-failures      dbu0naoa5iycvlsq@10.0.1.30  2026-03-04T10:00:02.005Z  Authentication for carol refused 10 times (401, 403, 401, 403, 401, 403, 401, 403, 401, 403)
warning   register-flapping  dbu0naoa5iycvlsq@10.0.1.30  2026-03-04T10:00:02.000Z  carol@example.com registered 5 times, median 2.036s apart
```

Alice shows the healthy pattern: REGISTER, 401 challenge, REGISTER with credentials, 200 (`ok`). Carol retries every ~2 s and every authenticated attempt is answered 403: the credentials (or the account) are wrong, and the phone keeps hammering the registrar. Look at the actual responses:

```
$ sipcurious show --utc -q --headers-only -w 'status = 403' --limit 1 testdata/samples/auth-register.pcap
#8 testdata/samples/auth-register.pcap 2026-03-04T10:00:02.028Z 10.0.0.1:5060 -> 10.0.1.30:5060
SIP/2.0 403 Forbidden
Via: SIP/2.0/UDP 10.0.1.30:5060;rport=5060;branch=z9hG4bKknvw3h2lmb1z
From: <sip:carol@example.com>;tag=iqyyg0z2z4
To: <sip:carol@example.com>;tag=rw2v24ir3m
Call-ID: dbu0naoa5iycvlsq@10.0.1.30
CSeq: 433 REGISTER
Server: Kamailio (5.7.2)
Content-Length: 0
```

A 401 followed by a 200 is normal; `401` repeated forever is a stale nonce or a wrong password, `403` after credentials is a denied account or ACL, `407` is the same for a proxy. On a busy registrar, find the worst offenders: `sipcurious diagnose --rules auth-failures,register-flapping trace.pcap`.

## 6. Calls that ring forever or never answer

```
$ sipcurious diagnose --utc -q testdata/samples/no-answer-retransmits.pcap
Findings
Severity  Rule                 Call-ID                     Time                      Title
error     no-response          wry2nm78bsadglhu@10.0.1.10  2026-03-04T10:00:00.000Z  INVITE to 10.0.2.99:5060 got no response (7 transmissions)
error     sip-retransmissions  wry2nm78bsadglhu@10.0.1.10  2026-03-04T10:00:00.000Z  INVITE retransmitted 6 times without any response
error     call-failed          yeqyr359bj5pafkb@10.0.1.10  2026-03-04T10:00:02.000Z  Call carol -> dave failed: 408 Request Timeout
warning   slow-setup           yeqyr359bj5pafkb@10.0.1.10  2026-03-04T10:00:02.000Z  Post-dial delay 32.004s for carol -> dave (threshold 3s)
warning   sip-retransmissions  yeqyr359bj5pafkb@10.0.1.10  2026-03-04T10:00:02.003Z  INVITE retransmitted 6 times before the first response
```

```
$ sipcurious calls --utc -q testdata/samples/no-answer-retransmits.pcap
Start                     Duration  Kind  State        Result               From   To        PDD  Setup  Talk  Codec  MOS  Call-ID
2026-03-04T10:00:00.000Z     31.5s  call  no-response                       alice  bob                         PCMU        wry2nm78bsadglhu@10.0.1.10
2026-03-04T10:00:02.000Z   32.007s  call  failed       408 Request Timeout  carol  dave   32.004s               PCMU        yeqyr359bj5pafkb@10.0.1.10
```

- **`no-response`**: the INVITE was sent seven times (the original plus six retransmissions at +0.5, +1.5, +3.5, +7.5, +15.5, +31.5 s: RFC 3261 Timer A doubling until Timer B) and nothing ever answered: the next hop is down, unreachable, or a firewall drops the packets. The finding names the destination (`10.0.2.99:5060`).
- **408 after 32 s**: the first hop (a proxy) answered `100 Trying` but its own downstream never answered; the proxy retransmitted and finally gave up with 408. The problem is behind the proxy: capture on the proxy's outbound side.

To list every call that burned retransmissions in a larger capture: `sipcurious calls -w 'retransmissions >= 3' trace.pcap`. `calls --state no-response` lists the calls that never got any response.

## 7. 486, 603, 404: what do the rejections mean

```
$ sipcurious messages --utc -q --status 486 testdata/samples/busy-and-reject.pcap
SIP messages
Timestamp                 Info           Call-ID                     From                                            To
2026-03-04T10:00:00.044Z  486 Busy Here  p98a67hlvnj047u3@10.0.1.10  "Alice" <sip:alice@example.com>;tag=we3s4k5pti  "Bob" <sip:bob@example.com>;tag=9z6v199hb8
```

`--status` takes a code or a class (`4xx`), and `-w 'final_code = 5xx'` selects whole calls by their final response. What to conclude:

| Response | Meaning | First suspects |
|---|---|---|
| 486 Busy Here | the callee is busy | normal; if unexpected: call waiting off, line limit reached |
| 603 Decline | the callee (or its user) refused | the user hit "reject"; a DND or blocklist feature; PDD and ring time tell which: in the demo it rang for 1 s first (`PDD 43.789ms`, duration `1.007s`) |
| 404 Not Found | no such user or number | wrong dial plan, number not provisioned, routing to the wrong trunk |
| 480/503/408 | unavailable, overloaded, timeout | callee unregistered, trunk down or overloaded, no response behind a proxy (case 6) |

Count them across a capture (case 13 has the whole histogram). A single call with its full story:

```
sipcurious flow --callid k4c4no2o3jug0m0o testdata/samples/busy-and-reject.pcap
```

## 8. The ACK never arrives

```
$ sipcurious diagnose --utc -q testdata/samples/missing-ack.pcap
Findings
Severity  Rule         Call-ID                     Time                      Title
error     missing-ack  0sgmu3yvwctjbrd2@10.0.1.10  2026-03-04T10:00:02.003Z  200 OK for alice -> bob sent 11 times without an ACK
info      no-media                                 2026-03-04T10:00:02.003Z  No RTP in the capture: 1 call was answered with audio but media was not captured
```

```
$ sipcurious flow --utc -q testdata/samples/missing-ack.pcap
…
         |<------ 200 OK ------|         +2.003s  (gap 1.937s)
         |<- 200 OK (retrans) -|         +2.503s
         |<- 200 OK (retrans) -|         +3.503s
         |<- 200 OK (retrans) -|         +5.503s  (gap 2.000s)
         |<- 200 OK (retrans) -|         +9.503s  (gap 4.000s)
…
         |<- 200 OK (retrans) -|         +33.503s  (gap 4.000s)
         |<------- BYE --------|         +34.003s
         |------ 200 OK ------>|         +34.038s
```

The callee keeps retransmitting its 200 OK (Timer G, backing off to 4 s, until Timer H) because the caller's ACK never arrived, then hangs up with a BYE: the caller hears nothing for 32 s. Where is the ACK lost? The ACK follows the `Contact` of the 200 OK (or the Route set), not the INVITE's path: look at `sipcurious show --headers-only --method INVITE -w 'status = 200' …` for the Contact, and check that address is reachable from the caller (private Contact behind NAT, a firewall dropping the in-dialog request, an SBC without a record-route). `Calls` marks the call `completed` because it was answered and ended with BYE; the `missing-ack` finding is the signal.

## 9. B2BUA or SBC: both legs of one call

A back-to-back user agent creates a *new Call-ID per leg*, so a "call" is two rows. The two legs are only linked by what the SBC copies from one to the other: here an `X-CID` header.

```
$ sipcurious calls --utc -q testdata/samples/b2bua-two-legs.pcap
Calls
Start                     Duration  Kind  State      Result  From   To         PDD   Setup    Talk  Codec   MOS  Call-ID
2026-03-04T10:00:00.000Z    6.031s  call  completed  200 OK  alice  bob  104.976ms  2.012s  4.007s  PCMU   4.39  bnvcw0zf0i6ci9es@10.0.1.10
2026-03-04T10:00:00.003Z    6.023s  call  completed  200 OK  alice  bob   96.983ms  2.003s  4.016s  PCMU   4.39  ipswrcvyqf4jfonu@10.0.0.1
```

`--where` reads any header with `header.Name` (or `h.Name`). Given the correlation header of one leg you get both legs:

```
$ sipcurious calls --utc -q -w 'header.X-CID = SBC-7f3a91c2' testdata/samples/b2bua-two-legs.pcap
Calls
Start                     Duration  Kind  State      Result  From   To         PDD   Setup    Talk  Codec   MOS  Call-ID
2026-03-04T10:00:00.000Z    6.031s  call  completed  200 OK  alice  bob  104.976ms  2.012s  4.007s  PCMU   4.39  bnvcw0zf0i6ci9es@10.0.1.10
2026-03-04T10:00:00.003Z    6.023s  call  completed  200 OK  alice  bob   96.983ms  2.003s  4.016s  PCMU   4.39  ipswrcvyqf4jfonu@10.0.0.1
```

To discover the value without knowing it, find the INVITEs that carry the header at all:

```
$ sipcurious messages --utc -q -w 'h.X-CID ~ SBC' --unique testdata/samples/b2bua-two-legs.pcap
SIP messages
Timestamp                 Info    Call-ID                     From                                            To
2026-03-04T10:00:00.000Z  INVITE  bnvcw0zf0i6ci9es@10.0.1.10  "Alice" <sip:alice@example.com>;tag=wwgrm1yqt6  "Bob" <sip:bob@example.com>
2026-03-04T10:00:00.003Z  INVITE  ipswrcvyqf4jfonu@10.0.0.1   "Alice" <sip:alice@example.com>;tag=xamk8jida0  "Bob" <sip:bob@example.com>
```

Then `sipcurious flow -w 'header.X-CID = SBC-7f3a91c2' --sdp …` draws both legs one after the other (leg A is `10.0.1.10 <-> SBC 10.0.0.1`, leg B `10.0.0.1 <-> 10.0.2.20`, the media shows new ports and SSRCs on each leg), and `export -w 'header.X-CID = …'` takes both legs (case 14). Other correlation keys work the same way: `h.Session-ID`, `h.P-Charging-Vector ~ icid-value=…`, or the `From`/`To` user plus `--since/--until` when the SBC rewrites nothing. The flags available to select calls are in [usage.md](usage.md#common-flags): there is no dedicated "correlate" flag; the filter language is the mechanism.

Reading the two legs against each other localises a problem: if leg A has MOS 4.4 and leg B 2.1, the damage is between the SBC and the callee; the `BYE` sender on each leg (`ended_by`, shown in `flow`, in `calls -F json`) tells who hung up first.

## 10. Hold and resume

```
$ sipcurious diagnose --utc -q testdata/samples/hold-resume.pcap
Findings
Severity  Rule         Call-ID                     Time                      Title
info      hold-resume  px32wk5nthn92bu1@10.0.1.10  2026-03-04T10:00:04.012Z  Call alice -> bob put on hold and resumed (1 time)
info      hold-resume  uisk21dfk8enm092@10.0.1.10  2026-03-04T10:00:19.014Z  Call carol -> dave put on hold and resumed (1 time)
```

Nothing is wrong; the rule explains why those calls have a silence in the RTP (and a large `MaxGap`):

```
$ sipcurious rtp --utc -q testdata/samples/hold-resume.pcap
Start                     Duration  Src              Dst              SSRC        Codec  Packets  Lost  Loss%    Jitter  JitterMax  MaxGap   MOS  …
2026-03-04T10:00:02.013Z    5.993s  10.0.2.20:32832  10.0.1.10:40152  0x5449B9E9  G729       201     0     0  66.335µs    830.5µs  2.013s  4.07  …
2026-03-04T10:00:02.018Z     5.98s  10.0.1.10:40152  10.0.2.20:32832  0x0931D04E  G729       300     0     0        0s         0s    20ms  4.07  …
```

The callee→caller stream has a 2.013 s gap: the hold. `flow --sdp` marks the re-INVITEs: `[audio G729,PCMU,telephone-event @10.0.1.10:40152 hold]` then the answer `recvonly`, and the resume. To see the raw SDP of the hold (`a=sendonly`, or the old-style `c=0.0.0.0`):

```
$ sipcurious show --utc -q --sdp-only -w 'body ~ "a=sendonly"' testdata/samples/hold-resume.pcap
#206 testdata/samples/hold-resume.pcap 2026-03-04T10:00:04.008Z 10.0.1.10:5060 -> 10.0.2.20:5060
v=0
…
c=IN IP4 10.0.1.10
m=audio 40152 RTP/AVP 18 0 101
…
a=sendonly
```

A hold that is never followed by a resume (a `hold` marker on the last re-INVITE) explains "one-way audio after a transfer".

## 11. SIP over TCP

SIP segmented over several TCP segments, and several messages in one segment, are reassembled; you do not have to care.

```
$ sipcurious messages --utc -q -w 'transport = tcp' testdata/samples/tcp-sip.pcap
SIP messages
Timestamp                 Info         Call-ID                     From                                            To
2026-03-04T10:00:00.000Z  INVITE       6lxghkzqy4soaz9i@10.0.1.10  "Alice" <sip:alice@example.com>;tag=mw5ft1a0eo  "Bob" <sip:bob@example.com>
2026-03-04T10:00:00.079Z  100 Trying   6lxghkzqy4soaz9i@10.0.1.10  …
2026-03-04T10:00:00.079Z  180 Ringing  6lxghkzqy4soaz9i@10.0.1.10  …
…
```

11 messages from 10 TCP frames in this capture (the 100 and the 180 share one segment). The RTP (UDP) is still correlated with the TCP-signalled call:

```
$ sipcurious calls --utc -q testdata/samples/tcp-sip.pcap
Calls
Start                     Duration  Kind     State      Result  From   To                       PDD   Setup    Talk  Codec   MOS  Call-ID
2026-03-04T10:00:00.000Z    4.014s  call     completed  200 OK  alice  bob                  79.16ms  2.003s  2.006s  PCMU   4.39  6lxghkzqy4soaz9i@10.0.1.10
2026-03-04T10:00:08.000Z    5.006s  options  ok         200 OK  ping   <sip:10.0.0.1:5060>                                        8w4bs1rpzmxdw4n5@10.0.1.10
```

`--extra` adds the Src/Dst ports (a high ephemeral source port = client connection). **TLS is not decoded**: SIP on 5061/TLS yields no messages (the packets are counted as skipped in `stats`); capture on the plaintext side of the TLS terminator instead. See [capture-formats.md](capture-formats.md).

## 12. IPv6 and VLAN

All frames of `ipv6-vlan.pcap` carry an 802.1Q tag and IPv6 addresses; nothing special is needed.

```
$ sipcurious calls --utc -q testdata/samples/ipv6-vlan.pcap
Calls
Start                     Duration  Kind          State      Result  From   To                              PDD   Setup    Talk  Codec   MOS  Call-ID
2026-03-04T10:00:00.000Z   39.69ms  registration  ok         200 OK  alice  alice                                                             9ufhl5sm04bcbrzy@[2001:db8:1::10]
2026-03-04T10:00:02.000Z    5.028s  call          completed  200 OK  alice  bob                       106.287ms  2.007s  3.008s  PCMU   4.39  8td1bdxzv5zogzhz@[2001:db8:1::10]
2026-03-04T10:00:10.000Z    5.006s  options       ok         200 OK  ping   <sip:[2001:db8::1]:5060>                                          sb8lb0dhjqgzyajm@[2001:db8:1::10]
```

CIDR filters work for IPv6: `--src-ip 2001:db8:2::/48` selects what the callee side sent (`-w 'src in 2001:db8::/32'` is the equivalent expression). The ladder shows the three-hop chain:

```
$ sipcurious flow --utc -q -w 'kind = call' --no-rtp testdata/samples/ipv6-vlan.pcap
…
   [2001:db8:1::10]:5060  [2001:db8::1]:5060  [2001:db8:2::20]:5060
         (Yealink)            (Kamailio)           (Asterisk)
             |                     |                    |
             |------ INVITE ------>|                    |            +0.000s
             |<---- 100 Trying ----|                    |            +0.003s
             |                     |----- INVITE ------>|            +0.004s
…
```

Other link layers (Linux cooked SLL/SLL2, raw IP, BSD loopback, Q-in-Q, GRE/IP-in-IP tunnels) are read the same way: [capture-formats.md](capture-formats.md).

## 13. Capacity planning: ASR, peak concurrency and CPS

`stats` summarises a whole capture. The mixed busy-hour demo (1100 SIP messages in 10 minutes):

```
$ sipcurious stats --utc -q --no-rtp testdata/samples/mixed-busy-hour.pcapng
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
…
failures
Kind  State   Code  Reason               Count  Sample Call-ID
call  failed   486  Busy Here               24  k3zyy0d7mv4ts2pz@10.0.1.46
call  failed   404  Not Found               18  a7ehy2aknvjipafe@10.0.1.38
call  failed   503  Service Unavailable     13  75y9xpwqsd921vsb@10.0.1.27
call  failed   408  Request Timeout          8  hh6zkik2br0kfp9n@10.0.1.13
call  failed   603  Decline                  7  ag7jmztyc6yjn9mf@10.0.1.30
…
```

- **ASR** = answered / INVITE attempts (43.2 %); **Adjusted ASR** leaves out the user-caused failures (final 486, 480, 404 or 603), so it measures the network rather than the users. **ACD** is the mean talk time.
- **Peak concurrent calls** and **peak INVITEs per second** (CPS) with the time they happened are what you size trunks and the SBC license for. Zoom into the minute around a peak with `--since 10:05:00 --until 10:06:00` (a time of day on the capture date; the other sections then describe only that minute).
- `failures` names a sample Call-ID for every failure class; paste it into `sipcurious flow --callid …`.
- `timings` (PDD, ring, setup, talk with percentiles), `top_calling`/`top_called` (ASR per number), `user_agents` and `negotiated_codecs` follow in the same output; `--top N` sets the rows per section, `-F json|markdown|html` exports the sections.

Which calls dominate the failures?

```
$ sipcurious calls --utc -q --sort duration --top 3 --state failed testdata/samples/mixed-busy-hour.pcapng
Calls
Start                     Duration  Kind  State   Result               From   To     PDD  Setup  Talk  Codec  MOS  Call-ID
2026-03-04T10:02:52.845Z   32.008s  call  failed  408 Request Timeout  dave   carol  32.004s               opus        52gmcdzn2wmd2un3@10.0.1.46
2026-03-04T10:09:36.260Z   32.008s  call  failed  408 Request Timeout  alice  judy   32.004s               opus        vw66p0djwozd45m9@10.0.1.48
2026-03-04T10:00:20.101Z   32.008s  call  failed  408 Request Timeout  dave   bob    32.004s               opus        hh6zkik2br0kfp9n@10.0.1.13
```

(The demo's RTP is only 3 packets per stream, below the 5-packet detection minimum, so its media sections are empty; real captures fill `rtp_codecs`, `rtp_worst_loss` and `rtp_worst_jitter`.) Pass `--no-rtp` for a fast signalling-only pass over multi-GB captures.

## 14. Extract one call for the vendor

Send the vendor *only* the call in question, SIP and media, not your whole trace.

```
$ sipcurious export --utc --callid bnvcw0zf0i6ci9es -o /tmp/one.pcapng testdata/samples/b2bua-two-legs.pcap
sipcurious: read 1 file, 816 packets, 14 SIP messages, 4 RTP streams in 0s
sipcurious: 1 call matched
sipcurious: exported 408 packets (7 SIP, 401 media) of 1 call to /tmp/one.pcapng, 103244 bytes
$ sipcurious calls --utc -q /tmp/one.pcapng
Calls
Start                     Duration  Kind  State      Result  From   To         PDD   Setup    Talk  Codec   MOS  Call-ID
2026-03-04T10:00:00.000Z    6.031s  call  completed  200 OK  alice  bob  104.976ms  2.012s  4.007s  PCMU   4.39  bnvcw0zf0i6ci9es@10.0.1.10
```

The new capture contains the original packets byte for byte (timestamps and link layer preserved), so Wireshark shows what you saw. Only the media correlated to the call is included. Variants:

```
# both legs of the B2BUA (case 9), signalling only (no media, e.g. for a privacy-sensitive trace)
$ sipcurious export -w 'header.X-CID = SBC-7f3a91c2' --no-media -F pcap -o legs.pcap testdata/samples/b2bua-two-legs.pcap
sipcurious: exported 14 packets (14 SIP, 0 media) of 2 calls to legs.pcap, 6991 bytes

# every failed call of a capture, as pcapng (export takes the same filters as every command)
$ sipcurious export -q -w 'state = failed' -o failed.pcapng testdata/samples/busy-and-reject.pcap && sipcurious messages --count -q failed.pcapng
13
```

Mind privacy: media is voice. `--no-media` leaves RTP out; numbers and user names remain in the SIP headers. Export needs file inputs (stdin is spooled to a temporary file first).

## 15. A shareable report

```
$ SIPCURIOUS_NOW=2026-03-04T12:00:00Z sipcurious report --utc -F markdown --title "Demo" -o report.md testdata/samples/bad-media.pcap
sipcurious: read 1 file, 803 packets, 21 SIP messages, 3 RTP streams in 0s
sipcurious: report: 3 calls, 3 errors, 0 warnings, 0 info
$ head -32 report.md
# Demo

1 file, 2026-03-04T10:00:00.000Z to 2026-03-04T10:00:28.014Z \(UTC\): testdata/samples/bad-media.pcap

Generated 2026-03-04T12:00:00Z

## Summary

- **Capture duration**: 28.014s
- **Packets**: 803
- **SIP messages**: 21
- **Endpoints**: 4
- **Calls**: 3
- **ASR**: 100.0%
- **ACD**: 6.006s
- **Peak concurrent**: 1
- **PDD p95**: 108.58ms
- **RTP streams**: 3
- **MOS mean**: 3.51
- **Calls without media**: 1

Findings: 3 errors, 0 warnings, 0 info.

## Findings

| Severity | Rule | Call-ID | Time | Title |
| --- | --- | --- | --- | --- |
| error | media-quality | gjsqxqhsuw6y4rox@10.0.1.10 | 2026-03-04T10:00:02.114Z | Poor media quality callee-\>caller: MOS 1.7, loss 39.3%, gap 1.965s |
…
```

The default `-F html` (`report -o report.html …`) is one self-contained file you can attach to a ticket or mail: summary, findings, the calls table, one section per call with its ladder as an inline SVG, and the statistics sections; it needs no network (no external resources; a few lines of inline JavaScript give the tables a filter box). `--max-calls N` limits the per-call detail on big captures (the rest is summarised), `--title` names it, `--generated` / `SIPCURIOUS_NOW` pin the "Generated" time so the same capture gives a byte-identical report. Restrict it with the usual filters: `sipcurious report -w 'state = failed' -o failed.html trace.pcap`.

Individual pieces paste into tickets directly: `sipcurious diagnose -F markdown …`, `sipcurious stats -F markdown …`, `sipcurious flow -F mermaid …` (renders in GitHub/GitLab).

## 16. CI gate: `diagnose --fail-on`

A regression test that places calls through your system and captures the traffic can fail the pipeline when sipcurious sees a problem.

```
$ sipcurious diagnose --fail-on error -q testdata/samples/basic-call.pcap; echo "exit=$?"
Findings
Severity  Rule  Call-ID  Time  Title
exit=0
$ sipcurious diagnose --fail-on error -q testdata/samples/bad-media.pcap; echo "exit=$?"
Findings
Severity  Rule           Call-ID                     Time                           Title
error     media-quality  gjsqxqhsuw6y4rox@10.0.1.10  2026-03-04T11:00:02.114+01:00  Poor media quality callee->caller: MOS 1.7, loss 39.3%, gap 1.965s
error     one-way-media  3ysto1i3gfo77fpr@10.0.1.10  2026-03-04T11:00:12.018+01:00  One-way audio: only caller->callee RTP captured, nothing callee->caller
error     no-media       ybfuxqgimm86dtek@10.0.1.10  2026-03-04T11:00:22.003+01:00  Call erin -> frank answered but no RTP was captured (PCMU, telephone-event)
exit=3
$ sipcurious diagnose --fail-on warning -q testdata/samples/busy-and-reject.pcap > /dev/null; echo "exit=$?"
exit=3
$ sipcurious diagnose --fail-on error -q testdata/samples/busy-and-reject.pcap > /dev/null; echo "exit=$?"
exit=0
```

(The `+01:00` is the local zone of the machine that ran the example; add `--utc` for UTC.) Exit 3 means "findings at or above that severity", exit 1 an unreadable capture, exit 2 a usage error, so a CI job can tell a failing test from a broken setup. A typical step:

```yaml
- run: |
    sipcurious diagnose --utc --fail-on error --min-severity warning \
      --rules no-media,one-way-media,media-quality,missing-ack,sdp-mismatch \
      -F markdown -o findings.md capture.pcap || { cat findings.md; exit 1; }
```

Pin the checks to the rules you care about with `--rules`/`--disable` (`sipcurious rules` lists them), and the thresholds to your SLA (`--min-mos 4.0 --max-loss 0.5 --slow-pdd 2s`). Failed calls are expected in a negative test: scope them out with `-w 'to !~ nobody'` (`diagnose` keeps the findings of matching calls) or `--calls-only`.

## 17. Automation with JSON and jq

Every table has `json` and `ndjson` formats with stable lower-snake-case keys. The first failed call of the busy-hour capture:

```
$ sipcurious calls --failed -F json -q testdata/samples/mixed-busy-hour.pcapng | jq -c '.[0]'
{"start":"2026-03-04T11:00:00.916+01:00","duration_ms":5439.059,"kind":"call","state":"failed","result":"486 Busy Here","from":"erin","to":"judy","pdd_ms":44.45,"codec":"PCMU","call_id":"k3zyy0d7mv4ts2pz@10.0.1.46","user_agents":"Cisco-CP-8845/12.8.1","endpoints":"10.0.1.46:5060 10.0.2.21:5060","retransmissions":0,"media":"10.0.1.46:39036","reason":"","ended_by":""}
```

A failure histogram by final response, straight from the JSON:

```
$ sipcurious calls -F json -q testdata/samples/mixed-busy-hour.pcapng | jq -r '[.[]|select(.state=="failed")]|group_by(.result)|map({r:.[0].result,n:length})|sort_by(-.n)|.[]|"\(.n)\t\(.r)"'
24	486 Busy Here
18	404 Not Found
13	503 Service Unavailable
8	408 Request Timeout
7	603 Decline
```

Findings carry `detail`, `hint` and `packets` in the machine formats:

```
$ sipcurious diagnose -F json -q testdata/samples/busy-and-reject.pcap | jq -c '.[0]|keys'
["call_id","detail","hint","packets","rule","severity","time","title"]
```

`jq` is optional: `-F csv` opens in any spreadsheet, and `-F ndjson` streams one object per line (`sipcurious messages -F ndjson -q trace.pcap | jq -c 'select(.info|startswith("INVITE"))'`). Remember the split between streams: only data on stdout, so `sipcurious … -F json > out.json` is always valid JSON; the summary and warnings are on stderr.
