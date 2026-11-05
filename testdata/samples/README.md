# Demo captures

Synthetic, deterministic captures produced by `internal/pcaptest` (no real traffic, no real addresses: RFC 1918 / 203.0.113.0/24 / 2001:db8::/32).
They exist to demo and integration-test the tool; other tests assert against the facts below.

## Regenerate

```
go run ./internal/pcaptest/cmd/gensamples          # writes testdata/samples/*
go test ./internal/pcaptest/ -run 'TestSamples'    # byte-compares every file with the generator output
```

Every capture starts at `2026-03-04T10:00:00Z` (epoch 1772618400.000), uses a fixed seed (column *Seed*; `MixedBusyHour` also seeds its own scenario RNG with 1013) and is
byte-identical on every run (`TestSamplesMatchCommitted`). Definitions are in `internal/pcaptest/samples.go`.

## How the facts were obtained

All numbers come from `tshark` (Wireshark, `/opt/homebrew/bin/tshark`) and `tcpdump`, never from sipcurious:

* packets: `tshark -r f | wc -l`; SIP messages: `tshark -r f -Y sip -T fields -e frame.number ...` (see TCP note); Call-IDs: `-e sip.Call-ID | sort -u`
* resent messages: `-Y sip.resend==1` (`-z sip,stat` for the mixed capture)
* calls: `-T fields -e frame.time_epoch -e sip.Call-ID -e sip.CSeq.method -e sip.Method -e sip.Status-Code`, grouped by Call-ID
* RTP: `tshark -r f -q -z rtp,streams` (lost % and jitter are tshark's RFC 3550 values, ms); `-Y rtp`/`rtpevent`/`rtcp` for DTMF and RTCP
* (`-z voip,calls` is not available in this tshark build: "Invalid -z argument")
* validation: `tcpdump -nn -vv -r f` prints no `bad cksum` / `incorrect` / `truncated` / `malformed` line for any file; `tshark -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE -o tcp.check_checksum:TRUE -q -z expert` reports no checksum error, no malformed packet and no warning for any file (only notes: unknown `X-CID` header in the B2BUA / mixed captures, TCP "SYN without SACK PERM" in the TCP captures)
* "Duration" below is first SIP message of the Call-ID to last SIP message of the Call-ID (capture timestamps); "Talk" is first `200 OK` to INVITE to first BYE; "Setup" offsets are seconds from capture start.
  *State* is the `call.State` meaning (internal/call/types.go) applied to those facts.

## Summary

| File | Link | Seed | Pkts | SIP msgs | Resent | Call-IDs | RTP streams | Size (B) |
|---|---|---|---|---|---|---|---|---|
| `basic-call.pcap` | Ethernet | 1001 | 507 | 7 | 0 | 1 | 2 | 118523 |
| `busy-and-reject.pcap` | Ethernet | 1002 | 13 | 13 | 0 | 3 | 0 | 6238 |
| `cancelled-call.pcap` | Ethernet | 1003 | 7 | 7 | 0 | 1 | 0 | 3128 |
| `no-answer-retransmits.pcap` | Ethernet | 1004 | 18 | 18 | 12 | 2 | 0 | 14408 |
| `auth-register.pcap` | Ethernet | 1005 | 24 | 24 | 0 | 2 | 0 | 12616 |
| `bad-media.pcap` | Ethernet | 1006 | 803 | 21 | 0 | 3 | 3 | 190422 |
| `missing-ack.pcap` | Ethernet | 1007 | 16 | 16 | 10 | 1 | 0 | 10705 |
| `nat-problem.pcap` | Ethernet | 1008 | 414 | 14 | 0 | 1 | 2 | 100108 |
| `b2bua-two-legs.pcap` | Ethernet | 1009 | 816 | 14 | 0 | 2 | 4 | 191451 |
| `hold-resume.pcap` | Ethernet | 1010 | 928 | 26 | 0 | 2 | 4 | 96534 |
| `tcp-sip.pcap` | Ethernet | 1011 | 228 | 11 (in 10 frames) | 0 | 2 | 2 | 52993 |
| `ipv6-vlan.pcap` | Ethernet + 802.1Q VLAN 100 (all 322 frames), IPv6 | 1012 | 322 | 22 | 0 | 3 | 2 | 89186 |
| `features-sll-nanos.pcap` | Linux cooked (SLL), nanosecond timestamps | 1014 | 1114 | 14 | 0 | 2 | 4 | 256812 |
| `mixed-busy-hour.pcapng` | Ethernet, pcapng | 1013 | 1574 | 1100 | 24 | 164 | 134 | 574688 |

All captures are UDP except `tcp-sip.pcap` (228 packets: 200 UDP RTP + 28 TCP) and 8 Call-IDs of `mixed-busy-hour.pcapng`. SIP is on port 5060 everywhere; all calls use ptime 20 ms.

## Per-capture facts

### basic-call.pcap — the happy path
Defect shown: none (baseline). Addresses: caller 10.0.1.10:5060 (RTP 16384), callee 10.0.2.20:5060 (RTP 18000); direct, no proxy.

| Call-ID | Flow | State | Duration | Talk | Ended by |
|---|---|---|---|---|---|
| `0jv0hk3er8amef7w@10.0.1.10` (alice→bob) | INVITE 0.000, 100 0.004, 180 0.052, 200 2.003, ACK 2.007, BYE 7.007 (caller), 200 7.011 | completed | 7.011 s | 5.004 s | caller |

RTP (2 streams, PCMU pt 0, 20 ms): `10.0.1.10:16384→10.0.2.20:18000` SSRC 0x1A2B3C01, 250 pkts, 0 lost, jitter 0.000 ms; `10.0.2.20:18000→10.0.1.10:16384` SSRC 0x1A2B3C02, 250 pkts, 0 lost, jitter 0.000 ms. SDP offer PCMU, PCMA, telephone-event; answer PCMU, telephone-event; sendrecv.

### busy-and-reject.pcap — failed calls
Defect shown: final failure responses (486, 603 after 180, 404). Caller 10.0.1.10, callee 10.0.2.20, no media.

| Call-ID | Flow | State | Duration |
|---|---|---|---|
| `p98a67hlvnj047u3@10.0.1.10` (t=0) | INVITE, 100, 486, ACK | failed (486) | 0.049 s |
| `k4c4no2o3jug0m0o@10.0.1.10` (t=5) | INVITE, 100, 180, 603 (t=6.003), ACK | failed (603), PDD 0.044 s | 1.007 s |
| `gvpckwvdgxqtbev0@10.0.1.10` (t=10) | INVITE, 100, 404, ACK | failed (404) | 0.048 s |

### cancelled-call.pcap — caller gives up while ringing
Defect shown: CANCEL during ringing, with `Reason: SIP;cause=200;text="Call completed elsewhere"` on the CANCEL.

| Call-ID | Flow | State | Duration |
|---|---|---|---|
| `5ne6xh31h7srybv3@10.0.1.10` | INVITE 0.000, 100, 180 0.099, CANCEL 4.003 (caller), 200 (CANCEL), 487 4.009, ACK 4.013 | cancelled | 4.013 s; ringing before CANCEL ≈ 3.9 s |

### no-answer-retransmits.pcap — unreachable callee (timer A/B)
Defect shown: INVITE retransmissions with no response; Timer B expiry.

| Call-ID | Flow | State | Duration |
|---|---|---|---|
| `wry2nm78bsadglhu@10.0.1.10` (direct to dead 10.0.2.99, t=0) | INVITE + 6 retransmissions at +0.5, +1.5, +3.5, +7.5, +15.5, +31.5 s (7 INVITEs, no response at all) | no-response | 31.500 s |
| `yeqyr359bj5pafkb@10.0.1.10` (via proxy 10.0.0.1 to dead 10.0.2.98, t=2) | INVITE 2.000; proxy 100 2.004, proxy forwards INVITE 2.004 and retransmits it 6 times (+0.5, +1.5, +3.5, +7.5, +15.5, +31.5 s after 2.004, i.e. 2.504 … 33.504); 408 34.004 (proxy→caller), ACK 34.007 | failed (408) | 32.007 s |

12 resent messages (6 per call, tshark `sip.resend`). Total 18 messages: 7 + 11.

### auth-register.pcap — REGISTER with digest auth
Defect shown: a normal two-step REGISTER (401 → 200) and a failing client (repeated 401/403 pairs, five attempts). Registrar 10.0.0.1.

| Call-ID | Flow | State |
|---|---|---|
| `kzehd5y775y8t67n@10.0.1.10` (alice, 10.0.1.10, t=0) | REGISTER 0.000, 401 0.007, REGISTER (auth) 0.036, 200 0.041 | ok (final 200 after one challenge); Duration 0.041 s |
| `dbu0naoa5iycvlsq@10.0.1.30` (carol, 10.0.1.30, t=2) | 5 × (REGISTER → 401, REGISTER with Authorization → 403) every 2 s: 20 messages, requests at 2.000, 2.023, 4.031, 4.067, 6.076, 6.096, 8.106, 8.133, 10.142, 10.171; last response 403 at 10.176 | failed (last final 403; first response of the first request is 401); Duration 8.176 s |

### bad-media.pcap — three answered calls with media problems
Defect shown: loss + jitter + a media gap (call 1), one-way audio (call 2), no media at all (call 3). Each call: INVITE, 100, 180, 200 (+2.0 s), ACK, BYE after 6 s talk, 200; all `completed`, Talk 6.004 / 6.005 / 6.007 s, Duration 8.011 / 8.012 / 8.014 s, ended by caller (10.0.1.10).

| Call-ID (start) | Callee | RTP as seen by tshark |
|---|---|---|
| `gjsqxqhsuw6y4rox@10.0.1.10` (t=0) | 10.0.2.20 | `10.0.1.10:47810→10.0.2.20:14714` SSRC 0xBAD00001: 300 pkts, 0 lost, jitter 0. `10.0.2.20:14714→10.0.1.10:47810` SSRC 0xBAD00002: 182 pkts received, **118 lost (39.3 %)** (generator: 8 % random loss + a 2 s gap from the 2nd second), jitter mean 26.55 ms / max 38.13 ms (tshark flags the stream as a problem), max delta 1964.6 ms (the gap) |
| `3ysto1i3gfo77fpr@10.0.1.10` (t=10) | 10.0.2.21 | **one-way audio**: only `10.0.1.10:20132→10.0.2.21:18574` SSRC 0xBAD00003, 300 pkts, 0 lost, jitter 0. Callee→caller: 0 packets |
| `ybfuxqgimm86dtek@10.0.1.10` (t=20) | 10.0.2.22 | **no media**: 0 RTP packets in either direction (SDP negotiated PCMU) |

Totals: 803 packets = 21 SIP + 782 RTP (300 + 182 + 300).

### missing-ack.pcap — 200 OK never acknowledged
Defect shown: callee retransmits the 200 OK (RFC 3261 timer G/H) because the ACK never arrives; the callee eventually sends BYE. No RTP.

| Call-ID | Flow | State | Duration | Talk |
|---|---|---|---|---|
| `0sgmu3yvwctjbrd2@10.0.1.10` | INVITE 0.000, 100, 180 0.066, 200 2.003, then 10 retransmitted 200s at 2.503, 3.503, 5.503, 9.503, 13.503, 17.503, 21.503, 25.503, 29.503, 33.503; no ACK in the capture; BYE 34.003 from the callee (10.0.2.20), 200 34.038 | completed (answered + BYE), MissingACK = true | 34.038 s | 32.000 s (ended by callee) |

### nat-problem.pcap — private address behind NAT, via proxy
Defect shown: SDP/Contact/Via advertise the private 192.168.1.50 while the packets come from 203.0.113.10, so the callee sends its RTP to the unroutable address. Topology: caller 203.0.113.10 → proxy 10.0.0.1 → callee 10.0.2.20. One Call-ID `vfj72cutpqa46bgf@192.168.1.50`, 14 SIP messages (7 per hop), state completed, Duration 6.027 s, Talk 4.009 s, ended by caller.
Via of the caller INVITE `SIP/2.0/UDP 192.168.1.50:5060`, Contact `<sip:alice@192.168.1.50:5060>`, SDP `c=192.168.1.50 m=audio 14284`; the proxy adds `received=203.0.113.10`.

RTP (2 streams): `203.0.113.10:14284→10.0.2.20:43158` SSRC 0x4A700001, 200 pkts, 0 lost, jitter 0; `10.0.2.20:43158→192.168.1.50:14284` SSRC 0x4A700002, 200 pkts, 0 lost, jitter 0. (The second stream's destination is the private address from the SDP, not the real source of the caller's packets: the mismatch the tool must flag.)

### b2bua-two-legs.pcap — SBC with two independent legs
Defect shown: one logical call is two Call-IDs correlated only by `X-CID: SBC-7f3a91c2`; the SBC relays media with new SSRCs and ports on each leg.

| Call-ID | Legs | State | Duration | Talk |
|---|---|---|---|---|
| `bnvcw0zf0i6ci9es@10.0.1.10` (leg A, 10.0.1.10 ↔ SBC 10.0.0.1) | 7 messages: INVITE 0.000, 100, 180, 200 2.011, ACK 2.019, BYE 6.019 (caller), 200 6.031 | completed | 6.031 s | 4.007 s |
| `ipswrcvyqf4jfonu@10.0.0.1` (leg B, SBC ↔ 10.0.2.20, starts 0.004) | INVITE 0.004, 100, 180, 200 2.007, ACK 2.023, BYE 6.023 (**sent by the SBC**), 200 6.027 | completed | 6.023 s | 4.016 s |

RTP (4 streams): `10.0.1.10:50530→10.0.0.1:32848` SSRC 0xB2B00001, 200 pkts; `10.0.0.1:32848→10.0.1.10:50530` SSRC 0xE0F24429, 201 pkts; `10.0.0.1:33762→10.0.2.20:41832` SSRC 0x15FE4443, 200 pkts; `10.0.2.20:41832→10.0.0.1:33762` SSRC 0xB2B00002, 201 pkts. All 0 lost, jitter 0. (SSRCs 0xE0F24429 / 0x15FE4443 are seed-derived.)

### hold-resume.pcap — re-INVITE hold / resume, G.729
Defect shown: call 1 holds with `a=sendonly` (answer `recvonly`) and a real address; call 2 holds the old way with `c=0.0.0.0` + sendonly. Both resume with a `sendrecv` re-INVITE; each hold re-INVITE is answered 200 and ACKed. Both completed, BYE from caller.

| Call-ID (start) | Flow | Duration | Talk | RTP (G.729, pt 18) |
|---|---|---|---|---|
| `px32wk5nthn92bu1@10.0.1.10` (t=0, callee 10.0.2.20) | 13 messages: INVITE, 100, 180, 200 2.003, ACK; hold INVITE 4.008 (sendonly) / 200 / ACK; resume INVITE 6.008 (sendrecv) / 200 / ACK; BYE 8.008, 200 | 8.012 s | 6.005 s | `10.0.1.10:40152→10.0.2.20:32832` SSRC 0x0931D04E: 300 pkts (keeps sending, it is the sendonly side); `10.0.2.20:32832→10.0.1.10:40152` SSRC 0x5449B9E9: 201 pkts (silent during hold). 0 lost, jitter < 0.1 ms |
| `uisk21dfk8enm092@10.0.1.10` (t=15, callee 10.0.2.21) | 13 messages: as above, hold INVITE 19.010 has `c=0.0.0.0` + sendonly, resume 21.010, BYE 23.010 | 8.014 s | 6.007 s | `10.0.1.10:40122→10.0.2.21:40780` SSRC 0x5039545B: 200 pkts; `10.0.2.21:40780→10.0.1.10:40122` SSRC 0x83ED108A: 201 pkts (both silent during hold). 0 lost, jitter < 0.1 ms |

Hold interval: call 1 t=4.008–6.008, call 2 t=19.010–21.010.

### tcp-sip.pcap — SIP over TCP with segmentation quirks
Defect shown: (1) the first INVITE is split into two TCP segments inside the headers (frames 4 and 6: 218 + 575 bytes; tshark reassembles it in frame 6 at t=0.005), (2) `100 Trying` and `180 Ringing` of the callee share one TCP segment (frame 8, 637 bytes, t=0.082: two SIP messages in one segment), (3) a keep-alive OPTIONS flow on a separate TCP connection. Direct call 10.0.1.10:48055 → 10.0.2.20:5060.

Connections (tshark `conv,tcp`): `10.0.1.10:48055 ↔ 10.0.2.20:5060` (17 packets, t=0.000–4.017) and `10.0.1.10:34005 ↔ 10.0.0.1:5060` (11 packets, t=8.000–13.009). 28 TCP packets = 2 handshakes (3 each) + data and pure ACKs; 200 RTP packets over UDP.

| Call-ID | Flow | State | Duration | Talk |
|---|---|---|---|---|
| `6lxghkzqy4soaz9i@10.0.1.10` | 7 messages: INVITE (complete 0.005), 100 + 180 (one segment, 0.082), 200 2.006, ACK 2.013, BYE 4.013 (caller), 200 4.017 | completed | ≈ 4.012 s (from the reassembled INVITE; 4.014 from its first segment) | 2.006 s |
| `8w4bs1rpzmxdw4n5@10.0.1.10` | OPTIONS 8.000 → 200, OPTIONS 13.000 → 200 (4 messages, 10.0.0.1) | ok | 5.006 s | – |

RTP (2 streams): `10.0.1.10:31988→10.0.2.20:51548` SSRC 0x9609365F 100 pkts; `10.0.2.20:51548→10.0.1.10:31988` SSRC 0xF286EDB8 100 pkts; 0 lost, jitter 0. SIP message count 11 = 7 + 4 (tshark shows 10 frames because two messages share one).

### ipv6-vlan.pcap — IPv6 over 802.1Q
Defect shown: none; exercises the link layer. All 322 frames carry VLAN id 100; addresses: client 2001:db8:1::10, proxy/registrar 2001:db8::1, callee 2001:db8:2::20. Call-IDs contain bracketed IPv6 hosts (`...@[2001:db8:1::10]`).

| Call-ID | Flow | State | Duration | Talk |
|---|---|---|---|---|
| `9ufhl5sm04bcbrzy@[2001:db8:1::10]` | REGISTER, 401, REGISTER, 200 (t=0) | ok | 0.040 s | – |
| `8td1bdxzv5zogzhz@[2001:db8:1::10]` | alice→bob via proxy, 14 messages (7 per hop): INVITE 2.000, 200 4.011 (proxy→caller), ACK 4.015, BYE 7.015, 200 7.028 | completed | 5.028 s | 3.008 s |
| `sb8lb0dhjqgzyajm@[2001:db8:1::10]` | OPTIONS 10.000 → 200, OPTIONS 15.000 → 200 | ok | 5.006 s | – |

RTP (2 streams, PCMU): `[2001:db8:1::10]:48690→[2001:db8:2::20]:49526` SSRC 0x97A7B52B, 150 pkts; reverse SSRC 0x2B899480, 150 pkts; 0 lost, jitter 0. 22 SIP messages: 4 + 14 + 4.

### features-sll-nanos.pcap — link layer + media features
Defect shown: none; covers Linux cooked capture (DLT 113, `capinfos`: "Linux cooked-mode capture v1", time resolution ns, e.g. first response at 0.003379500 s), early media (183 with SDP), delayed offer (INVITE without SDP, offer in the 200, answer in the ACK), RFC 4733 DTMF, RTCP sender reports, Reason header, callee hang-up.

| Call-ID (start) | Flow | State | Duration | Talk |
|---|---|---|---|---|
| `va3j73e09dzse7n2@10.0.1.10` (t=0, callee 10.0.2.20) | 7 messages: INVITE, 100, **183 with SDP (t=0.046)**, 200 2.003, ACK 2.010, **BYE from the callee 8.010** with `Reason: Q.850;cause=16;text="Normal call clearing"`, 200 8.015 | completed (ended by callee) | 8.015 s | 6.007 s |
| `ubmkf9q6ix92ibng@10.0.1.10` (t=15, callee 10.0.2.21) | 7 messages: INVITE with **no SDP** (Content-Length 0), 100, 180, 200 17.003 (offer: PCMA, telephone-event), ACK 17.008 (answer: PCMA, PCMU, telephone-event), BYE 21.008, 200 | completed | 6.012 s | 4.004 s |

RTP (4 streams): call 1 `10.0.1.10:10794→10.0.2.20:38578` SSRC 0xFEA70001: 300 pkts (264 PCMU pt 0 + 36 telephone-event pt 101: digits 1, 2, 3, # (id 11), each 6 packets without end bit + 3 end-bit packets, from t=3.02 s); `10.0.2.20:38578→10.0.1.10:10794` SSRC 0xFEA70002: 398 pkts, starting at t=0.056 (early media, before the 200), pt 0; call 2 `10.0.1.10:38780→10.0.2.21:36160` SSRC 0xFEA70003 and reverse 0xFEA70004: 200 pkts each, PCMA pt 8. 0 lost everywhere; tshark jitter on 0xFEA70001 mean 2.29 ms / max 26.3 ms (tshark counts the DTMF timestamp jumps; the audio is clean), 0 on the rest.
RTCP: two sender reports (SR + SDES CNAME), one per direction of call 1, on RTP port + 1: `10.0.2.20:38579` at t=5.059 (SSRC 0xFEA70002, 251 pkts / 40160 octets sent) and `10.0.1.10:10795` at t=7.023 (SSRC 0xFEA70001, 251 pkts / 34544 octets sent); both report fraction lost 0, cumulative lost 0, jitter 0.

### mixed-busy-hour.pcapng — busy hour, ~10 minutes
Defect shown: a realistic mix for statistics / filtering / top-N: many user agents (7 caller UAs, 4 callee UAs), all failure classes, auth rounds, holds, direct / proxy / SBC topologies, 8 TCP Call-IDs, registrations and OPTIONS keep-alives. pcapng (nanosecond resolution), duration 618.823968 s, 1574 packets: 1052 SIP over UDP, 120 TCP packets (48 carry SIP, 72 are handshakes/pure ACKs; 1100 SIP messages in total) and 402 RTP. RTP is 134 streams of exactly 3 packets each (0 lost, jitter 0); per-packet payload types: pt 0 PCMU 132, pt 8 PCMA 102, pt 18 G.729 72, pt 111 Opus 96. 24 resent SIP messages (tshark `-z sip,stat`).

Call-IDs: **164** = 155 INVITE + 6 OPTIONS + 3 REGISTER.
* 3 REGISTER (10.0.1.10, .11, .12, 401 then 200, t=0, 1, 2) and 6 OPTIONS (10.0.0.1 → 10.0.3.10/.11/.12, one every 100 s, each answered 200; the first Call-ID is `89dcvt82yvjsb1c1@10.0.0.1`).
* 155 INVITE Call-IDs = 150 caller legs + 5 second B2BUA legs. 10 Call-IDs carry an `X-CID` header (5 B2BUA calls = 5 pairs).
* Final result of the 155 INVITE Call-IDs: 200 + BYE **67** (7 of them first drew a 407 and were re-sent with credentials), 486 **24**, 487 after CANCEL **18**, 404 **18**, 503 **13**, 408 **8**, 603 **7**.
* Of these, the **150 caller legs** (generator `MixedStats`, `Calls = 150`): answered 53 + answered with 407 auth 7 + answered with hold 3 = **63 completed**; busy-486 24; cancelled 12 + no-answer-cancel (20 s ring) 6 = **18 cancelled/487**; rejected-404 17; rejected-603 7; server-error-503 13; unreachable-408 (via proxy) 8. By subtraction from the Call-ID totals above, the 5 second B2BUA legs are 4 × 200+BYE and 1 × 404.

Because of the length of this capture, tests should compare aggregates (the numbers above, `-z sip,stat`: 1100 messages, 486 ×24, 487 ×18, 603 ×8 (7 Call-IDs; one of them, `zns4xcadnf1q7qyy@10.0.1.14`, is relayed by a proxy and shows it twice), 407 ×7, 200 ×187, 408 ×8, 503 ×13, 180 ×144, 100 ×172, 401 ×3, 404 ×18, INVITE ×212, ACK ×180, REGISTER ×6, OPTIONS ×6, BYE ×76, CANCEL ×18) rather than a per-call listing.

## Jitter / loss categories used above

* "jitter 0": tshark mean/max jitter below 0.01 ms.
* "problem": tshark's `X` problem flag in `rtp,streams` (only `0xBAD00002` in `bad-media.pcap`: 39.3 % loss, 26.6 ms mean jitter).
