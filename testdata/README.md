# Test data

`aaa.pcap` is the original sample (Wireshark wiki, "SIP and RTP traffic"; also shipped in sngrep's tests).
`golden/` and `generated/` belong to the CLI golden tests and the synthetic capture matrix.

`realworld/` holds real captures of other people's SIP traffic plus a few byte-level transcodings of one of them. All are exercised by `internal/capture/realworld_test.go`.
Expected packet / message / Call-ID counts and the spot-checked messages were derived without sipcurious (byte scan of the capture records for SIP start lines and `Call-ID`/`i:` headers, `tcpdump -nn -tt -A` for addresses, headers and timestamps).
"Dialogs" below means distinct Call-IDs.

Nothing is downloaded at test time. Every file is at most 256 KB; `realworld/` is 1.5 MB in total.

## Sources and terms

| Source | Terms |
|---|---|
| Wireshark wiki sample captures, <https://wiki.wireshark.org/SampleCaptures> (git: `gitlab.com/wireshark/wireshark.wiki`) and Wireshark `test/captures` (<https://gitlab.com/wireshark/wireshark/-/tree/master/test/captures>) | Wiki: "available under the GNU GPL; by contributing you agree to the terms of the GNU GPL" (<https://wiki.wireshark.org/License>). `test/captures`: repository licence GPL-2.0-or-later |
| OISF suricata-verify, <https://github.com/OISF/suricata-verify> `tests/sip-*` | MIT |
| PcapPlusPlus, <https://github.com/seladb/PcapPlusPlus> `Tests/Packet++Test/PacketExamples`, `Tests/Pcap++Test/PcapExamples` | Unlicense (public domain) |
| sngrep, <https://github.com/irontec/sngrep> `tests/` | GPL-3.0 |
| nDPI, <https://github.com/ntop/nDPI> `tests/cfgs/default/pcap` | LGPL-3.0 |
| Zeek, <https://github.com/zeek/zeek> `testing/btest/Traces/sip` | Zeek BSD-3-clause style licence (`COPYING`) |

sipcurious is GPL-3.0; all of the above permit redistribution as test fixtures. Files marked *trimmed* were cut with `tcpdump -r in -w out '<filter>'`; nothing else was changed. Files marked *derived* were rewritten by a throwaway script (not committed) from a real capture, only to change the container or link layer; the SIP bytes are the real ones.

## Real captures

| File | Origin (file in source) | Link layer | What it exercises | Pkts | SIP | Dialogs |
|---|---|---|---|---|---|---|
| `wireshark-sip-rtp-g711.pcap` | wiki `sip-rtp-g711.pcap` (SIPp vs FreeSWITCH) | Ethernet | INVITE/100/200/ACK/BYE flow, SDP bodies, RTP noise (852 packets, 10 SIP) | 852 | 10 | 2 |
| `wireshark-sip-rtp.pcapng` | Wireshark `test/captures/sip-rtp.pcapng` | Ethernet, pcapng | pcapng, REGISTER with auth + INVITE call, RTP noise | 562 | 14 | 4 |
| `wireshark-sip-rawip.pcapng` | Wireshark `test/captures/sip.pcapng` | Raw IP (101), pcapng | raw IP link type, REGISTER, INVITE with SDP over loopback, non-SIP UDP (MEGACO) in between | 6 | 5 | 2 |
| `wireshark-sip-dtmf2.pcap` | wiki `SIP_DTMF2.cap`, *trimmed* to `port 5060` | Ethernet | 5 dialogs, REGISTER x several, 603 Decline, parallel INVITEs, 180 + 200 from two forks | 29 | 29 | 5 |
| `wireshark-sip-call-g711.pcap` | wiki `SIP_CALL_RTP_G711`, *trimmed* to `port 5060 or port 5061 or tcp` | Ethernet | INVITE calls + REGISTER from three phones (4 Call-IDs; 14 messages); also non-SIP TCP traffic and a CRLF keep-alive datagram on port 5060 (not a message). A Telnet segment contains the text `I: 7c`, which is not a Call-ID | 539 | 14 | 4 |
| `wireshark-dtmf-sipinfo.pcap` | wiki `DTMFsipinfo.pcap` | Ethernet | INFO, CANCEL, re-INVITE in one dialog | 32 | 32 | 1 |
| `wireshark-fax-t38.pcap` | wiki `FAX-Call-t38-CA-TDM-SIP-FB-1.pcap`, *trimmed* to `udp port 5060` | Ethernet | 92 messages through a proxy (the same Call-ID seen on 3 hops), re-INVITE for T.38, OPTIONS, 2 dialogs; double spaces after `CSeq:`/`To:` | 92 | 92 | 2 |
| `wireshark-asterisk-zfone-xlite.pcap` | wiki `Asterisk_ZFONE_XLITE.pcap` | Ethernet | Asterisk with Zfone and X-Lite: REGISTER (401 challenge), SUBSCRIBE x4, OPTIONS, re-INVITE, BYE, source port 13434; ZRTP noise | 1042 | 27 | 5 |
| `wireshark-h263-over-rtp.pcap` | wiki `h263-over-rtp.pcap` | BSD loopback (NULL) | NULL link type, INVITE/100/200/ACK + RTP | 49 | 4 | 1 |
| `wireshark-magicjack-short-call.pcap` | wiki `MagicJack-_short_call.pcap`, *trimmed* to `udp port 5070 or tcp` | Ethernet | server on port 5070, 401 challenge then INVITE with auth, 183 Session Progress, BYE sent by the callee | 50 | 11 | 1 |
| `wireshark-metasploit-invite-spoof.pcap` | wiki `metasploit-sip-invite-spoof.pcap` | Ethernet | INVITE on UDP port 10270, empty user in Request-URI (`sip:@127.0.0.1`), trailing blank lines; ICMP port unreachable | 3 | 2 | 1 |
| `wireshark-nb6-startup.pcap` | wiki `nb6-startup.pcap` | Ethernet | IMS REGISTER (AKA 401 then 200) on port 5062 among DHCP/DNS/HTTP; Request-URI with a long IMS domain | 531 | 4 | 1 |
| `wireshark-nb6-telephone.pcap` | wiki `nb6-telephone.pcap` | Ethernet | INVITE/BYE call on port 5062 from a Neufbox | 527 | 7 | 1 |
| `wireshark-switchport-sip-with-arp-stp.pcap` | wiki `port-16_vlan24_200.pcap` | Ethernet | 3 SIP messages (INVITE, ACK, BYE; INVITE has a body) among ARP, 802.3/STP and TCP traffic on a switch port. The file name suggests VLAN but there are no 802.1Q tags in it | 316 | 3 | 1 |
| `wireshark-rtp-conversacion.pcap` | wiki `rtp_conversacion.pcap`, *trimmed* to `port 5060` | Ethernet | 407 + INVITE, OPTIONS, BYE, source port 11384, **and a keep-alive `\r\n\r\n` datagram** (packet 11, must not count as a message) | 13 | 12 | 2 |
| `wireshark-sip-tls13-caplen-gt-origlen.pcap` | wiki `sip-tls-1.3-and-rtcp.zip` (`tls-1.3/sip.pcap`), first 40 records only | Linux cooked (SLL) | SIP over TLS 1.3 (not decodable). Every record has `caplen > origlen` (tcpdump: "Invalid header"); read using the capture length like libpcap, no warning | 40 | 0 | 0 |
| `wireshark-sctp-megaco-bigendian.pcap` | wiki `sctp.cap` | Ethernet, **big-endian** pcap | SCTP DATA (H.248) + SACK + heartbeat; no SIP at all, must yield nothing, not an error | 4 | 0 | 0 |
| `sngrep-ipip-tcp.pcap` | sngrep `tests/ipip.pcap` | Ethernet | SIP over **TCP** (port 5090) with some segments carried in an **IP-in-IP** tunnel; the endpoints must be the inner ones | 4 | 4 | 1 |
| `sngrep-ipv6-frag-sll.pcap` | sngrep `tests/ipv6frag.pcap` | Linux cooked v1 (SLL) | **IPv6**, SIPp calls with PRACK/UPDATE, UDP port 5062, **IPv6 fragments**: 2 of the 34 packets are the second halves of 1500-byte INVITEs; 2 INVITE datagrams (packets 1+2, 4+5) must be reassembled | 34 | 32 | 1 |
| `suricata-sip-tcp-register.pcap` | suricata-verify `sip-tcp-method` | Ethernet, loopback | SIP over TCP: REGISTER request split in two segments (the 2nd segment carries the rest of the headers and has no start line (not reported)), 200 OK | 11 | 2 | 1 |
| `suricata-sip-tcp-port5062.pcap` | suricata-verify `sip-tcp-pattern-matching` | Ethernet | SIP over TCP on a non-standard port 5062 | 7 | 2 | 1 |
| `suricata-sip-udp-port5062.pcap` | suricata-verify `sip-pattern-matching` | Ethernet | SIP over UDP on port 5062, `Contact:` with double space | 2 | 2 | 1 |
| `suricata-sip-body-large-tcp-loopback.pcap` | suricata-verify `sip-body-large` | BSD loopback (NULL) | a 65 KB INVITE over TCP in 5 segments (16 KB loopback packets); only the first segment starts with a start line, so the message is seen once, headers only; plus the 100 Trying | 16 | 2 | 1 |
| `suricata-sip-body-frames-cloudshark.pcap` | suricata-verify `sip-body-frames` (public CloudShark sample) | Ethernet | 2 INVITE flows with SDP and a REGISTER; quoted display names | 10 | 10 | 3 |
| `suricata-sip-compact-form.pcap` | suricata-verify `sip-compact-form` | Ethernet | compact header names (`v:`, `f:`, `t:`, `c:`), escaped quotes in the display name | 1 | 1 | 1 |
| `suricata-sip-header-multi-value.pcap` | suricata-verify `sip-header-multi-value` | Ethernet | repeated and comma-joined headers (first Call-ID wins) | 1 | 1 | 1 |
| `suricata-sip-options.pcap` | suricata-verify `sip-options-method` | Ethernet | OPTIONS + 200 OK, broadcast MAC | 2 | 2 | 1 |
| `suricata-sip-sdp.pcap` | suricata-verify `sip-sdp` | Ethernet | INVITE/200 OK with SDP bodies | 2 | 2 | 1 |
| `pcapplusplus-sip-requests-pppoe.pcap` | PcapPlusPlus `sip_reqs.pcap` | Ethernet (one packet in **PPPoE**) | INVITE, CANCEL, ACK, BYE from four unrelated captures, one inside PPPoE session | 4 | 4 | 3 |
| `pcapplusplus-sip-responses.pcap` | PcapPlusPlus `sip_resp.pcap` | Ethernet | 100, 180, 200, 401, 504, 503 from unrelated captures; packet 5 is a 401 inside a **TCP** segment (port 5054 to 51806), the rest UDP | 7 | 7 | 5 |
| `pcapplusplus-sip-port52380.pcap` | PcapPlusPlus `sip_non_default_port.pcap` | Ethernet | SIP on UDP port 52380 (PBX web port), no `SIP` in the port number | 2 | 2 | 2 |
| `pcapplusplus-sip-publish.pcap` | PcapPlusPlus `sip_not_sdp.pcap` | Ethernet | PUBLISH with a non-SDP body | 1 | 1 | 1 |
| `pcapplusplus-sip-200-sdp.pcap` | PcapPlusPlus `sdp.pcap` | Ethernet | 200 OK with SDP | 1 | 1 | 1 |
| `pcapplusplus-nanosecs.pcap` | PcapPlusPlus `nanosecs.pcap` | Ethernet, **nanosecond** pcap | no SIP, 2 packets with unusual EtherType; must not fail | 2 | 0 | 0 |
| `pcapplusplus-nanosecs-bigendian-http.pcap` | PcapPlusPlus `nanosecs_big_endian.pcap` | Ethernet, **big-endian nanosecond** pcap | HTTP over TCP on port 8000, no SIP | 10 | 0 | 0 |
| `ndpi-sip-keepalive-hello.pcapng` | nDPI `sip_hello.pcapng` | Ethernet, pcapng | UDP 5060 <-> 5060 with a `hello\0\0...` keep-alive every ~49 s (22 packets, not SIP), two REGISTER (401 challenge) flows | 30 | 8 | 1 |
| `ndpi-http-on-sip-port.pcap` | nDPI `http_on_sip_port.pcap` | Ethernet, **pcapng stored under a `.pcap` name** (content detection, not extension) | HTTP on TCP port 5060: the port must not make it SIP | 4 | 0 | 0 |
| `zeek-sip-junk-before-request.pcap` | Zeek `Traces/sip/sip-junk-before-request.pcap` | Ethernet | a UDP datagram with 4 zero bytes (junk, not SIP) followed by a REGISTER without Call-ID/From/To/CSeq | 2 | 1 | 0 |
| `zeek-sip-long-paths-rawipv4.pcap` | Zeek `Traces/sip/sip-long-request-response-paths.pcap` | **LINKTYPE_IPV4 (228)** | 9.5 KB OPTIONS and 200 OK with huge Via headers; no Ethernet header at all | 2 | 2 | 1 |

## Derived captures

All nine contain the same 10 SIP messages as `suricata-sip-body-frames-cloudshark.pcap` (3 dialogs), rewritten only to change the container or link layer.
They exist because no real SIP capture with these properties could be found (see below). Timestamps are the originals, except in the nanosecond files where each packet *i* got `+ i*111 ns` so that sub-microsecond precision is observable.

| File | Rewrite |
|---|---|
| `derived-cloudshark-microsecond-be.pcap` | big-endian microsecond pcap |
| `derived-cloudshark-nanosecond-le.pcap` | little-endian **nanosecond** pcap |
| `derived-cloudshark-nanosecond-be.pcap` | big-endian **nanosecond** pcap |
| `derived-cloudshark-vlan.pcap` | one 802.1Q tag (VLAN 100) inserted after the MAC addresses |
| `derived-cloudshark-qinq.pcap` | 802.1ad outer tag (VLAN 200) + 802.1Q inner tag (VLAN 100) |
| `derived-cloudshark-sll.pcap` | Ethernet header replaced by Linux cooked v1 (SLL) |
| `derived-cloudshark-sll2.pcap` | Ethernet header replaced by Linux cooked v2 (SLL2), ifindex 7 |
| `derived-cloudshark.pcapng` | pcapng with nanosecond (`if_tsresol=9`) timestamps |
| `derived-cloudshark-multiif.pcapng` | pcapng with **two interfaces** (Ethernet and SLL2), packets alternate between them |

## Not found / not covered by real captures

Searched: Wireshark wiki and `test/captures`, suricata-verify, nDPI, Zeek, tcpdump, libpcap, Arkime, PcapPlusPlus, sngrep, SIPp, pjproject, kamailio, opensips, asterisk, sippy, heplify, homer, gopacket, nfstream, GitHub code search (`filename:sip extension:pcap` and variants) and several dozen small SIP projects.
Nothing usable was found for these, so they are only covered by the derived files above or by the synthetic captures (`testdata/generated`):

- **SIP over TLS, decoded** (no key material is available; the one real TLS capture is truncated by the reader, see above) and **WebSocket** SIP.
- **SIP over SCTP**: the only real SCTP captures carry MEGACO/H.248 or HTTP.
- **A real VLAN-tagged, Q-in-Q or SLL2 SIP capture**: the only real SIP+VLAN candidates (Cisco voice VLAN, `cdp_v2_voice_vlan.pcap`) contain no plain-text SIP. Real SLL2 captures exist (`suricata-verify decode-sll2-*`, PcapPlusPlus) but carry no SIP.
- **A real nanosecond or multi-interface pcapng SIP capture**.
- **Real SIP over IPv6 without fragmentation** (the IPv6 capture is fragmented SIPp traffic over SLL).
- **REFER, NOTIFY, MESSAGE** flows. SUBSCRIBE, PUBLISH, INFO, PRACK, UPDATE, CANCEL, OPTIONS, re-INVITE are present.
- Large (> 256 KB) captures: skipped on purpose to keep the repository small.

## RTP captures

Used by `internal/rtp` (`realworld_test.go`). Expected packet counts, loss and jitter come from `tshark -r <file> -q -z rtp,streams` (plus `-Y rtpevent` and `-T fields -e rtcp.*`), never from sipcurious; the test file documents every intentional delta. The RTP streams of the files below are also covered: `wireshark-sip-rtp-g711.pcap`, `wireshark-asterisk-zfone-xlite.pcap` (one-way media with a 4.7 s hole, 369 lost packets; SRTCP-like sender reports), `wireshark-h263-over-rtp.pcap` (90 kHz video, BSD loopback), `wireshark-rtp-conversacion.pcap`, `wireshark-nb6-telephone.pcap` (jittery PCMA), `wireshark-switchport-sip-with-arp-stp.pcap` and the generated `samples/basic-call.pcap` / `samples/bad-media.pcap`.

| File | Source | Content | Packets | RTP streams |
|---|---|---|---|---|
| `wireshark-rtp-dtmf-event.pcap` | wiki `SIP_DTMF2.cap`, *trimmed* to `frame.time_relative <= 86` (tshark `-w`, pcap) | SIP INVITE/200/ACK of two phones, 30 ms PCMA media (PT 8) and **RFC 4733 telephone-event** (PT 96 from SDP): 7 digits = 35 event packets, 5 per digit (tshark `-Y rtpevent`) | 637 (26 SIP, 611 RTP) | 2 (306 and 305 packets) |
| `wireshark-rtp-rtcp-g722-freeswitch.pcap` | wiki `sip-tls-1.3-and-rtcp.zip` (`tls-1.3/sip.pcap`), UDP only, first 640 records | FreeSWITCH G.722 call (PT 9, RTP clock 8000), plain **RTCP** SR/RR/SDES on port+1 (the SIP was TLS and is not in this file; tshark needs `-o rtp.heuristic_rtp:TRUE` to see the stream): SR at packets 201/404/607, RR at 203/406/609 (cumulative lost 1, jitter 6 then 22 timestamp units) | 613 (607 RTP, 6 RTCP) | 1 |

Both are redistributable Wireshark wiki sample captures (wiki.wireshark.org/SampleCaptures), under 200 KB.
