# Capture formats and what is read from them

sipcurious is pure Go: no libpcap, no tshark, no root. It reads captures **by content**, not by name or port.

## Inputs

| Input | Support |
|---|---|
| Classic pcap, microsecond or nanosecond timestamps, little or big endian | yes |
| libpcap "modified" format (Kuznetsov), any 2.x file version | yes |
| pcapng (several sections/interfaces, mixed link types per interface, `if_tsresol` timestamps) | yes |
| gzip-compressed pcap or pcapng (`.gz`, detected by the `1f 8b` magic) | yes, transparent |
| Standard input: path `-` (pcap, pcapng or gzip) | yes: `tcpdump -w - ... \| sipcurious calls -` |
| Several files, directories, shell globs | yes, merged by capture time (see below) |
| A directory | walked recursively for `*.pcap`, `*.pcapng`, `*.cap`, `*.pcap.gz`, `*.pcapng.gz` (lexical order) |
| Format by extension | no: the container is detected by magic, so a pcapng named `.pcap` works |

Examples (all run against the demo captures):

```
$ sipcurious messages --count testdata/samples/basic-call.pcap
7
$ gzip -c testdata/samples/basic-call.pcap > /tmp/b.pcap.gz && sipcurious messages --count /tmp/b.pcap.gz
7
$ cat testdata/samples/tcp-sip.pcap | sipcurious messages --count -
11
```

With several files the messages and streams are merged and sorted by capture time (stable: equal times keep file order, then packet order). Each file is read by its own goroutine (at most `GOMAXPROCS` at a time), so a directory of captures is read in parallel. `--no-rtp` skips RTP analysis for the fastest signalling-only pass.

Stdin is read as one stream; commands that must read an input twice (`export`) need regular files.

## Link layers

| Link type | Notes |
|---|---|
| Ethernet (1) | with 802.1Q and Q-in-Q (802.1ad) VLAN tags (up to 8 stacked); also 802.3/LLC, PPPoE, MPLS and ERSPAN through the gopacket fallback |
| Linux cooked SLL (113) and SLL2 (276) | `tcpdump -i any` |
| Raw IP (101, 228 IPv4, 229 IPv6) | no link header |
| BSD loopback / Null (0) and Loop | loopback captures |
| PPP | gopacket fallback |
| GRE (incl. transparent Ethernet bridging), IP-in-IP, IPv6-in-IP, EtherIP | tunnels are unwrapped, nesting bounded to 4 levels |

The endpoints of a message are those of the **innermost** IP header, so SIP inside an IP-in-IP tunnel is attributed to the inner addresses (`testdata/realworld/sngrep-ipip-tcp.pcap`: 4 messages). A pcapng with several interfaces of differing link types is decoded per interface (`derived-cloudshark-multiif.pcapng`: 10 messages from Ethernet and SLL2 interfaces mixed).

Network layer: IPv4 (with options) and IPv6 (including hop-by-hop, routing, destination-options and fragment extension headers; AH). A record whose captured length exceeds its original length (some capture tools write this) is read using the captured length, like libpcap.

## Fragmentation and reassembly

- **IPv4 and IPv6 fragments are reassembled** before the transport layer is decoded: large INVITEs over UDP that were fragmented are one message (`sngrep-ipv6-frag-sll.pcap`: two fragmented 1500-byte INVITEs are found). Overlapping fragments: the earliest received bytes win. The number of pending datagrams and fragments per datagram is bounded.
- **TCP is reassembled per direction of each connection** for SIP: messages are framed by `Content-Length` (compact form `l`; no header means no body), so several messages in one segment and one message over several segments both work (`testdata/samples/tcp-sip.pcap`: 11 SIP messages in 10 frames, one INVITE split in two segments). Retransmitted bytes are dropped by sequence number, a modest number of out-of-order segments is reordered, and after loss or garbage the stream resynchronises at the next line that is a SIP start line. A stream is only followed once a SIP start line was seen, so TLS, HTTP or other traffic on port 5060 costs no state and is ignored. At most 1024 directions are tracked (least recently used flushed); a message keeps at most 64 KiB.
- A message split over several packets is timestamped and numbered (`file#index`) by the packet that carried its **first** byte.
- **UDP**: one datagram = one message. CRLF keep-alives (`\r\n\r\n`), STUN and RTP are not messages. A message must start with a valid SIP start line (`METHOD URI SIP/2.0` or `SIP/2.0 code reason`); leading CR/LF are stripped.
- **SCTP**: each DATA chunk is offered to the handlers as one message (no association tracking or chunk reassembly across fragmented DATA chunks).

## Port independence

SIP is recognised **by its start line on any port and any transport**: `testdata/realworld/pcapplusplus-sip-port52380.pcap` (UDP 52380), `suricata-sip-tcp-port5062.pcap` and `wireshark-magicjack-short-call.pcap` (5070) are found without configuration, while HTTP on TCP/5060 (`ndpi-http-on-sip-port.pcap`) yields nothing. RTP is likewise detected on any UDP port from the packet contents (see [definitions.md](definitions.md)); no SDP is needed to see a stream, SDP only correlates it with a call.

## Damaged and truncated captures

A capture that ends or breaks in the middle of a record (for example `tcpdump` killed, a file copied while still being written) is **not an error**: every intact packet before the damage is processed and a warning is printed on stderr, the exit code stays 0:

```
$ head -c 6000 testdata/samples/basic-call.pcap > /tmp/cut.pcap
$ sipcurious messages /tmp/cut.pcap
sipcurious: warning: /tmp/cut.pcap: capture ends abruptly at packet 19 (unexpected EOF); 18 packets read
sipcurious: read 1 file, 18 packets, 5 SIP messages in 0s
sipcurious: 5 messages matched
...
```

`--quiet` hides warnings and the summary. A file that is not a capture at all, or cannot be opened, is a runtime error (exit 1) naming the path:

```
$ sipcurious messages /dev/null
sipcurious: /dev/null: not a pcap or pcapng file: file too short
```

**Snaplen-truncated packets** (`tcpdump -s 96`): the payload is cut at the snaplen. A SIP message that was cut mid-header keeps what arrived, but a half-captured header line is dropped (a `Call-ID: ab` cut after two characters would otherwise become the wrong Call-ID); a message cut right after the start line is still reported. RTP packets cut below the 12-byte header are not RTP; with a snaplen shorter than the RTP payload the packet and loss counts stay correct (they come from the header), but byte counts do not.

## What is not supported

| Not supported | What you get |
|---|---|
| **TLS decryption** (SIP over TLS/SIPS, SRTP keys) | no key handling at all. Encrypted TCP is ignored (no SIP messages are found; `wireshark-sip-tls13-caplen-gt-origlen.pcap` yields 0 messages). Decrypt first (for example with Wireshark and a key log file) and export the result as pcap. The filter field `transport` has the values `TLS`, `WS`, `WSS` reserved, but the packet reader reports only `UDP`, `TCP` and `SCTP`. |
| **WebSocket** SIP (RFC 7118, WS/WSS) | not decoded: WebSocket frames do not start with a SIP start line, so nothing is found |
| **SRTP payload** | RTP headers are readable, so streams, loss, jitter and gaps are measured; the payload is opaque. Codec names come from the payload type or SDP only |
| **SCTP associations** | only DATA chunks are delivered and each is treated as one message; fragmented DATA chunks and multi-stream ordering are not reassembled. Only synthetic captures cover SIP over SCTP; the one real SCTP capture in the tests carries H.248 |
| **Non-SIP VoIP signalling** (H.323, MGCP, SCCP, IAX2, MEGACO) | ignored; such packets are counted as skipped |
| **RTP in TCP** (RFC 4571, interleaved RTSP) | not detected: RTP is only looked for in UDP datagrams |
| **Other link types** (802.11 radiotap, USB, ...) | decoded only as far as the gopacket fallback allows, otherwise the packet is skipped |
| **Live capture** | no: read files or stdin |

## Test corpus and provenance

The behaviour above is pinned by tests against real third-party captures and derived rewrites in `testdata/realworld/` (provenance, licences and how the expected numbers were obtained without sipcurious are in [`testdata/README.md`](../testdata/README.md)), and by deterministic synthetic captures in `testdata/samples/` ([`testdata/samples/README.md`](../testdata/samples/README.md), facts from tshark/tcpdump). The README of the corpus also lists what real captures could **not** be found for: decoded SIP over TLS, WebSocket SIP, SIP over SCTP, a real VLAN/Q-in-Q/SLL2 SIP capture, REFER/NOTIFY/MESSAGE flows. Those paths are covered by derived or synthetic files only.
