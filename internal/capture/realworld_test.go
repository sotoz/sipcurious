package capture_test

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/trace"
)

// Real-world capture matrix. Every fixture lives in ../../testdata/realworld
// and is documented (source, licence, link layer) in testdata/README.md.
//
// The expected values were derived independently of sipcurious: packet counts
// from the capture file records, SIP start lines and Call-ID headers with a
// separate byte-level scan of every packet, and the spot-checked messages
// from `tcpdump -nn -tt -A` (addresses, ports, headers, timestamps).

const realWorldDir = "../../testdata/realworld/"

// check pins every field of one message, addressed by its 1-based packet
// number. An empty time is not compared.
type check struct {
	packet                                     int
	info, uri, callID, from, to, cseq, contact string
	src, dst, transport, time                  string
}

type realCapture struct {
	file     string
	packets  int
	messages int
	callIDs  int    // distinct non-empty Call-IDs among the SIP messages
	seq      string // "packet:method-or-status" for every SIP message, in order
	checks   []check
}

var realCaptures = []realCapture{
	{
		file:     "derived-cloudshark-microsecond-be.pcap",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658696Z"},
		},
	},
	{
		file:     "derived-cloudshark-multiif.pcapng",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658696Z"},
		},
	},
	{
		file:     "derived-cloudshark-nanosecond-be.pcap",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944111Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658697110Z"},
		},
	},
	{
		file:     "derived-cloudshark-nanosecond-le.pcap",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944111Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658697110Z"},
		},
	},
	{
		file:     "derived-cloudshark-qinq.pcap",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658696Z"},
		},
	},
	{
		file:     "derived-cloudshark-sll.pcap",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658696Z"},
		},
	},
	{
		file:     "derived-cloudshark-sll2.pcap",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658696Z"},
		},
	},
	{
		file:     "derived-cloudshark-vlan.pcap",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658696Z"},
		},
	},
	{
		file:     "derived-cloudshark.pcapng",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944111Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658697110Z"},
		},
	},
	{
		file:     "ndpi-http-on-sip-port.pcap",
		packets:  4,
		messages: 0,
		callIDs:  0,
		seq:      "",
	},
	{
		file:     "ndpi-sip-keepalive-hello.pcapng",
		packets:  30,
		messages: 8,
		callIDs:  1,
		seq:      "9:REGISTER 10:401 11:REGISTER 12:200 25:REGISTER 26:401 27:REGISTER 28:200",
		checks: []check{
			{packet: 9, info: "REGISTER", uri: "sip:10.192.60.4", callID: "c15740-ae78e54-13c4-38-3e10ffda-38", from: "\"26841945\"<sip:26841945@10.192.60.4>;tag=c085d8-ae78e54-13c4-41c244-2c55dc23-41c244", to: "\"26841945\"<sip:26841945@10.192.60.4>", cseq: "28715 REGISTER", contact: "<sip:26841945@10.231.142.84:5060>", src: "172.29.38.91:5060", dst: "10.239.156.235:5060", transport: "UDP", time: "2022-02-22T07:46:35.292160Z"},
			{packet: 28, info: "200 OK", uri: "", callID: "c15740-ae78e54-13c4-38-3e10ffda-38", from: "\"26841945\"<sip:26841945@10.192.60.4>;tag=c08958-ae78e54-13c4-41c370-3717a08c-41c370", to: "\"26841945\"<sip:26841945@10.192.60.4>;tag=x8heihiy", cseq: "28718 REGISTER", contact: "<sip:26841945@10.231.142.84:5060>;expires=600", src: "10.239.156.235:5060", dst: "172.29.38.91:5060", transport: "UDP", time: "2022-02-22T07:51:35.555308Z"},
		},
	},
	{
		file:     "pcapplusplus-nanosecs-bigendian-http.pcap",
		packets:  10,
		messages: 0,
		callIDs:  0,
		seq:      "",
	},
	{
		file:     "pcapplusplus-nanosecs.pcap",
		packets:  2,
		messages: 0,
		callIDs:  0,
		seq:      "",
	},
	{
		file:     "pcapplusplus-sip-200-sdp.pcap",
		packets:  1,
		messages: 1,
		callIDs:  1,
		seq:      "1:200",
		checks: []check{
			{packet: 1, info: "200 OK", uri: "", callID: "1450530377152201062221@10.33.6.101", from: "<sip:201@10.33.6.101>;tag=1c1450530943", to: "<sip:101@10.33.6.100;user=phone>;tag=1c782609321", cseq: "1 INVITE", contact: "<sip:101@10.33.6.100:5060>", src: "10.33.6.100:5060", dst: "10.33.6.101:5060", transport: "UDP", time: "2011-08-09T06:32:58.525951Z"},
		},
	},
	{
		file:     "pcapplusplus-sip-port52380.pcap",
		packets:  2,
		messages: 2,
		callIDs:  2,
		seq:      "1:INVITE 2:200",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:1006@192.168.21.83:52380", callID: "0c3bab2cebe34ec997a80daa4346b393", from: "<sip:1005@192.168.21.83>;tag=a50bffb5ddd3426e8f848ece7d0d389b", to: "<sip:1006@192.168.21.83>", cseq: "12003 INVITE", contact: "<sip:1005@192.168.20.68:53309;ob>", src: "192.168.20.68:53309", dst: "192.168.21.83:52380", transport: "UDP", time: "2025-12-22T16:21:01.358045Z"},
			{packet: 2, info: "200 OK", uri: "", callID: "0c1fb1c5-59f5-123f-1ab0-005056a58049", from: "\"Extension 1005\" <sip:1005@192.168.21.83>;tag=9ctQt2N5Zm5FD", to: "<sip:1006@192.168.20.68;ob>;tag=520e46519ce94352bef2606aaad6333c", cseq: "108656438 INVITE", contact: "<sip:1006@192.168.20.68:57586;ob>", src: "192.168.20.68:57586", dst: "192.168.21.83:52380", transport: "UDP", time: "2025-12-22T16:21:02.787319Z"},
		},
	},
	{
		file:     "pcapplusplus-sip-publish.pcap",
		packets:  1,
		messages: 1,
		callIDs:  1,
		seq:      "1:PUBLISH",
		checks: []check{
			{packet: 1, info: "PUBLISH", uri: "sip:telephone1@172.16.98.101;transport=UDP", callID: "ZGM3MGRjZWQyMjg0MjRlMjdmZTM4YWZlODIzOGZjZDc.", from: "<sip:telephone1@172.16.98.101;transport=UDP>;tag=cf63c934", to: "<sip:telephone1@172.16.98.101;transport=UDP>", cseq: "1 PUBLISH", contact: "<sip:telephone1@172.16.98.1:42952;transport=UDP>", src: "172.16.98.1:42952", dst: "172.16.98.101:5060", transport: "UDP", time: "2016-05-17T08:04:00.336117Z"},
		},
	},
	{
		file:     "pcapplusplus-sip-requests-pppoe.pcap",
		packets:  4,
		messages: 4,
		callIDs:  3,
		seq:      "1:INVITE 2:CANCEL 3:ACK 4:BYE",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 4, info: "BYE", uri: "sip:sipp@10.0.2.20:5060", callID: "1-4247@10.0.2.20", from: "test <sip:test@10.0.2.15:5060>;tag=j6QZcFDB22vSN", to: "\"speex/16000\" <sip:sipp@10.0.2.20:5060>;tag=1", cseq: "99791795 BYE", contact: "", src: "10.0.2.15:5060", dst: "10.0.2.20:5060", transport: "UDP", time: "2016-11-27T14:08:39.610514Z"},
		},
	},
	{
		file:     "pcapplusplus-sip-responses.pcap",
		packets:  7,
		messages: 7,
		callIDs:  5,
		seq:      "1:100 2:180 3:200 4:401 5:401 6:504 7:503",
		checks: []check{
			{packet: 1, info: "100 Trying", uri: "", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=298852044", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:02.973833Z"},
			{packet: 7, info: "503 Service Unavailable", uri: "", callID: "1831883062", from: "<sip:user155@ims.hom>;tag=193822779", to: "<sip:user155@ims.hom>;tag=z9hG4bKPjGE3INi51plg2DTc0WHnSGS0eld7PiYeo", cseq: "1 REGISTER", contact: "", src: "10.129.34.51:5060", dst: "10.3.160.214:5060", transport: "UDP", time: "2014-10-10T18:42:29.724840Z"},
		},
	},
	{
		file:     "sngrep-ipip-tcp.pcap",
		packets:  4,
		messages: 4,
		callIDs:  1,
		seq:      "1:INVITE 2:183 3:200 4:BYE",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:1bdaa608131517540001@172.28.1.3;transport=tcp", callID: "1RLuVzzBClYCf2", from: "<sip:1bdaa608131517540000@10.15.197.103>;tag=jr57na6shh", to: "<sip:1bdaa608131517540000@10.15.193.31>", cseq: "6 INVITE", contact: "<sip:1bdaa608131517540000-1bdaa608131517540000-ashteadiev-4@10.15.197.103:5090;transport=tcp>", src: "10.15.197.103:5090", dst: "10.15.193.31:33093", transport: "TCP", time: "2021-12-14T13:49:07.335564Z"},
			{packet: 4, info: "BYE", uri: "sip:1bdaa608131517540001@172.28.1.3;transport=tcp", callID: "1RLuVzzBClYCf2", from: "<sip:1bdaa608131517540000@10.15.197.103>;tag=jr57na6shh", to: "<sip:1bdaa608131517540000@10.15.193.31>;tag=to-tag", cseq: "16 BYE", contact: "<sip:1bdaa608131517540000-1bdaa608131517540000-ashteadiev-4@10.15.197.103:5090;transport=tcp>", src: "10.15.197.103:5090", dst: "10.15.193.31:33093", transport: "TCP", time: "2021-12-14T13:49:41.007679Z"},
		},
	},
	{
		file:     "sngrep-ipv6-frag-sll.pcap",
		packets:  34,
		messages: 32,
		callIDs:  1,
		seq:      "2:INVITE 3:100 5:INVITE 6:183 7:183 8:PRACK 9:PRACK 10:200 11:200 12:UPDATE 13:UPDATE 14:200 15:200 16:183 17:183 18:PRACK 19:PRACK 20:200 21:200 22:UPDATE 23:UPDATE 24:200 25:200 26:200 27:200 28:200 29:ACK 30:ACK 31:BYE 32:BYE 33:200 34:200",
		checks: []check{
			{packet: 2, info: "INVITE", uri: "sip:08019200028@[fd17:625c:f037:2:a00:27ff:feb9:4222]:25060", callID: "71846-1647924829-397430@fd17:625c:f037:2:a00:27ff:feb9:1521", from: "sipp <sip:sipp@[fd17:625c:f037:2:a00:27ff:feb9:1521]:15060>;tag=397430SIPpTag0071846", to: "mcr <sip:mcr@[fd17:625c:f037:2:a00:27ff:feb9:3519]:5062>", cseq: "1 INVITE", contact: "sip:sipp@[fd17:625c:f037:2:a00:27ff:feb9:1521]:15060", src: "[fd17:625c:f037:2:a00:27ff:feb9:1521]:15060", dst: "[fd17:625c:f037:2:a00:27ff:feb9:3519]:5062", transport: "UDP", time: ""},
			{packet: 34, info: "200 OK", uri: "", callID: "71846-1647924829-397430@fd17:625c:f037:2:a00:27ff:feb9:1521", from: "\"sipp\" <sip:sipp@[fd17:625c:f037:2:a00:27ff:feb9:1521]:15060>;tag=397430SIPpTag0071846", to: "\"mcr\" <sip:mcr@[fd17:625c:f037:2:a00:27ff:feb9:3519]:5062>;tag=1632476SIPpTag0171847", cseq: "2 BYE", contact: "<sip:[fd17:625c:f037:2:a00:27ff:feb9:4222]:25060;transport=UDP>", src: "[fd17:625c:f037:2:a00:27ff:feb9:3519]:5062", dst: "[fd17:625c:f037:2:a00:27ff:feb9:1521]:15060", transport: "UDP", time: "2022-03-22T05:23:10.661924Z"},
		},
	},
	{
		file:     "suricata-sip-body-frames-cloudshark.pcap",
		packets:  10,
		messages: 10,
		callIDs:  3,
		seq:      "1:INVITE 2:100 3:180 4:200 5:ACK 6:REGISTER 7:200 8:INVITE 9:100 10:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 10, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658696Z"},
		},
	},
	{
		file:     "suricata-sip-body-large-tcp-loopback.pcap",
		packets:  16,
		messages: 2,
		callIDs:  1,
		seq:      "5:INVITE 11:100",
		checks: []check{
			{packet: 5, info: "INVITE", uri: "sip:bob@target.com", callID: "test123@attacker.com", from: "<sip:alice@attacker.com>;tag=abc123", to: "<sip:bob@target.com>", cseq: "1 INVITE", contact: "", src: "127.0.0.1:59809", dst: "127.0.0.1:5060", transport: "TCP", time: "2026-06-23T19:37:32.935667Z"},
			{packet: 11, info: "100 Trying", uri: "", callID: "test123@attacker.com", from: "<sip:alice@attacker.com>;tag=abc123", to: "<sip:bob@target.com>", cseq: "1 INVITE", contact: "", src: "127.0.0.1:5060", dst: "127.0.0.1:59809", transport: "TCP", time: "2026-06-23T19:37:32.935965Z"},
		},
	},
	{
		file:     "suricata-sip-compact-form.pcap",
		packets:  1,
		messages: 1,
		callIDs:  1,
		seq:      "1:INVITE",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:97239287044@voip.brujula.net", callID: "105090259-446faf7a@192.168.1.2", from: "\\\"arik\\\" <sip:816666@voip.brurjula.net>;tag=6433ef9", to: "<sip:97239287044@voip.brujula.net>", cseq: "1 INVITE", contact: "<sip:816666@192.168.1.2>", src: "1.1.1.1:5555", dst: "2.2.2.2:5060", transport: "UDP", time: "2024-04-18T13:14:56.386450Z"},
		},
	},
	{
		file:     "suricata-sip-header-multi-value.pcap",
		packets:  1,
		messages: 1,
		callIDs:  1,
		seq:      "1:INVITE",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:97239287044@voip.brujula.net", callID: "105090259-446faf7a@192.168.1.2", from: "\\\"arik\\\" <sip:816666@voip.brurjula.net>;tag=6433ef9", to: "<sip:97239287044@voip.brujula.net>", cseq: "1 INVITE", contact: "<sip:816666@192.168.1.2>", src: "1.1.1.1:5555", dst: "2.2.2.2:5060", transport: "UDP", time: "2024-06-19T15:21:33.156061Z"},
		},
	},
	{
		file:     "suricata-sip-options.pcap",
		packets:  2,
		messages: 2,
		callIDs:  1,
		seq:      "1:OPTIONS 2:200",
		checks: []check{
			{packet: 1, info: "OPTIONS", uri: "sip:test@example.com", callID: "1234567890@192.168.1.10", from: "<sip:alice@example.com>;tag=1234", to: "<sip:test@example.com>", cseq: "1 OPTIONS", contact: "<sip:alice@192.168.1.10:5060>", src: "192.168.1.10:5060", dst: "192.168.1.20:5060", transport: "UDP", time: "2026-05-30T11:46:30.686694Z"},
			{packet: 2, info: "200 OK", uri: "", callID: "1234567890@192.168.1.10", from: "<sip:alice@example.com>;tag=1234", to: "<sip:test@example.com>;tag=5678", cseq: "1 OPTIONS", contact: "", src: "192.168.1.20:5060", dst: "192.168.1.10:5060", transport: "UDP", time: "2026-05-30T11:46:30.686973Z"},
		},
	},
	{
		file:     "suricata-sip-sdp.pcap",
		packets:  2,
		messages: 2,
		callIDs:  1,
		seq:      "1:INVITE 2:200",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:97239287044@voip.brujula.net", callID: "105090259-446faf7a@192.168.1.2", from: "\\\"arik\\\" <sip:816666@voip.brurjula.net>;tag=6433ef9", to: "<sip:97239287044@voip.brujula.net>", cseq: "1 INVITE", contact: "<sip:816666@192.168.1.2>", src: "1.1.1.1:5555", dst: "2.2.2.2:5060", transport: "UDP", time: "2024-10-15T07:28:53.934216Z"},
			{packet: 2, info: "200 Ok", uri: "", callID: "105090259-446faf7a@192.168.1.2", from: "\\\"arik\\\" <sip:816666@voip.brurjula.net>;tag=6433ef9", to: "<sip:97239287044@voip.brujula.net>", cseq: "1 INVITE", contact: "<sip:816666@192.168.1.2>", src: "2.2.2.2:5060", dst: "1.1.1.1:5555", transport: "UDP", time: "2024-10-15T07:28:53.934449Z"},
		},
	},
	{
		file:     "suricata-sip-tcp-port5062.pcap",
		packets:  7,
		messages: 2,
		callIDs:  1,
		seq:      "4:REGISTER 6:401",
		checks: []check{
			{packet: 4, info: "REGISTER", uri: "sip:sip.cybercity.dk", callID: "578222729-4665d775@578222732-4665d772", from: "<sip:voi18063@sip.cybercity.dk>;tag=903df0a", to: "<sip:voi18063@sip.cybercity.dk>", cseq: "68 REGISTER", contact: "<sip:voi18063@192.168.1.2:5060;line=9c7d2dbd8822013c>;expires=1200;q=0.500", src: "1.1.1.1:5555", dst: "2.2.2.2:5062", transport: "TCP", time: "2023-11-25T07:55:05.696011Z"},
			{packet: 6, info: "401 Unauthorized", uri: "", callID: "578222729-4665d775@578222732-4665d772", from: "<sip:voi18063@sip.cybercity.dk>;tag=903df0a", to: "<sip:voi18063@sip.cybercity.dk>;tag=00-04092-1701af62-120c67172", cseq: "68 REGISTER", contact: "", src: "2.2.2.2:5062", dst: "1.1.1.1:5555", transport: "TCP", time: "2023-11-25T07:55:05.696417Z"},
		},
	},
	{
		file:     "suricata-sip-tcp-register.pcap",
		packets:  11,
		messages: 2,
		callIDs:  1,
		seq:      "4:REGISTER 8:200",
		checks: []check{
			{packet: 4, info: "REGISTER", uri: "sip:192.168.43.100;transport=TCP", callID: "8OmtYUU8EdlafUh4g4jiAw..", from: "<sip:987654@192.168.43.100;transport=TCP>;tag=9b99167f", to: "<sip:987654@192.168.43.100;transport=TCP>", cseq: "1 REGISTER", contact: "<sip:987654@192.168.43.1:48376;rinstance=be2ec98d0f43e70c;transport=tcp>", src: "127.0.0.1:58882", dst: "127.0.0.1:5060", transport: "TCP", time: "2022-02-02T18:52:14.643241Z"},
			{packet: 8, info: "200 OK", uri: "", callID: "8OmtYUU8EdlafUh4g4jiAw..", from: "<sip:987654@192.168.43.100;transport=TCP>;tag=9b99167f", to: "<sip:987654@192.168.43.100;transport=TCP>;tag=9dd61ff61e802d8e2bef5f14621ef3c2.5c1b", cseq: "1 REGISTER", contact: "<sip:987654@192.168.43.1:48376;rinstance=be2ec98d0f43e70c;transport=tcp>;expires=600", src: "127.0.0.1:5060", dst: "127.0.0.1:58882", transport: "TCP", time: "2022-02-02T18:52:14.643471Z"},
		},
	},
	{
		file:     "suricata-sip-udp-port5062.pcap",
		packets:  2,
		messages: 2,
		callIDs:  1,
		seq:      "1:REGISTER 2:401",
		checks: []check{
			{packet: 1, info: "REGISTER", uri: "sip:sip.cybercity.dk", callID: "578222729-4665d775@578222732-4665d772", from: "<sip:voi18063@sip.cybercity.dk>;tag=903df0a", to: "<sip:voi18063@sip.cybercity.dk>", cseq: "68 REGISTER", contact: "<sip:voi18063@192.168.1.2:5060;line=9c7d2dbd8822013c>;expires=1200;q=0.500", src: "1.1.1.1:5555", dst: "2.2.2.2:5062", transport: "UDP", time: "2023-11-25T07:56:28.324229Z"},
			{packet: 2, info: "401 Unauthorized", uri: "", callID: "578222729-4665d775@578222732-4665d772", from: "<sip:voi18063@sip.cybercity.dk>;tag=903df0a", to: "<sip:voi18063@sip.cybercity.dk>;tag=00-04092-1701af62-120c67172", cseq: "68 REGISTER", contact: "", src: "2.2.2.2:5062", dst: "1.1.1.1:5555", transport: "UDP", time: "2023-11-25T07:56:28.324520Z"},
		},
	},
	{
		file:     "wireshark-asterisk-zfone-xlite.pcap",
		packets:  1042,
		messages: 27,
		callIDs:  5,
		seq:      "1:REGISTER 2:401 3:REGISTER 4:OPTIONS 5:200 6:200 7:SUBSCRIBE 8:401 9:SUBSCRIBE 10:401 11:SUBSCRIBE 12:404 13:SUBSCRIBE 14:404 15:INVITE 16:401 17:ACK 18:INVITE 19:100 20:180 23:200 27:ACK 1036:INVITE 1039:200 1040:ACK 1041:BYE 1042:200",
		checks: []check{
			{packet: 1, info: "REGISTER", uri: "sip:192.168.10.2", callID: "M2NhZDAwZmYwZGNkYmZjYzQzYmY1MTMxMDQ2MzkzMTk.", from: "\"Philippec2\"<sip:10009@192.168.10.2>;tag=65f92ced", to: "\"Philippec2\"<sip:10009@192.168.10.2>", cseq: "1 REGISTER", contact: "<sip:10009@192.168.10.41:13434;rinstance=309c3e58798d5f69>", src: "192.168.10.41:13434", dst: "192.168.10.2:5060", transport: "UDP", time: "2010-09-27T07:12:49.978304Z"},
			{packet: 1042, info: "200 OK", uri: "", callID: "ZDYzOWVlNjEwM2NjZTBjNzliNmM1ZTNiOGZjNWFhN2E.", from: "\"philippec1\"<sip:10008@192.168.10.2>;tag=as0b1a917b", to: "\"Philippec2\"<sip:10009@192.168.10.2>;tag=40580753", cseq: "103 BYE", contact: "<sip:10009@192.168.10.41:13434>", src: "192.168.10.41:13434", dst: "192.168.10.2:5060", transport: "UDP", time: "2010-09-27T07:13:22.468332Z"},
		},
	},
	{
		file:     "wireshark-dtmf-sipinfo.pcap",
		packets:  32,
		messages: 32,
		callIDs:  1,
		seq:      "1:INVITE 2:INVITE 3:100 4:200 5:INVITE 6:CANCEL 7:CANCEL 8:100 9:ACK 10:200 11:ACK 12:200 13:100 14:200 15:200 16:ACK 17:INFO 18:200 19:INFO 20:200 21:INVITE 22:100 23:200 24:ACK 25:INVITE 26:100 27:200 28:ACK 29:INFO 30:200 31:INFO 32:200",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:echo@iptel.org", callID: "2091060b-146f-e011-809a-0019cb53db77@admind-desktop", from: "\"sam netmon \" <sip:admind@178.45.73.241>;tag=bc86060b-146f-e011-809a-0019cb53db77", to: "<sip:echo@iptel.org>", cseq: "1 INVITE", contact: "<sip:admind@178.45.73.241>", src: "178.45.73.241:5060", dst: "213.192.59.75:5060", transport: "UDP", time: "2011-04-27T08:14:29.846846Z"},
			{packet: 32, info: "200 OK", uri: "", callID: "2091060b-146f-e011-809a-0019cb53db77@admind-desktop", from: "\"sam netmon \" <sip:admind@178.45.73.241>;tag=bc86060b-146f-e011-809a-0019cb53db77", to: "<sip:echo@iptel.org>;tag=420976BC-4DB7D064000EE90C-B692BBB0", cseq: "10 INFO", contact: "<sip:echo@213.192.59.78:5080>", src: "213.192.59.75:5060", dst: "178.45.73.241:5060", transport: "UDP", time: "2011-04-27T08:15:48.321286Z"},
		},
	},
	{
		file:     "wireshark-fax-t38.pcap",
		packets:  92,
		messages: 92,
		callIDs:  2,
		seq:      "1:INVITE 2:INVITE 3:100 4:INVITE 5:INVITE 6:100 7:100 8:100 9:180 10:180 11:180 12:180 13:200 14:200 15:200 16:200 17:ACK 18:ACK 19:ACK 20:ACK 21:INVITE 22:100 23:INVITE 24:INVITE 25:100 26:100 27:200 28:200 29:INVITE 30:100 31:200 32:200 33:ACK 34:ACK 35:ACK 36:ACK 37:OPTIONS 38:OPTIONS 39:OPTIONS 40:OPTIONS 41:200 42:200 43:200 44:200 45:INVITE 46:INVITE 47:100 48:100 49:INVITE 50:100 51:INVITE 52:100 53:488 54:ACK 55:488 56:488 57:488 58:ACK 59:ACK 60:ACK 61:INVITE 62:100 63:INVITE 64:INVITE 65:INVITE 66:100 67:100 68:100 69:200 70:200 71:200 72:200 73:ACK 74:ACK 75:ACK 76:ACK 77:OPTIONS 78:OPTIONS 79:OPTIONS 80:OPTIONS 81:200 82:200 83:200 84:200 85:BYE 86:BYE 87:BYE 88:BYE 89:200 90:200 91:200 92:200",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:061963177-ikhuuep5bi123@10.35.60.100:5060;transport=udp", callID: "00e9d4a500e9d48-0015-0001-0000-0000@10.35.40.25", from: "<sip:unavailable@hostportion>;tag=00e9d478", to: "<sip:061963177@italtel.it;user=phone>", cseq: "1 INVITE", contact: "<sip:anonymous.iIiIiI.0a232819.@10.35.60.72>", src: "10.35.60.72:5060", dst: "10.35.60.100:5060", transport: "UDP", time: "2008-12-05T09:22:38.651179Z"},
			{packet: 92, info: "200 OK", uri: "", callID: "00e9d4a500e9d48-0015-0001-0000-0000@10.35.40.25", from: "<sip:unavailable@hostportion>;tag=00e9d478", to: "<sip:061963177@italtel.it;user=phone>;tag=SD4909799-617263616479616E-331715520-5336f785-187410205", cseq: "6 BYE", contact: "", src: "10.35.40.200:5060", dst: "10.35.40.25:5060", transport: "UDP", time: "2008-12-05T09:24:02.445270Z"},
		},
	},
	{
		file:     "wireshark-h263-over-rtp.pcap",
		packets:  49,
		messages: 4,
		callIDs:  1,
		seq:      "1:INVITE 2:100 3:200 4:ACK",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:auto@localhost", callID: "NmNhYWNhMjY0Y2M0OTc4YTI2MzgzZTNlYTRhZTMxNTE.", from: "\"Matthew Hodgson\"<sip:matthew@mxtelecom.com>;tag=5c7cdb68", to: "\"sip:auto@localhost\"<sip:auto@localhost>", cseq: "1 INVITE", contact: "<sip:matthew@127.0.0.1:13764>", src: "127.0.0.1:13764", dst: "127.0.0.1:5060", transport: "UDP", time: "2008-04-15T12:19:44.291540Z"},
			{packet: 4, info: "ACK", uri: "sip:127.0.0.1:5060", callID: "NmNhYWNhMjY0Y2M0OTc4YTI2MzgzZTNlYTRhZTMxNTE.", from: "\"Matthew Hodgson\"<sip:matthew@mxtelecom.com>;tag=5c7cdb68", to: "\"sip:auto@localhost\"<sip:auto@localhost>;tag=tCAED3F5A", cseq: "1 ACK", contact: "<sip:matthew@127.0.0.1:13764>", src: "127.0.0.1:13764", dst: "127.0.0.1:5060", transport: "UDP", time: "2008-04-15T12:19:44.712119Z"},
		},
	},
	{
		file:     "wireshark-magicjack-short-call.pcap",
		packets:  50,
		messages: 11,
		callIDs:  1,
		seq:      "9:INVITE 10:100 11:401 12:ACK 13:INVITE 14:100 15:183 16:200 17:ACK 18:BYE 19:200",
		checks: []check{
			{packet: 9, info: "INVITE", uri: "sip:9055551212@talk4free.com", callID: "C5570127C1A6A1ABF7ED9DB9AD608CE00xc0a8000a", from: "\"unknown\" <sip:E646657195201@talk4free.com>;tag=2afc8c735218176", to: "<sip:9055551212@talk4free.com>", cseq: "1 INVITE", contact: "<sip:E646657195201@192.168.0.10:59205>", src: "192.168.0.10:59205", dst: "216.234.64.8:5070", transport: "UDP", time: "2012-04-12T15:40:15.711324Z"},
			{packet: 19, info: "200 OK", uri: "", callID: "C5570127C1A6A1ABF7ED9DB9AD608CE00xc0a8000a", from: "<sip:9055551212@talk4free.com>;tag=30da0aed-co12170-INS015", to: "\"unknown\" <sip:E646657195201@talk4free.com>;tag=2afc8c735218176", cseq: "1217001 BYE", contact: "<sip:E646657195201@192.168.0.10:59205>", src: "192.168.0.10:59205", dst: "216.234.64.8:5070", transport: "UDP", time: "2012-04-12T15:40:35.625275Z"},
		},
	},
	{
		file:     "wireshark-metasploit-invite-spoof.pcap",
		packets:  3,
		messages: 2,
		callIDs:  1,
		seq:      "1:INVITE 2:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:@127.0.0.1", callID: "14810.0.1.45", from: "\"testtest\"<sip:10.0.1.199>", to: "<sip:10.0.1.45>", cseq: "1 INVITE", contact: "<sip:127.0.0.1>", src: "10.0.1.199:62986", dst: "10.0.1.45:10270", transport: "UDP", time: "2007-04-05T01:51:18.700063Z"},
			{packet: 2, info: "180 Ringing", uri: "", callID: "14810.0.1.45", from: "\"testtest\"<sip:10.0.1.199>", to: "<sip:10.0.1.45>;tag=20d70673", cseq: "1 INVITE", contact: "<sip:127.0.0.1>", src: "10.0.1.45:10270", dst: "10.0.1.199:5060", transport: "UDP", time: "2007-04-05T01:51:18.801137Z"},
		},
	},
	{
		file:     "wireshark-nb6-startup.pcap",
		packets:  531,
		messages: 4,
		callIDs:  1,
		seq:      "279:REGISTER 280:401 281:REGISTER 282:200",
		checks: []check{
			{packet: 279, info: "REGISTER", uri: "sip:ims.mnc010.mcc208.3gppnetwork.org", callID: "BEBA3F51D67EDA@10.251.23.139", from: "\"0360653674\" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org>;tag=17BC4C57", to: "\"0360653674\" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org>", cseq: "1 REGISTER", contact: "<sip:+33360653674@10.251.23.139:5060;user=phone>", src: "10.251.23.139:5060", dst: "172.26.235.86:5062", transport: "UDP", time: "2014-01-02T08:25:49.500976Z"},
			{packet: 282, info: "200 OK", uri: "", callID: "BEBA3F51D67EDA@10.251.23.139", from: "\"0360653674\" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org>;tag=17BC4C57", to: "\"0360653674\" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org>;tag=51d541c6-1388651149675081", cseq: "2 REGISTER", contact: "<sip:+33360653674@10.251.23.139:5060;user=phone>;expires=3171", src: "172.26.235.86:5062", dst: "10.251.23.139:5060", transport: "UDP", time: "2014-01-02T08:25:49.689674Z"},
		},
	},
	{
		file:     "wireshark-nb6-telephone.pcap",
		packets:  527,
		messages: 7,
		callIDs:  1,
		seq:      "5:INVITE 6:100 7:183 9:200 18:ACK 522:BYE 524:200",
		checks: []check{
			{packet: 5, info: "INVITE", uri: "sip:147@ims.mnc010.mcc208.3gppnetwork.org;user=phone", callID: "1135D8701739D86@10.251.23.139", from: "\"0360653674\" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org;user=phone>;tag=66891B8", to: "<sip:147@ims.mnc010.mcc208.3gppnetwork.org;user=phone>", cseq: "1 INVITE", contact: "<sip:+33360653674@10.251.23.139:5060;user=phone>", src: "10.251.23.139:5060", dst: "172.22.75.71:5062", transport: "UDP", time: "2014-01-01T19:23:51.036868Z"},
			{packet: 524, info: "200 OK", uri: "", callID: "1135D8701739D86@10.251.23.139", from: "\"0360653674\" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org;user=phone>;tag=66891B8", to: "<sip:147@ims.mnc010.mcc208.3gppnetwork.org;user=phone>;tag=524b656f-138860423163019-gm-po-lucentPCSF-021676", cseq: "2 BYE", contact: "<sip:pcgw-0006.imsgroup0-005.ach4isc02.ims.sfr.net:5062>", src: "172.22.75.71:5062", dst: "10.251.23.139:5060", transport: "UDP", time: "2014-01-01T19:23:56.586533Z"},
		},
	},
	{
		file:     "wireshark-switchport-sip-with-arp-stp.pcap",
		packets:  316,
		messages: 3,
		callIDs:  1,
		seq:      "5:INVITE 16:ACK 292:BYE",
		checks: []check{
			{packet: 5, info: "INVITE", uri: "sip:6001@192.168.25.202:5060;transport=udp", callID: "2247957968-92448163@192.168.24.200", from: "\"j.test\" <sip:6601@192.168.24.200>;tag=0_2247957968-92448165", to: "<sip:6001@192.168.25.202>", cseq: "1 INVITE", contact: "\"j.test\" <sip:6601@192.168.24.200:5060;transport=udp>", src: "192.168.24.200:5060", dst: "192.168.25.202:5060", transport: "UDP", time: "2009-11-17T16:37:43.615240Z"},
			{packet: 292, info: "BYE", uri: "sip:6001@192.168.25.202:5060;transport=udp", callID: "2247957968-92448163@192.168.24.200", from: "\"j.test\" <sip:6601@192.168.24.200>;tag=0_2247957968-92448165", to: "<sip:6001@192.168.25.202>;tag=0_3010231744-92878190", cseq: "2 BYE", contact: "", src: "192.168.24.200:5060", dst: "192.168.25.202:5060", transport: "UDP", time: "2009-11-17T16:37:50.572947Z"},
		},
	},
	{
		file:     "wireshark-rtp-conversacion.pcap",
		packets:  13,
		messages: 12,
		callIDs:  2,
		seq:      "1:INVITE 2:407 3:ACK 4:INVITE 5:100 6:180 7:200 8:ACK 9:OPTIONS 10:200 12:BYE 13:200",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:101@192.168.1.78", callID: "N2E5MDkwN2RjYzAwZTA1OTc0YTI3N2QzMjU5ZmYzNTI.", from: "\"Gonzalo\"<sip:102@192.168.1.78>;tag=fb22e144", to: "\"101\"<sip:101@192.168.1.78>", cseq: "1 INVITE", contact: "<sip:102@192.168.1.64:11384>", src: "192.168.1.64:11384", dst: "192.168.1.78:5060", transport: "UDP", time: "2010-05-13T22:17:24.562466Z"},
			{packet: 13, info: "200 OK", uri: "", callID: "N2E5MDkwN2RjYzAwZTA1OTc0YTI3N2QzMjU5ZmYzNTI.", from: "\"Gonzalo\"<sip:102@192.168.1.78>;tag=fb22e144", to: "\"101\"<sip:101@192.168.1.78>;tag=as3d3a7c12", cseq: "3 BYE", contact: "<sip:101@192.168.1.78>", src: "192.168.1.78:5060", dst: "192.168.1.64:11384", transport: "UDP", time: "2010-05-13T22:17:50.900888Z"},
		},
	},
	{
		file:     "wireshark-sctp-megaco-bigendian.pcap",
		packets:  4,
		messages: 0,
		callIDs:  0,
		seq:      "",
	},
	{
		file:     "wireshark-sip-call-g711.pcap",
		packets:  539,
		messages: 14,
		callIDs:  4,
		seq:      "1:INVITE 2:100 3:180 56:REGISTER 57:200 247:200 249:ACK 313:REGISTER 314:200 427:REGISTER 428:200 442:INVITE 443:100 444:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 444, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658696Z"},
		},
	},
	{
		file:     "wireshark-sip-dtmf2.pcap",
		packets:  29,
		messages: 29,
		callIDs:  5,
		seq:      "1:REGISTER 2:100 3:200 4:REGISTER 5:100 6:200 7:INVITE 8:100 9:603 10:ACK 11:REGISTER 12:100 13:200 14:INVITE 15:100 16:INVITE 17:100 18:180 19:180 20:200 21:200 22:ACK 23:ACK 24:REGISTER 25:100 26:200 27:REGISTER 28:100 29:200",
		checks: []check{
			{packet: 1, info: "REGISTER", uri: "sip:192.168.105.105", callID: "3070@192.168.105.105", from: "2503 <sip:2503@192.168.105.105>;tag=11113", to: "2503 <sip:2503@192.168.105.105>", cseq: "1 REGISTER", contact: "\"2503\" <sip:2503@192.168.105.110:5060;transport=udp>", src: "192.168.105.110:5060", dst: "192.168.105.105:5060", transport: "UDP", time: "2005-09-09T12:02:25.330945Z"},
			{packet: 29, info: "200 OK", uri: "", callID: "18585@192.168.105.105", from: "2502 <sip:2502@192.168.105.105>;tag=21645", to: "2502 <sip:2502@192.168.105.105>;tag=1126267445359--1195183179", cseq: "2 REGISTER", contact: "\"2502\" <sip:2502@192.168.105.110:5060>;expires=3600;q=1.0", src: "192.168.105.105:5060", dst: "192.168.105.110:5060", transport: "UDP", time: "2005-09-09T12:04:05.367724Z"},
		},
	},
	{
		file:     "wireshark-sip-rawip.pcapng",
		packets:  6,
		messages: 5,
		callIDs:  2,
		seq:      "1:REGISTER 2:200 3:INVITE 4:100 6:181",
		checks: []check{
			{packet: 1, info: "REGISTER", uri: "sip:csp.noklab.net", callID: "003094c3-a0160002-23aa7e86-29e5808d@192.168.1.100", from: "sip:34903@csp.noklab.net", to: "sip:34903@csp.noklab.net", cseq: "144 REGISTER", contact: "<sip:34903@192.168.1.100:5060>", src: "10.102.130.150:5060", dst: "10.102.130.185:5060", transport: "UDP", time: "2014-03-06T13:34:49.416000Z"},
			{packet: 6, info: "181 Call Is Being Forwarded", uri: "", callID: "7f00000113ce0000047b000cd140@127.0.0.1", from: "\"B5-2C23-052 Blu\"<sip:7323685154@127.25.29.135:5060>;tag=0000047b000ce0e0", to: "<sip:17324201111@135.25.31.10:5060>", cseq: "2 INVITE", contact: "", src: "127.0.0.1:5060", dst: "127.0.0.1:5070", transport: "UDP", time: "2014-03-06T13:39:06.127000Z"},
		},
	},
	{
		file:     "wireshark-sip-rtp-g711.pcap",
		packets:  852,
		messages: 10,
		callIDs:  2,
		seq:      "1:INVITE 2:100 4:200 5:ACK 432:BYE 433:200 434:INVITE 435:100 437:200 438:ACK",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:test@10.0.2.15:5060", callID: "1-1966@10.0.2.20", from: "\"PCMU/8000\" <sip:sipp@10.0.2.20:5060>;tag=1", to: "test <sip:test@10.0.2.15:5060>", cseq: "1 INVITE", contact: "sip:sipp@10.0.2.20:5060", src: "10.0.2.20:5060", dst: "10.0.2.15:5060", transport: "UDP", time: "2016-11-26T14:52:59.666393Z"},
			{packet: 438, info: "ACK", uri: "sip:test@10.0.2.15:5060", callID: "1-1968@10.0.2.20", from: "\"PCMA/8000\" <sip:sipp@10.0.2.20:5060>;tag=1", to: "test <sip:test@10.0.2.15:5060>;tag=r5e24Nr505FjF", cseq: "1 ACK", contact: "sip:sipp@10.0.2.20:5060", src: "10.0.2.20:5060", dst: "10.0.2.15:5060", transport: "UDP", time: "2016-11-26T14:53:08.290927Z"},
		},
	},
	{
		file:     "wireshark-sip-rtp.pcapng",
		packets:  562,
		messages: 14,
		callIDs:  4,
		seq:      "1:INVITE 2:100 3:180 4:REGISTER 5:200 6:200 10:ACK 166:REGISTER 167:200 350:REGISTER 351:200 352:INVITE 353:100 354:180",
		checks: []check{
			{packet: 1, info: "INVITE", uri: "sip:francisco@bestel.com:55060", callID: "12013223@200.57.7.195", from: "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>", cseq: "1 INVITE", contact: "<sip:200.57.7.195:5060>", src: "200.57.7.195:5060", dst: "200.57.7.204:5061", transport: "UDP", time: "2005-01-14T17:58:02.965944Z"},
			{packet: 354, info: "180 Ringing", uri: "", callID: "12015624@200.57.7.195", from: "\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", to: "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=4098209679", cseq: "1 INVITE", contact: "<sip:francisco@200.57.7.204:5061>", src: "200.57.7.204:5061", dst: "200.57.7.195:5060", transport: "UDP", time: "2005-01-14T17:58:27.658696Z"},
		},
	},
	{
		file:     "zeek-sip-junk-before-request.pcap",
		packets:  2,
		messages: 1,
		callIDs:  0,
		seq:      "2:REGISTER",
		checks: []check{
			{packet: 2, info: "REGISTER", uri: "sip:1.1.1.1:5060", callID: "", from: "", to: "", cseq: "", contact: "", src: "1.1.1.1:31000", dst: "1.1.1.2:5060", transport: "UDP", time: "2021-04-14T22:00:12.376318Z"},
		},
	},
	{
		file:     "zeek-sip-long-paths-rawipv4.pcap",
		packets:  2,
		messages: 2,
		callIDs:  1,
		seq:      "1:OPTIONS 2:200",
		checks: []check{
			{packet: 1, info: "OPTIONS", uri: "sip:bob@example.com", callID: "path-growth@example.com", from: "<sip:alice@example.com>;tag=1", to: "<sip:bob@example.com>", cseq: "1 OPTIONS", contact: "", src: "192.0.2.10:50600", dst: "198.51.100.20:5060", transport: "UDP", time: "2023-11-14T22:13:20.000000Z"},
			{packet: 2, info: "200 OK", uri: "", callID: "path-growth@example.com", from: "<sip:alice@example.com>;tag=1", to: "<sip:bob@example.com>;tag=2", cseq: "1 OPTIONS", contact: "", src: "198.51.100.20:5060", dst: "192.0.2.10:50600", transport: "UDP", time: "2023-11-14T22:13:20.001000Z"},
		},
	},
}

// maxPacketsPerMessage bounds how many packets one message of the capture may
// occupy (the TCP captures reassemble messages over several segments).
func maxPacketsPerMessage(file string) int {
	if strings.Contains(file, "tcp") {
		return 8
	}
	return 1
}

func methodOrStatus(m trace.Message) string {
	if m.IsRequest {
		return m.Method
	}
	return strconv.Itoa(m.StatusCode)
}

func TestRealWorldCaptures(t *testing.T) {
	for _, rc := range realCaptures {
		t.Run(rc.file, func(t *testing.T) {
			res, err := readFile(context.Background(), realWorldDir+rc.file)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if res.Packets != rc.packets {
				t.Errorf("packets = %d, want %d", res.Packets, rc.packets)
			}
			if len(res.Messages) != rc.messages {
				t.Errorf("messages = %d, want %d", len(res.Messages), rc.messages)
			}
			// Datagram transports: one message per packet. TCP messages may
			// span several packets, which are all consumed, so Skipped can
			// only be bounded from above.
			if res.Skipped > res.Packets || res.Skipped < res.Packets-len(res.Messages)*maxPacketsPerMessage(rc.file) {
				t.Errorf("skipped = %d with %d packets and %d messages", res.Skipped, res.Packets, len(res.Messages))
			}

			ids := map[string]bool{}
			var seq []string
			byPacket := map[int]trace.Message{}
			prev := time.Time{}
			for _, m := range res.Messages {
				if m.CallID != "" {
					ids[m.CallID] = true
				}
				seq = append(seq, strconv.Itoa(m.Index)+":"+methodOrStatus(m))
				byPacket[m.Index] = m
				if m.Time.Location() != time.UTC {
					t.Errorf("packet %d: time zone = %v, want UTC", m.Index, m.Time.Location())
				}
				if m.Time.Before(prev) {
					t.Errorf("packet %d: time %v goes backwards (previous %v)", m.Index, m.Time, prev)
				}
				prev = m.Time
				if m.File != realWorldDir+rc.file {
					t.Errorf("packet %d: File = %q", m.Index, m.File)
				}
			}
			if len(ids) != rc.callIDs {
				t.Errorf("distinct Call-IDs = %d, want %d", len(ids), rc.callIDs)
			}
			if got := strings.Join(seq, " "); got != rc.seq {
				t.Errorf("message sequence:\n got %s\nwant %s", got, rc.seq)
			}

			for _, c := range rc.checks {
				m, ok := byPacket[c.packet]
				if !ok {
					t.Errorf("packet %d: no SIP message", c.packet)
					continue
				}
				fields := []struct{ name, got, want string }{
					{"info", m.Info(), c.info},
					{"request-uri", m.RequestURI, c.uri},
					{"call-id", m.CallID, c.callID},
					{"from", m.From, c.from},
					{"to", m.To, c.to},
					{"cseq", m.CSeq, c.cseq},
					{"contact", m.Contact, c.contact},
					{"src", m.SrcAddr().String(), c.src},
					{"dst", m.DstAddr().String(), c.dst},
					{"transport", m.Transport, c.transport},
				}
				for _, f := range fields {
					if f.got != f.want {
						t.Errorf("packet %d %s = %q, want %q", c.packet, f.name, f.got, f.want)
					}
				}
				if c.time != "" {
					want, err := time.Parse(time.RFC3339Nano, c.time)
					if err != nil {
						t.Fatalf("bad expected time %q: %v", c.time, err)
					}
					if !m.Time.Equal(want) {
						t.Errorf("packet %d time = %s, want %s", c.packet, m.Time.Format(time.RFC3339Nano), c.time)
					}
				}
			}
		})
	}
}

// All fixtures read together: totals add up and the merge is time ordered.
func TestRealWorldReadFilesMerge(t *testing.T) {
	var paths []string
	packets, messages := 0, 0
	for _, rc := range realCaptures {
		paths = append(paths, realWorldDir+rc.file)
		packets += rc.packets
		messages += rc.messages
	}
	res, err := readFiles(context.Background(), paths)
	if err != nil {
		t.Fatalf("ReadFiles: %v", err)
	}
	if res.Packets != packets || len(res.Messages) != messages {
		t.Errorf("packets/messages = %d/%d, want %d/%d", res.Packets, len(res.Messages), packets, messages)
	}
	if !slices.IsSortedFunc(res.Messages, func(a, b trace.Message) int { return a.Time.Compare(b.Time) }) {
		t.Error("merged messages are not sorted by time")
	}
}

// The first fragment of an IPv6 datagram carries the UDP header and the whole
// SIP header block; the reassembled message must therefore be reported with
// the time of one of its two fragments (packets 1 and 2, capture truth from
// tcpdump) and the UDP endpoints from the first fragment.
func TestRealWorldIPv6FragmentTime(t *testing.T) {
	res, err := readFile(context.Background(), realWorldDir+"sngrep-ipv6-frag-sll.pcap")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	m := res.Messages[0]
	if m.Index != 1 && m.Index != 2 {
		t.Fatalf("first message packet = %d, want 1 or 2", m.Index)
	}
	frag1, _ := time.Parse(time.RFC3339Nano, "2022-03-22T05:20:26.047902Z")
	frag2, _ := time.Parse(time.RFC3339Nano, "2022-03-22T05:20:26.047912Z")
	if !m.Time.Equal(frag1) && !m.Time.Equal(frag2) {
		t.Errorf("time = %s, want %s or %s", m.Time.Format(time.RFC3339Nano), frag1.Format(time.RFC3339Nano), frag2.Format(time.RFC3339Nano))
	}
	if m.Transport != "UDP" || m.SrcPort != 15060 || m.DstPort != 5062 {
		t.Errorf("transport/ports = %s %d>%d, want UDP 15060>5062", m.Transport, m.SrcPort, m.DstPort)
	}
}

// Wireshark's sip-tls-1.3 sample was written with capture lengths 16 bytes
// larger than the original packet lengths (the writer counted the SLL header
// in one but not the other). tcpdump prints "Invalid header" for each of its
// 40 records (`tcpdump -nn -r FILE | wc -l` is 41 with the link-type banner);
// libpcap-style tolerance reads them using the capture length. The traffic is
// SIP over TLS 1.3, so no plaintext SIP message is visible.
func TestRealWorldCaplenExceedsOriginal(t *testing.T) {
	path := realWorldDir + "wireshark-sip-tls13-caplen-gt-origlen.pcap"
	res, err := readFile(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %q, want none", res.Warnings)
	}
	if res.Packets != 40 || res.Skipped != 40 || len(res.Messages) != 0 {
		t.Errorf("packets/skipped/messages = %d/%d/%d, want 40/40/0", res.Packets, res.Skipped, len(res.Messages))
	}
}
