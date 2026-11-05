package query

import (
	"net/netip"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// msgField registers a built-in message field read by id.
func msgField(id fid, name string, aliases []string, t Type, doc string, values ...string) {
	f := Field{Name: name, Aliases: aliases, Type: t, Doc: doc, Values: values, id: id, classes: id == fStatus}
	g := f // the closure reads a stable copy; the registry keeps its own
	f.Message = func(m trace.Message) Value { return g.msgValue(&m) }
	RegisterField(f)
}

func callField(name string, aliases []string, t Type, doc string, get func(*call.Call) Value, values ...string) {
	RegisterField(Field{Name: name, Aliases: aliases, Type: t, Doc: doc, Values: values, Call: get, classes: name == "final_code"})
}

func init() {
	msgField(fMethod, "method", nil, TypeString, "request method; responses carry the method from CSeq: method = INVITE, method in (INVITE, BYE)")
	msgField(fStatus, "status", []string{"code"}, TypeInt, "response status code, null for requests: status = 486, status = 4xx, status in (404, 500..599)")
	msgField(fURI, "uri", []string{"request_uri", "ruri"}, TypeString, "Request-URI of a request: uri ~ sip:+4930")
	msgField(fCallID, "callid", []string{"call_id"}, TypeString, "Call-ID header: callid = 85216695@10.0.0.1")
	msgField(fFrom, "from", nil, TypeString, "whole From header (display name, URI, tag): from ~ alice")
	msgField(fTo, "to", nil, TypeString, "whole To header: to ~ \"+49 30\"")
	msgField(fFromUser, "from_user", nil, TypeString, "user part of the From URI: from_user = 100")
	msgField(fToUser, "to_user", nil, TypeString, "user part of the To URI: to_user = +4930123456")
	msgField(fFromTag, "from_tag", nil, TypeString, "tag parameter of From: from_tag = 1928301774")
	msgField(fToTag, "to_tag", nil, TypeString, "tag parameter of To; empty outside a dialog: to_tag = a6c85cf")
	msgField(fContact, "contact", nil, TypeString, "whole Contact header: contact ~ 192.168.")
	msgField(fCSeq, "cseq", nil, TypeString, "whole CSeq header: cseq = \"101 INVITE\"")
	msgField(fVia, "via", nil, TypeString, "topmost Via header: via ~ 10.0.0.5")
	msgField(fBranch, "branch", nil, TypeString, "branch parameter of the topmost Via: branch = z9hG4bK776asdhds")
	msgField(fSrc, "src", []string{"src_ip"}, TypeAddr, "source IP, CIDR aware: src = 10.0.0.0/8, src in (192.168.1.0/24, 2001:db8::/32)")
	msgField(fDst, "dst", []string{"dst_ip"}, TypeAddr, "destination IP, CIDR aware: dst = 203.0.113.9")
	msgField(fSport, "sport", []string{"src_port"}, TypeInt, "source port: sport = 5060")
	msgField(fDport, "dport", []string{"dst_port"}, TypeInt, "destination port: dport in (5060, 5061)")
	msgField(fTransport, "transport", nil, TypeEnum, "transport protocol: transport = tcp", "UDP", "TCP", "SCTP", "TLS", "WS", "WSS")
	msgField(fTime, "time", nil, TypeTime, "capture time (UTC): time > 2024-05-01T10:00:00Z, time >= 10:30 (time of day, any date)")
	msgField(fUA, "ua", nil, TypeString, "User-Agent of a request or Server of a response: ua ~ cisco")
	msgField(fIsRequest, "is_request", nil, TypeBool, "true for requests: is_request and method = INVITE")
	msgField(fIsResponse, "is_response", nil, TypeBool, "true for responses: is_response and status >= 500")
	msgField(fHasSDP, "has_sdp", nil, TypeBool, "message carries an SDP body (also inside multipart): has_sdp")
	msgField(fFile, "file", nil, TypeString, "capture file the packet came from: file ~ trunk-a")
	msgField(fIndex, "index", nil, TypeInt, "1-based packet number inside its file: index in 100..200")
	msgField(fRaw, "raw", nil, TypeString, "complete message text; a bare word searches here: raw ~ \"a=sendonly\"")
	msgField(fBody, "body", nil, TypeString, "message body (SDP etc.): body ~ a=inactive")

	callField("state", nil, TypeEnum, "where the call ended up: state = failed", func(c *call.Call) Value { return StringValue(string(c.State)) },
		string(call.StateInSetup), string(call.StateNoResponse), string(call.StateCancelled), string(call.StateRedirected),
		string(call.StateFailed), string(call.StateAnswered), string(call.StateCompleted), string(call.StateOK))
	callField("kind", nil, TypeEnum, "what opened the Call-ID: kind = call", func(c *call.Call) Value { return StringValue(string(c.Kind)) },
		string(call.KindCall), string(call.KindRegistration), string(call.KindSubscription), string(call.KindMessage),
		string(call.KindOptions), string(call.KindOther))
	callField("result", nil, TypeString, "\"<code> <reason>\" of the final response to the first request: result ~ busy", func(c *call.Call) Value { return StringValue(c.Result) })
	callField("final_code", []string{"final"}, TypeInt, "status of the final response to the first request, null if none: final_code = 486, final_code = 5xx",
		func(c *call.Call) Value { return nonZero(c.FinalCode) })
	callField("duration", nil, TypeDuration, "first to last message of the call: duration > 30s, duration < 2s", func(c *call.Call) Value {
		if c.Start.IsZero() {
			return Value{}
		}
		return DurationValue(c.Duration())
	})
	callField("pdd", nil, TypeDuration, "post-dial delay, INVITE to first 180/183: pdd > 3s", func(c *call.Call) Value { return nonZeroDur(c.PDD) })
	callField("ring_time", nil, TypeDuration, "first 180/183 to answer or final response: ring_time > 30s", func(c *call.Call) Value { return nonZeroDur(c.RingTime) })
	callField("setup_time", nil, TypeDuration, "INVITE to 200 OK: setup_time > 5s", func(c *call.Call) Value { return nonZeroDur(c.SetupTime) })
	callField("talk_time", nil, TypeDuration, "200 OK to first BYE: talk_time < 5s", func(c *call.Call) Value { return nonZeroDur(c.TalkTime) })
	callField("ended_by", nil, TypeEnum, "who sent the first BYE (CANCEL is always the caller); empty if neither: ended_by = callee",
		func(c *call.Call) Value { return StringValue(c.EndedBy) }, "caller", "callee")
	callField("end_method", nil, TypeEnum, "method that ended the call; empty if none: end_method = CANCEL",
		func(c *call.Call) Value { return StringValue(c.EndMethod) }, "BYE", "CANCEL")
	callField("reason", nil, TypeString, "Reason header (RFC 3326) of the terminating message: reason ~ q.850", func(c *call.Call) Value { return StringValue(c.Reason) })
	callField("retransmissions", []string{"retrans"}, TypeInt, "messages recognised as retransmissions: retransmissions >= 3", func(c *call.Call) Value { return IntValue(int64(c.Retransmissions)) })
	callField("msgs", []string{"messages"}, TypeInt, "number of SIP messages in the call: msgs > 100", func(c *call.Call) Value { return IntValue(int64(len(c.Messages))) })
	callField("codec", nil, TypeString, "negotiated or observed codec, any of them matches: codec = PCMA", codecs)
	callField("has_media", nil, TypeBool, "an RTP stream was correlated to the call: not has_media", func(c *call.Call) Value { return BoolValue(len(c.Streams) > 0) })
	callField("mos", nil, TypeFloat, "worst estimated MOS over the call's RTP streams, null without media: mos < 3.5", func(c *call.Call) Value { return minOver(c.Streams, func(s rtp.Stream) float64 { return s.MOS }, true) })
	callField("loss", nil, TypeFloat, "worst RTP packet loss in percent, null without media: loss > 1", func(c *call.Call) Value { return maxOver(c.Streams, func(s rtp.Stream) float64 { return s.LossPct }) })
	callField("jitter", nil, TypeDuration, "worst mean RTP jitter over the call's streams, null without media: jitter > 30ms", func(c *call.Call) Value {
		if len(c.Streams) == 0 {
			return Value{}
		}
		var m time.Duration
		for _, s := range c.Streams {
			m = max(m, s.JitterMean)
		}
		return DurationValue(m)
	})
	callField("user_agent", nil, TypeString, "every User-Agent/Server seen in the call, any of them matches: user_agent ~ asterisk", func(c *call.Call) Value { return StringsValue(c.UserAgents) })
	callField("start", nil, TypeTime, "time of the first message (UTC): start >= 2024-05-01 10:00", func(c *call.Call) Value { return TimeValue(c.Start) })
	callField("end", nil, TypeTime, "time of the last message (UTC): end < 12:00", func(c *call.Call) Value { return TimeValue(c.End) })
	callField("caller", nil, TypeAddr, "source address of the first request, CIDR aware: caller in 10.0.0.0/8", func(c *call.Call) Value { return addrOfPort(c.Caller) })
	callField("callee", nil, TypeAddr, "destination address of the first request, CIDR aware: callee = 203.0.113.9", func(c *call.Call) Value { return addrOfPort(c.Callee) })
}

func nonZero(n int) Value {
	if n == 0 {
		return Value{}
	}
	return IntValue(int64(n))
}

func nonZeroDur(d time.Duration) Value {
	if d == 0 {
		return Value{}
	}
	return DurationValue(d)
}

func addrOfPort(p netip.AddrPort) Value { return AddrValue(p.Addr()) }

// codecs lists the codecs of every negotiated m-line and observed RTP stream.
func codecs(c *call.Call) Value {
	n := len(c.Streams)
	for _, m := range c.Media {
		n += len(m.Codecs)
	}
	if n == 0 {
		return Value{ok: true}
	}
	out := make([]string, 0, n)
	for _, m := range c.Media {
		out = append(out, m.Codecs...)
	}
	for _, s := range c.Streams {
		if s.Codec != "" {
			out = append(out, s.Codec)
		}
	}
	return StringsValue(out)
}

func minOver(ss []rtp.Stream, get func(rtp.Stream) float64, skipZero bool) Value {
	found, best := false, 0.0
	for _, s := range ss {
		v := get(s)
		if skipZero && v == 0 {
			continue
		}
		if !found || v < best {
			found, best = true, v
		}
	}
	if !found {
		return Value{}
	}
	return FloatValue(best)
}

func maxOver(ss []rtp.Stream, get func(rtp.Stream) float64) Value {
	if len(ss) == 0 {
		return Value{}
	}
	best := get(ss[0])
	for _, s := range ss[1:] {
		best = max(best, get(s))
	}
	return FloatValue(best)
}
