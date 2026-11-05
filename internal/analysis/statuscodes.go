package analysis

import (
	"strconv"
	"strings"
)

// StatusInfo is the built-in knowledge about a SIP failure response.
type StatusInfo struct {
	Meaning string // what the code says
	Causes  string // typical causes in the field
	Check   string // what to check next
}

// statusTable covers the failure codes of RFC 3261 and the common extensions
// (RFC 3262, 3265, 3311, 3326, 3329, 3398, 4412, 5393, 5626, 6026, 6086,
// 6442, 8197 and carrier practice).
var statusTable = map[int]StatusInfo{
	400: {"Bad Request", "Malformed message: broken header, wrong Content-Length, bad SDP, invalid URI.", "Read the rejected request and the Warning/reason text; compare with what the sender's stack should produce."},
	401: {"Unauthorized", "The UAS or registrar demands credentials (digest challenge).", "Normal first step of authentication; it is a problem only if the retry with credentials is also rejected (wrong password, realm or user)."},
	402: {"Payment Required", "Reserved; some carriers use it for exhausted credit or prepaid balance.", "Check the account balance or billing state at the carrier."},
	403: {"Forbidden", "Request understood but refused: wrong credentials, source IP not whitelisted, account blocked, caller ID or destination not allowed, trunk not provisioned.", "Check IP ACLs and trunk authentication on the far end, the account state, and whether From/P-Asserted-Identity are allowed."},
	404: {"Not Found", "Number or user unknown at that server: wrong dial plan, number not provisioned, missing prefix/E.164 normalisation.", "Check the Request-URI that was sent (prefix, country code, domain) against the far end's numbering plan."},
	405: {"Method Not Allowed", "The server does not support that method on this resource (e.g. REGISTER to a trunk, UPDATE or INFO to a basic UA).", "Read the Allow header of the response and stop sending that method."},
	406: {"Not Acceptable", "The Accept headers cannot be satisfied.", "Compare the request's Accept headers with what the server can produce."},
	407: {"Proxy Authentication Required", "The proxy demands credentials (digest challenge).", "Normal first step of authentication; a problem only if the retry is also rejected (wrong password, realm or user)."},
	408: {"Request Timeout", "The server could not find the user in time, or the transaction timed out downstream.", "Check the downstream hop and whether the called endpoint is registered and reachable."},
	409: {"Conflict", "Obsolete; some servers report a registration or resource conflict.", "Check for duplicate registrations or concurrent updates."},
	410: {"Gone", "The user existed but is permanently gone (number disconnected, ported out).", "Check number status and portability at the carrier."},
	411: {"Length Required", "Content-Length missing on a stream transport.", "Fix the sender to add Content-Length (mandatory on TCP)."},
	412: {"Conditional Request Failed", "SIP-If-Match did not match the publication state (PUBLISH).", "Re-read the current entity tag and retry."},
	413: {"Request Entity Too Large", "The body (SDP, multipart, headers) exceeds what the server accepts.", "Reduce the message size: fewer codecs/attributes, drop unneeded headers, or use TCP."},
	414: {"Request-URI Too Long", "URI longer than the server accepts.", "Shorten the Request-URI, check for URI parameter loops."},
	415: {"Unsupported Media Type", "The body or Content-Type is not understood (e.g. multipart, ISUP, SIP-I, unusual SDP).", "Check the Accept header of the response and strip unsupported body parts."},
	416: {"Unsupported URI Scheme", "Request-URI scheme (tel:, sips:) not supported.", "Send a sip: URI or enable the scheme on the far end."},
	417: {"Unknown Resource-Priority", "Resource-Priority namespace unknown.", "Remove the Resource-Priority header or align namespaces."},
	420: {"Bad Extension", "A required extension in Require/Proxy-Require is not supported by the peer.", "Read the Unsupported header of the response; drop the Require (100rel, timer, replaces...) or enable it on the peer."},
	421: {"Extension Required", "The peer insists on an extension the caller did not list in Supported.", "Read the Require header of the response and add that option to Supported."},
	422: {"Session Interval Too Small", "Session timer (RFC 4028) value below the peer's Min-SE.", "Retry with Session-Expires >= the Min-SE of the response; align session timer settings."},
	423: {"Interval Too Brief", "Registration Expires shorter than the registrar's minimum.", "Use Expires >= the Min-Expires of the response."},
	424: {"Bad Location Information", "Geolocation information could not be used.", "Check the Geolocation header and the location URI."},
	425: {"Bad Alert Message", "Alert-Info content rejected.", "Check the Alert-Info header."},
	426: {"Upgrade Required", "The server requires a different (secure) transport.", "Switch to TLS/WSS as the Upgrade header indicates."},
	428: {"Use Identity Header", "STIR/SHAKEN: the call needs an Identity header.", "Sign the call or enable STIR/SHAKEN attestation on the originating side."},
	429: {"Provide Referrer Identity", "REFER without a Referred-By.", "Add Referred-By to the REFER."},
	430: {"Flow Failed", "Outbound (RFC 5626) flow to the UA failed.", "The registered connection is gone: the UA must re-register."},
	433: {"Anonymity Disallowed", "Anonymous calls are not accepted by the callee.", "Send the call with a caller identity."},
	436: {"Bad Identity-Info", "STIR: the Identity-Info URI is bad.", "Check the certificate URL of the signer."},
	437: {"Unsupported Certificate", "STIR: the certificate was not accepted.", "Check the signing certificate and its chain."},
	438: {"Invalid Identity Header", "STIR: the Identity signature is invalid.", "Check signing and that the header was not altered in transit."},
	439: {"First Hop Lacks Outbound Support", "The first hop does not support outbound.", "Disable outbound or register through a supporting proxy."},
	440: {"Max-Breadth Exceeded", "Too many parallel forks.", "Reduce forking breadth or raise the limit."},
	469: {"Bad Info Package", "Info-Package unknown or unsupported.", "Check the Recv-Info header."},
	470: {"Consent Needed", "Consent to send to a URI is required.", "Obtain consent from the recipient."},
	480: {"Temporarily Unavailable", "The callee is known but not reachable now: not registered, registration expired, device off or out of coverage, do-not-disturb.", "Check the callee's registration state and expiry, and whether the device is online."},
	481: {"Call/Transaction Does Not Exist", "A BYE, re-INVITE or CANCEL refers to a dialog or transaction the peer does not have: state lost (restart, failover), timeout, or a message routed to the wrong node.", "Check whether the peer or an SBC restarted, whether dialogs time out (session timer), and whether in-dialog requests reach the same node."},
	482: {"Loop Detected", "The request reached a server that already processed it: routing loop.", "Trace the Via and Record-Route headers to find where two hops send the request to each other."},
	483: {"Too Many Hops", "Max-Forwards reached 0 along the path: routing loop or a very long chain.", "Check the Via list for repeated hops and fix the routing/dial plan loop."},
	484: {"Address Incomplete", "The number is incomplete (overlap dialling, missing digits).", "Check the dialled number and the digit collection/prefix rules."},
	485: {"Ambiguous", "The address matches several destinations.", "Make the Request-URI unique; use the Contact alternatives of the response."},
	486: {"Busy Here", "The callee is busy (or has call waiting disabled / max calls reached).", "Normal if the user is on another call; with trunks check the channel/concurrent call limit."},
	487: {"Request Terminated", "The INVITE was cancelled by a CANCEL (normal), or ended by the proxy.", "Normal after CANCEL; without a CANCEL look for the proxy or B2BUA that terminated the request."},
	488: {"Not Acceptable Here", "The SDP offer cannot be accepted: no common codec, unsupported SRTP/DTLS profile, wrong ptime, unacceptable media.", "Compare the offered codecs and media profile (RTP/AVP vs SAVP) with what the callee supports; check the Warning header."},
	489: {"Bad Event", "Unknown event package in SUBSCRIBE.", "Check the Event header and what the server supports."},
	491: {"Request Pending", "Crossed re-INVITEs (glare).", "Normal; the UAs retry after a random delay. A loop means both sides keep retrying at once."},
	493: {"Undecipherable", "Encrypted body (S/MIME) could not be decrypted.", "Check the keys/certificates."},
	494: {"Security Agreement Required", "Sec-Agree negotiation needed (IMS).", "Add the Security-Client / Security-Verify headers."},
	500: {"Server Internal Error", "The server failed unexpectedly: software bug, backend/database down, overload.", "Look at the server's own logs for the same Call-ID; check the Retry-After header and backend health."},
	501: {"Not Implemented", "The server does not support the method or feature.", "Do not send that method or feature to that peer."},
	502: {"Bad Gateway", "The proxy received an invalid answer from the next hop, or could not reach it.", "Check the next hop that the proxy uses: connectivity, DNS, TLS, and its reply."},
	503: {"Service Unavailable", "Overload, maintenance, trunk capacity exhausted, rate limiting, or the downstream is down.", "Check the Retry-After header, the concurrent call/CPS limits of the trunk, and the health of the downstream."},
	504: {"Server Time-out", "The server did not get a response from the downstream in time.", "Check the downstream hop and its reachability and latency."},
	505: {"Version Not Supported", "SIP version other than 2.0.", "Fix the version in the start line."},
	513: {"Message Too Large", "The message exceeds the server's size limit.", "Reduce the message size or use TCP."},
	555: {"Push Notification Service Not Supported", "The push provider is not supported.", "Check the pn-provider parameter."},
	580: {"Precondition Failure", "QoS preconditions could not be met.", "Check the precondition attributes in the SDP; disable preconditions if not needed."},
	600: {"Busy Everywhere", "The callee is busy on all devices.", "Normal for a busy user; check forwarding rules."},
	603: {"Decline", "The callee actively rejected the call (button press, do-not-disturb, call blocking, spam filter).", "Normal if user-initiated; otherwise check call blocking and DND rules, and whether the call was identified as spam."},
	604: {"Does Not Exist Anywhere", "The number does not exist anywhere (authoritative).", "Check the dialled number and its provisioning."},
	606: {"Not Acceptable", "The session description is not acceptable anywhere.", "Compare the codecs and media profile in the offer with what the callee supports."},
}

// Status returns what is known about a failure status code. For an
// unassigned code it falls back to the class (4xx client error, 5xx server
// error, 6xx global failure).
func Status(code int) StatusInfo {
	if s, ok := statusTable[code]; ok {
		return s
	}
	switch {
	case code >= 400 && code < 500:
		return StatusInfo{"Client Error", "The request cannot be fulfilled as sent.", "Read the reason phrase and any Warning or Reason header of the response."}
	case code >= 500 && code < 600:
		return StatusInfo{"Server Error", "The server failed to fulfil a valid request.", "Look at the server's own logs for this Call-ID and check Retry-After."}
	case code >= 600 && code < 700:
		return StatusInfo{"Global Failure", "The request cannot be fulfilled at any server.", "Read the reason phrase; the callee or number is not reachable anywhere."}
	}
	return StatusInfo{}
}

// q850 maps the Q.850 cause values common in SIP Reason headers.
var q850 = map[int]string{
	1:   "Unallocated (unassigned) number: the number does not exist on the far network",
	16:  "Normal call clearing",
	17:  "User busy",
	18:  "No user responding: the called device did not answer the setup",
	19:  "No answer from user (alerted but not answered)",
	21:  "Call rejected by the user or the network",
	27:  "Destination out of order: the interface or endpoint is down",
	28:  "Invalid number format (address incomplete)",
	31:  "Normal, unspecified",
	34:  "No circuit/channel available: trunk congested or out of channels",
	38:  "Network out of order",
	41:  "Temporary failure",
	42:  "Switching equipment congestion",
	102: "Recovery on timer expiry: a timer ran out (no answer from a downstream hop)",
}

// Q850 returns the meaning of a Q.850 cause value, "" for values this tool
// does not know.
func Q850(cause int) string { return q850[cause] }

// reasonCause extracts the protocol and cause number (and text) from a
// Reason header value such as `Q.850;cause=17;text="User busy"` or
// `SIP;cause=200;text="Call completed elsewhere"`. If the header carries
// several reasons, the Q.850 one is preferred.
func reasonCause(reason string) (proto string, cause int, text string, ok bool) {
	for _, part := range strings.Split(reason, ",") {
		p, c, t, found := parseReason(part)
		if !found {
			continue
		}
		if !ok || strings.EqualFold(p, "Q.850") {
			proto, cause, text, ok = p, c, t, true
		}
	}
	return
}

func parseReason(s string) (proto string, cause int, text string, ok bool) {
	fields := strings.Split(s, ";")
	proto = strings.TrimSpace(fields[0])
	if proto == "" {
		return
	}
	for _, f := range fields[1:] {
		k, v, _ := strings.Cut(strings.TrimSpace(f), "=")
		switch strings.ToLower(k) {
		case "cause":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				cause, ok = n, true
			}
		case "text":
			text = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return
}
