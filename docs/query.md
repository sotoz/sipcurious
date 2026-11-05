# Filter language

Every command that reads captures accepts `--where EXPR` (`-w`) with an expression over SIP messages and calls. The reference between the horizontal rules is the output of `sipcurious fields` (generated from the field registry, so it is always current); the examples at the
end were run against the demo captures in `testdata/samples/` and the match counts are what the tool printed.

## How filters combine

- `--where` and the sugar flags (`--from`, `--to`, `--callid`, `--uri`, `--method`, `--status`, `--src-ip`, `--dst-ip`, `--since`, `--until`) are **ANDed**.
  Each sugar flag is a shorthand for one condition:

  | Flag | Equivalent condition |
  |---|---|
  | `--from TEXT`, `--to TEXT`, `--callid TEXT`, `--uri TEXT` | `from ~ TEXT`, `to ~ TEXT`, `callid ~ TEXT`, `uri ~ TEXT` (substring of the whole header) |
  | `--method M` | `method = M` |
  | `--status 486` / `--status 4xx` | `status = 486` / `status = 4xx` |
  | `--src-ip CIDR`, `--dst-ip CIDR` | `src in CIDR`, `dst in CIDR` |
  | `--since T`, `--until T` | `time >= T`, `time <= T` |
  | `--case-sensitive` | makes `=`, `~`, `=~`, `in` on text case-sensitive (enums such as `state` always ignore case) |

- Commands that list messages (`messages`, `show`) evaluate the expression per message. Commands that list calls (`calls`) evaluate it per call
  (`Query.MatchCall`): a message-field condition is true when **any** message of the call satisfies it, and every condition is judged on its own.
  So `from ~ alice and status >= 500` selects calls that contain a message from Alice and a 5xx message, not necessarily the same message.
- Negation applies to the existential result: `not status >= 500` = a call **without** any 5xx message; `status != 500` = a call with at least one message
  whose status is not 500 (requests count, because their status is null and null never equals anything).
- Call fields used while listing messages (`messages -w 'state = failed'`) are read from the call the message belongs to, so the whole call's messages match.
  This makes RTP analysis necessary when the query needs call fields such as `mos`; the commands switch it on by themselves (and `--no-rtp` turns it off).
- A bad expression is a usage error (exit code 2) and points at the problem:

```
$ sipcurious messages -w 'status = abc' testdata/samples/basic-call.pcap
sipcurious: invalid --where expression:
    status = abc
             ^~~ "abc" is not an integer (status is an int field, e.g. 486 or 4xx)
$ sipcurious messages -w 'from ~ alice and (status >= 500' testdata/samples/basic-call.pcap
sipcurious: invalid --where expression:
    from ~ alice and (status >= 500
                     ^ unclosed "(": add a matching ")"
```

(exit code 2). Quote the expression for your shell: use single quotes around the whole expression and double quotes inside it.

---

```
FILTER EXPRESSIONS

A filter is a boolean expression over messages and calls:

  from ~ alice and status >= 500
  method in (INVITE, BYE) and src in 10.0.0.0/8
  duration > 30s and not has_media
  "a=sendonly"

Combining
  a and b, a && b       both must hold (binds tighter than or)
  a or b, a || b        either holds
  not a, !a             negation (binds tightest); keywords are case-insensitive
  ( ... )               grouping

Conditions
  field                 a boolean field is true:      has_sdp, is_request
  field OP value        compare:                      status = 486
  field in (v1, v2)     any of the values (or one):   method in (INVITE, BYE)
  field not in (...)    none of them
  word, "some text"     substring search in the raw message, e.g.  INVITE  or  "Call-ID: 12"

Operators
  =  ==     equal (text: whole value, ignoring case; addr: inside the CIDR)
  !=        not equal                     !~        does not contain
  ~         contains (text)               =~        matches the Go (RE2) regexp
  <  <=  >  >=   ordering (int, float, duration, time)
  in        any of a list; ranges as 100..199 for numbers, durations and times

Values
  Bare words need no quotes unless they contain spaces, parentheses, commas or
  operator characters; "double" or 'single' quotes may be used anywhere (\" and \\
  escape inside; other backslashes stay as written, so regexps need no doubling).
  int         486   (status and final_code also take a class: 4xx)
  float       3.5
  duration    250ms  3s  1m30s  (a bare number is seconds)
  time        2024-05-01T10:00:00Z   "2024-05-01 10:00:00" (UTC)   2024-05-01   10:30   10:30:15
              HH:MM[:SS] is a time of day on the day of the message (or call start)
  addr        10.0.0.1  10.0.0.0/8  2001:db8::/32   (= and in use CIDR matching)
  bool        true  false
  null        a datum that is absent (status of a request, pdd of an unanswered call)
              matches no comparison, so != / !~ / not in are true for it

Text matching ignores case unless the case-sensitive option is set.
Header fields: header.Name or h.Name is the first value of any header
(compact forms such as i, f, t, v are understood): h.P-Asserted-Identity ~ 4930
A bare header.Name is true when that header is present.

Scopes
  Message fields are evaluated per message. When selecting calls, a message
  field is true if ANY message of the call matches it; each condition is judged
  on its own ("from ~ alice and status >= 500" = the call has both).
  Call fields (state, duration, mos, ...) describe the whole call; when
  filtering single messages they are read from the call the message belongs to
  (and are false when no call is known).
```

## Message fields

```
  method                   string    request method; responses carry the method from CSeq: method = INVITE, method in (INVITE, BYE)
  status (code)            int       response status code, null for requests: status = 486, status = 4xx, status in (404, 500..599)
  uri (request_uri, ruri)  string    Request-URI of a request: uri ~ sip:+4930
  callid (call_id)         string    Call-ID header: callid = 85216695@10.0.0.1
  from                     string    whole From header (display name, URI, tag): from ~ alice
  to                       string    whole To header: to ~ "+49 30"
  from_user                string    user part of the From URI: from_user = 100
  to_user                  string    user part of the To URI: to_user = +4930123456
  from_tag                 string    tag parameter of From: from_tag = 1928301774
  to_tag                   string    tag parameter of To; empty outside a dialog: to_tag = a6c85cf
  contact                  string    whole Contact header: contact ~ 192.168.
  cseq                     string    whole CSeq header: cseq = "101 INVITE"
  via                      string    topmost Via header: via ~ 10.0.0.5
  branch                   string    branch parameter of the topmost Via: branch = z9hG4bK776asdhds
  src (src_ip)             addr      source IP, CIDR aware: src = 10.0.0.0/8, src in (192.168.1.0/24, 2001:db8::/32)
  dst (dst_ip)             addr      destination IP, CIDR aware: dst = 203.0.113.9
  sport (src_port)         int       source port: sport = 5060
  dport (dst_port)         int       destination port: dport in (5060, 5061)
  transport                enum      transport protocol: transport = tcp
                                     values: UDP, TCP, SCTP, TLS, WS, WSS
  time                     time      capture time (UTC): time > 2024-05-01T10:00:00Z, time >= 10:30 (time of day, any date)
  ua                       string    User-Agent of a request or Server of a response: ua ~ cisco
  is_request               bool      true for requests: is_request and method = INVITE
  is_response              bool      true for responses: is_response and status >= 500
  has_sdp                  bool      message carries an SDP body (also inside multipart): has_sdp
  file                     string    capture file the packet came from: file ~ trunk-a
  index                    int       1-based packet number inside its file: index in 100..200
  raw                      string    complete message text; a bare word searches here: raw ~ "a=sendonly"
  body                     string    message body (SDP etc.): body ~ a=inactive
  header.<Name>            string    first value of any header: header.Subject ~ urgent, h.X-Account = 4711
```

## Call fields

```
  state                      enum      where the call ended up: state = failed
                                       values: in-setup, no-response, cancelled, redirected, failed, answered, completed, ok
  kind                       enum      what opened the Call-ID: kind = call
                                       values: call, registration, subscription, message, options, other
  result                     string    "<code> <reason>" of the final response to the first request: result ~ busy
  final_code (final)         int       status of the final response to the first request, null if none: final_code = 486, final_code = 5xx
  duration                   duration  first to last message of the call: duration > 30s, duration < 2s
  pdd                        duration  post-dial delay, INVITE to first 180/183: pdd > 3s
  ring_time                  duration  first 180/183 to answer or final response: ring_time > 30s
  setup_time                 duration  INVITE to 200 OK: setup_time > 5s
  talk_time                  duration  200 OK to first BYE: talk_time < 5s
  ended_by                   enum      who sent the first BYE (CANCEL is always the caller); empty if neither: ended_by = callee
                                       values: caller, callee
  end_method                 enum      method that ended the call; empty if none: end_method = CANCEL
                                       values: BYE, CANCEL
  reason                     string    Reason header (RFC 3326) of the terminating message: reason ~ q.850
  retransmissions (retrans)  int       messages recognised as retransmissions: retransmissions >= 3
  msgs (messages)            int       number of SIP messages in the call: msgs > 100
  codec                      string    negotiated or observed codec, any of them matches: codec = PCMA
  has_media                  bool      an RTP stream was correlated to the call: not has_media
  mos                        float     worst estimated MOS over the call's RTP streams, null without media: mos < 3.5
  loss                       float     worst RTP packet loss in percent, null without media: loss > 1
  jitter                     duration  worst mean RTP jitter over the call's streams, null without media: jitter > 30ms
  user_agent                 string    every User-Agent/Server seen in the call, any of them matches: user_agent ~ asterisk
  start                      time      time of the first message (UTC): start >= 2024-05-01 10:00
  end                        time      time of the last message (UTC): end < 12:00
  caller                     addr      source address of the first request, CIDR aware: caller in 10.0.0.0/8
  callee                     addr      destination address of the first request, CIDR aware: callee = 203.0.113.9
```

---

## Examples on the demo captures

All examples use `testdata/samples/*`; "all 14 samples" is every file of that directory in one run (the commands are
`sipcurious messages -w 'EXPR' testdata/samples/*` and `sipcurious calls -w 'EXPR' testdata/samples/*`; **Matches** is the number in the
`N messages matched` / `N calls matched` line on stderr). Times are UTC (the captures start at 2026-03-04T10:00:00Z).

### Messages (`sipcurious messages -w ...`)

| Expression | Captures | Matches | What it finds |
|---|---|---:|---|
| `status >= 500` | all 14 samples | 22 | every 5xx/6xx response |
| `status = 4xx` | `mixed-busy-hour.pcapng` | 78 | response class |
| `status in (404, 500..599)` | `mixed-busy-hour.pcapng` | 31 | list with a range |
| `method in (INVITE, BYE)` | `basic-call.pcap` | 6 | responses carry the method of their CSeq, so this includes `200 OK` to the INVITE and BYE |
| `is_request and method = INVITE and src in 10.0.1.0/24` | `mixed-busy-hour.pcapng` | 163 | INVITE requests from a subnet |
| `from ~ alice and status >= 400` | `mixed-busy-hour.pcapng` | 12 | error responses to calls from Alice (matched on the From header of the response itself) |
| `ua ~ yealink` | `mixed-busy-hour.pcapng` | 31 | User-Agent of requests / Server of responses |
| `header.Server =~ "^Asterisk"` | `mixed-busy-hour.pcapng` | 23 | regular expression on an arbitrary header |
| `h.X-CID` | `mixed-busy-hour.pcapng` | 12 | bare header name: the header is present |
| `has_sdp and method = INVITE` | `basic-call.pcap` | 2 | messages carrying SDP |
| `"a=sendonly"` | `hold-resume.pcap` | 2 | quoted text: substring search in the raw message |
| `body ~ "0.0.0.0"` | `hold-resume.pcap` | 1 | SDP of a legacy hold (`c=0.0.0.0`) |
| `transport = tcp` | `mixed-busy-hour.pcapng` | 48 | SIP carried over TCP |
| `time >= 10:05 and time < 10:06` | `mixed-busy-hour.pcapng` | 116 | a time-of-day window (UTC) |
| `index in 1..3` | `basic-call.pcap` | 3 | packet numbers of the file |
| `contact ~ 192.168.` | `nat-problem.pcap` | 4 | private addresses in Contact |

### Calls (`sipcurious calls -w ...`)

| Expression | Captures | Matches | What it finds |
|---|---|---:|---|
| `state = failed` | `mixed-busy-hour.pcapng` | 70 | calls that ended with a failure response (same as `calls --state failed`) |
| `kind = call and state = failed and final_code = 5xx` | `mixed-busy-hour.pcapng` | 13 | server errors |
| `duration > 30s` | all 14 samples | 12 | long Call-IDs (all kinds) |
| `pdd > 3s` | `mixed-busy-hour.pcapng` | 8 | slow post-dial delay |
| `setup_time > 2s and state = completed` | `mixed-busy-hour.pcapng` | 51 | slow setup of calls that were answered |
| `retransmissions >= 3` | all 14 samples | 11 | calls with many retransmissions |
| `has_media and mos < 3.5` | all 14 samples | 1 | bad estimated quality |
| `loss > 1` | all 14 samples | 1 | more than 1 % RTP loss in any stream |
| `jitter > 20ms` | all 14 samples | 1 | mean jitter above 20 ms |
| `kind = call and state = completed and not has_media` | all 14 samples | 69 | answered, but no RTP was correlated (69 here, most of them from `mixed-busy-hour.pcapng`, whose streams have only 3 packets each and stay below the 5-packet RTP detection threshold; see definitions.md) |
| `ended_by = callee` | all 14 samples | 5 | the called party hung up |
| `reason ~ q.850` | all 14 samples | 1 | calls whose terminating message has a Q.850 Reason |
| `codec = G729` | `hold-resume.pcap` | 2 | negotiated or observed codec |
| `kind = registration and state = failed` | all 14 samples | 1 | failed registrations |
| `caller in 203.0.113.0/24` | all 14 samples | 1 | calls whose first request came from a subnet |
| `user_agent ~ yealink and state = cancelled` | `mixed-busy-hour.pcapng` | 3 | any User-Agent/Server seen in the call |
| `start >= 10:05 and start < 10:06` | `mixed-busy-hour.pcapng` | 17 | calls that began in a window |
| `talk_time < 5s and state = completed` | `mixed-busy-hour.pcapng` | 5 | very short conversations |

### Combining with other flags

```
$ sipcurious messages --count -w 'method = INVITE' testdata/samples/mixed-busy-hour.pcapng
708
$ sipcurious messages --count --unique -w 'method = INVITE' testdata/samples/mixed-busy-hour.pcapng   # first match per Call-ID
155
```

The same filter with `calls --state failed --kind call` or `calls --failed` is the flag form of `state`/`kind` conditions.

## Adding a field

Fields are registered, not hard-coded: see "Register a query field" in [architecture.md](architecture.md).
