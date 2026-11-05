package flow

// Golden outputs, reviewed by hand. ~~~ stands for a Markdown code fence in the Mermaid outputs.
var goldens = map[string]struct{ ascii, mermaid string }{
	"answeredSDPMedia": {
		ascii: `Call-ID: call-1@example.com
From: <sip:alice@example.com>;tag=ft -> To: <sip:bob@example.com>
Time: 2026-03-01T12:00:00.000Z  duration 7.520s  7 msgs
State: completed  Result: 200 OK  PDD 0.500s  setup 2.500s  talk 5.010s  ended by caller (BYE)
UA: Linphone/4.5; Asterisk PBX 18.1

   10.0.0.1:5060                                          10.0.0.3:5060
    (Linphone)                                             (Asterisk)
         |                                                      |
         |---------------------- INVITE ----------------------->|        +0.000s
         |  [audio PCMU,PCMA,telephone-event @10.0.0.1:20000]   |
         |<-------------------- 100 Trying ---------------------|        +0.010s
         |<-------------------- 180 Ringing --------------------|        +0.500s
         |<---------------------- 200 OK -----------------------|        +2.500s  (gap 2.000s)
         |     [audio PCMA,telephone-event @10.0.0.3:30000]     |
         |------------------------ ACK ------------------------>|        +2.510s
         |~~~~~~ RTP PCMA 245 pkts, loss 0.4%, MOS 4.31 ~~~~~~~>|        +2.600s
         |<~~~~~~ RTP PCMA 240 pkts, loss 0.0%, MOS 4.40 ~~~~~~~|        +2.700s
         |------------------------ BYE ------------------------>|        +7.510s  (gap 5.000s)
         |<---------------------- 200 OK -----------------------|        +7.520s
         |                                                      |

RTP streams:
  Direction       Codec  Packets  Loss  Jitter  MOS   Flow
  caller->callee  PCMA   245      0.4%  3ms     4.31  10.0.0.1:20000 -> 10.0.0.3:30000
  callee->caller  PCMA   240      0.0%  1ms     4.40  10.0.0.3:30000 -> 10.0.0.1:20000
`,
		mermaid: `~~~mermaid
sequenceDiagram
    participant P1 as 10.0.0.1:5060 (Linphone)
    participant P2 as 10.0.0.3:5060 (Asterisk)
    Note over P1,P2: Call-ID: call-1@example.com<br/>From: #lt;sip:alice@example.com#gt;#59;tag=ft -#gt; To: #lt;sip:bob@example.com#gt;<br/>Time: 2026-03-01T12:00:00.000Z  duration 7.520s  7 msgs<br/>State: completed  Result: 200 OK  PDD 0.500s  setup 2.500s  talk 5.010s  ended by caller (BYE)<br/>UA: Linphone/4.5#59; Asterisk PBX 18.1
    P1->>P2: INVITE (+0.000s)
    Note over P2: audio PCMU,PCMA,telephone-event @10.0.0.1:20000
    P2-->>P1: 100 Trying (+0.010s)
    P2-->>P1: 180 Ringing (+0.500s)
    P2-->>P1: 200 OK (+2.500s) [gap 2.000s]
    Note over P1: audio PCMA,telephone-event @10.0.0.3:30000
    P1->>P2: ACK (+2.510s)
    P1-)P2: RTP PCMA 245 pkts, loss 0.4#37;, MOS 4.31 (+2.600s)
    P2-)P1: RTP PCMA 240 pkts, loss 0.0#37;, MOS 4.40 (+2.700s)
    P1->>P2: BYE (+7.510s) [gap 5.000s]
    P2-->>P1: 200 OK (+7.520s)
    Note over P1,P2: RTP caller-#gt;callee PCMA 245 pkts, loss 0.4#37;, jitter 3ms, MOS 4.31<br/>RTP callee-#gt;caller PCMA 240 pkts, loss 0.0#37;, jitter 1ms, MOS 4.40
~~~
`,
	},
	"answeredAbsolute": {
		ascii: `Call-ID: call-1@example.com
From: <sip:alice@example.com>;tag=ft -> To: <sip:bob@example.com>
Time: 2026-03-01T12:00:00.000Z  duration 7.520s  7 msgs
State: completed  Result: 200 OK  PDD 0.500s  setup 2.500s  talk 5.010s  ended by caller (BYE)
UA: Linphone/4.5; Asterisk PBX 18.1

   10.0.0.1:5060     10.0.0.3:5060
    (Linphone)        (Asterisk)
         |                 |
         |---- INVITE ---->|        12:00:00.000
         |<-- 100 Trying --|        12:00:00.010
         |<- 180 Ringing --|        12:00:00.500
         |<---- 200 OK ----|        12:00:02.500  (gap 2.000s)
         |----- ACK ------>|        12:00:02.510
         |----- BYE ------>|        12:00:07.510  (gap 5.000s)
         |<---- 200 OK ----|        12:00:07.520
         |                 |
`,
		mermaid: `~~~mermaid
sequenceDiagram
    participant P1 as 10.0.0.1:5060 (Linphone)
    participant P2 as 10.0.0.3:5060 (Asterisk)
    Note over P1,P2: Call-ID: call-1@example.com<br/>From: #lt;sip:alice@example.com#gt;#59;tag=ft -#gt; To: #lt;sip:bob@example.com#gt;<br/>Time: 2026-03-01T12:00:00.000Z  duration 7.520s  7 msgs<br/>State: completed  Result: 200 OK  PDD 0.500s  setup 2.500s  talk 5.010s  ended by caller (BYE)<br/>UA: Linphone/4.5#59; Asterisk PBX 18.1
    P1->>P2: INVITE (12:00:00.000)
    P2-->>P1: 100 Trying (12:00:00.010)
    P2-->>P1: 180 Ringing (12:00:00.500)
    P2-->>P1: 200 OK (12:00:02.500) [gap 2.000s]
    P1->>P2: ACK (12:00:02.510)
    P1->>P2: BYE (12:00:07.510) [gap 5.000s]
    P2-->>P1: 200 OK (12:00:07.520)
~~~
`,
	},
	"proxy": {
		ascii: `Call-ID: call-1@example.com
From: <sip:alice@example.com>;tag=ft -> To: <sip:bob@example.com>
Time: 2026-03-01T12:00:00.000Z  duration 0.950s  8 msgs
State: answered  Result: 200 OK  PDD 0.300s  setup 0.900s
UA: Yealink SIP-T46; OpenSIPS (3.4); FreeSWITCH-mod_sofia/1.10

   10.0.0.1:5060     10.0.0.2:5060     10.0.0.3:5060
     (Yealink)        (OpenSIPS)    (FreeSWITCH-mod_…)
         |                 |                 |
         |---- INVITE ---->|                 |           +0.000s
         |<-- 100 Trying --|                 |           +0.005s
         |                 |---- INVITE ---->|           +0.006s
         |                 |<- 180 Ringing --|           +0.300s
         |<- 180 Ringing --|                 |           +0.301s
         |                 |<---- 200 OK ----|           +0.900s
         |<---- 200 OK ----|                 |           +0.901s
         |-------------- ACK --------------->|           +0.950s
         |                 |                 |
`,
		mermaid: `~~~mermaid
sequenceDiagram
    participant P1 as 10.0.0.1:5060 (Yealink)
    participant P2 as 10.0.0.2:5060 (OpenSIPS)
    participant P3 as 10.0.0.3:5060 (FreeSWITCH-mod_…)
    Note over P1,P3: Call-ID: call-1@example.com<br/>From: #lt;sip:alice@example.com#gt;#59;tag=ft -#gt; To: #lt;sip:bob@example.com#gt;<br/>Time: 2026-03-01T12:00:00.000Z  duration 0.950s  8 msgs<br/>State: answered  Result: 200 OK  PDD 0.300s  setup 0.900s<br/>UA: Yealink SIP-T46#59; OpenSIPS (3.4)#59; FreeSWITCH-mod_sofia/1.10
    P1->>P2: INVITE (+0.000s)
    P2-->>P1: 100 Trying (+0.005s)
    P2->>P3: INVITE (+0.006s)
    P3-->>P2: 180 Ringing (+0.300s)
    P2-->>P1: 180 Ringing (+0.301s)
    P3-->>P2: 200 OK (+0.900s)
    P2-->>P1: 200 OK (+0.901s)
    P1->>P3: ACK (+0.950s)
~~~
`,
	},
	"failedRetrans": {
		ascii: `Call-ID: call-1@example.com
From: <sip:alice@example.com>;tag=ft -> To: <sip:bob@example.com>
Time: 2026-03-01T12:00:00.000Z  duration 1.020s  5 msgs, 2 retrans
State: failed  Result: 486 Busy Here  PDD 1.020s

   10.0.0.1:5060                10.0.0.3:5060
         |                            |
         |--------- INVITE ---------->|        +0.000s
         |---- INVITE (retrans) ----->|        +0.500s
!        |<====== 486 Busy Here ======|        +0.520s
         |----------- ACK ----------->|        +0.530s
!        |<= 486 Busy Here (retrans) =|        +1.020s
         |                            |
`,
		mermaid: `~~~mermaid
sequenceDiagram
    participant P1 as 10.0.0.1:5060
    participant P2 as 10.0.0.3:5060
    Note over P1,P2: Call-ID: call-1@example.com<br/>From: #lt;sip:alice@example.com#gt;#59;tag=ft -#gt; To: #lt;sip:bob@example.com#gt;<br/>Time: 2026-03-01T12:00:00.000Z  duration 1.020s  5 msgs, 2 retrans<br/>State: failed  Result: 486 Busy Here  PDD 1.020s
    P1->>P2: INVITE (+0.000s)
    P1->>P2: INVITE (retrans) (+0.500s)
    rect rgba(229, 72, 77, 0.2)
        P2-->>P1: 486 Busy Here (+0.520s)
    end
    P1->>P2: ACK (+0.530s)
    rect rgba(229, 72, 77, 0.2)
        P2-->>P1: 486 Busy Here (retrans) (+1.020s)
    end
~~~
`,
	},
	"holdSDP": {
		ascii: `Call-ID: call-1@example.com
From: <sip:alice@example.com>;tag=ft -> To: <sip:bob@example.com>
Time: 2026-03-01T12:00:00.000Z  duration 20.000s  7 msgs
State: completed  Result: 200 OK  PDD 0.200s  setup 0.200s  talk 19.800s  ended by caller (BYE)

   10.0.0.1:5060                              10.0.0.3:5060
         |                                          |
         |---------------- INVITE ----------------->|        +0.000s
         |       [audio PCMU @10.0.0.1:20000]       |
         |<---------------- 200 OK -----------------|        +0.200s
         |       [audio PCMU @10.0.0.3:30000]       |
         |------------------ ACK ------------------>|        +0.210s
         |---------------- INVITE ----------------->|        +10.000s  (gap 9.790s)
         |    [audio PCMU @10.0.0.1:20000 hold]     |
         |<---------------- 200 OK -----------------|        +10.020s
         |  [audio PCMU @10.0.0.3:30000 recvonly]   |
         |------------------ ACK ------------------>|        +10.030s
         |------------------ BYE ------------------>|        +20.000s  (gap 9.970s)
         |                                          |
`,
		mermaid: `~~~mermaid
sequenceDiagram
    participant P1 as 10.0.0.1:5060
    participant P2 as 10.0.0.3:5060
    Note over P1,P2: Call-ID: call-1@example.com<br/>From: #lt;sip:alice@example.com#gt;#59;tag=ft -#gt; To: #lt;sip:bob@example.com#gt;<br/>Time: 2026-03-01T12:00:00.000Z  duration 20.000s  7 msgs<br/>State: completed  Result: 200 OK  PDD 0.200s  setup 0.200s  talk 19.800s  ended by caller (BYE)
    P1->>P2: INVITE (+0.000s)
    Note over P2: audio PCMU @10.0.0.1:20000
    P2-->>P1: 200 OK (+0.200s)
    Note over P1: audio PCMU @10.0.0.3:30000
    P1->>P2: ACK (+0.210s)
    P1->>P2: INVITE (+10.000s) [gap 9.790s]
    Note over P2: audio PCMU @10.0.0.1:20000 hold
    P2-->>P1: 200 OK (+10.020s)
    Note over P1: audio PCMU @10.0.0.3:30000 recvonly
    P1->>P2: ACK (+10.030s)
    P1->>P2: BYE (+20.000s) [gap 9.970s]
~~~
`,
	},
	"hostile": {
		ascii: `Call-ID: id   ]0;pwn <script>
From: <sip:alice@example.com>;tag=ft -> To: <sip:bob@example.com>
Time: 2026-03-01T12:00:00.000Z  duration 0.010s  2 msgs
State: failed  Result: 486 x [31m  y  #;%<>&"'z  PDD 0.010s
UA: x [31m

  [2001:db8::1]:5060  [2001:db8::2]:5060
          (x)                 (x)
           |                   |
           |----- INVITE ----->|                            +0.000s
!          |                   |==+  486 x [31m  y  #;%<…   +0.010s
           |                   |<=+
           |                   |

RTP: no streams correlated
`,
		mermaid: `~~~mermaid
sequenceDiagram
    participant P1 as [2001:db8::1]:5060 (x)
    participant P2 as [2001:db8::2]:5060 (x)
    Note over P1,P2: Call-ID: id   ]0#59;pwn #lt;script#gt;<br/>From: #lt;sip:alice@example.com#gt;#59;tag=ft -#gt; To: #lt;sip:bob@example.com#gt;<br/>Time: 2026-03-01T12:00:00.000Z  duration 0.010s  2 msgs<br/>State: failed  Result: 486 x [31m  y  #35;#59;#37;#lt;#gt;&"'z  PDD 0.010s<br/>UA: x [31m
    P1->>P2: INVITE (+0.000s)
    rect rgba(229, 72, 77, 0.2)
        P2-->>P2: 486 x [31m  y  #35;#59;#37;#lt;… (+0.010s)
    end
    Note over P1,P2: RTP: no streams correlated
~~~
`,
	},
}
