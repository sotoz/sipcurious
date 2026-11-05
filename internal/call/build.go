package call

import (
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/sotoz/sipcurious/internal/trace"
)

// Build groups msgs by Call-ID and derives the state, timings, media and
// diagnostics of every group. msgs is never modified; messages are copied into
// one shared backing array. Messages with an empty Call-ID are ignored. The
// result is ordered by Start (ties keep the order in which each Call-ID was
// first seen) and the messages of every call are chronological, stable for
// equal timestamps. Cost is O(n log n) in the worst case (unsorted input) and
// O(n) for input that is already time-ordered; analysis of independent calls
// runs on GOMAXPROCS workers.
//
// # Definitions
//
// Kind is decided by the first request of the Call-ID: INVITE and the
// in-dialog methods ACK, BYE, CANCEL, PRACK, UPDATE and INFO give KindCall
// (a call whose start is outside the capture begins with one of those);
// REGISTER gives KindRegistration; SUBSCRIBE, NOTIFY and REFER give
// KindSubscription; MESSAGE and OPTIONS give KindMessage and KindOptions;
// anything else is KindOther. A Call-ID with responses only is classified by
// the method in the CSeq of its first response and has Method "".
//
// Transactions. Messages are matched to transactions by CSeq number, From tag
// and CSeq method (the two ends of a dialog number their requests
// independently), so responses to CANCEL, BYE, PRACK, UPDATE, INFO and
// re-INVITEs never influence the outcome of the call set-up. For KindCall the
// relevant ("initial") transactions are the INVITEs without a To tag; when no
// INVITE request was captured, the response-only INVITE transactions stand in.
// For every other Kind they are the transactions of the method of the first
// request. The deciding transaction is the latest initial one that got any
// response, so REGISTER 401 then REGISTER 200 gives state ok, REGISTER 401 then
// REGISTER 403 gives failed 403, and a retry after a 401/407 that was never
// answered stays failed 401/407. Attempts is the number of initial
// transactions. The final response of a transaction is its first 2xx,
// otherwise its last response >= 300 (with forking the last failure is the one
// the caller saw).
//
// State for KindCall (first matching rule wins):
//
//	answered/completed  a 2xx to any INVITE was seen (first 2xx wins; forks
//	                    answering later, or a 487/4xx from another fork or to
//	                    a re-INVITE, do not change it); also when the deciding
//	                    INVITE has no response at all but an ACK for a 2xx
//	                    (branch different from every INVITE branch) was
//	                    captured, the 2xx itself having been lost.
//	                    "completed" when a BYE (or a response to a BYE) was
//	                    seen, else "answered" (still up, or capture ended).
//	no initial INVITE   (capture started mid-call) completed if BYE,
//	                    cancelled if CANCEL, else answered: a re-INVITE or
//	                    UPDATE only proves an established dialog.
//	redirected          the deciding INVITE's final response is 3xx.
//	cancelled           the final response is 487 and a CANCEL was seen; or
//	                    no final response and a CANCEL was seen. A 487 without
//	                    a CANCEL, or any other final after a CANCEL (crossed
//	                    with a rejection), is "failed".
//	failed              any other final response >= 400.
//	completed (early)   a BYE without any 2xx or final response captured
//	                    (the answer was lost, or the BYE crossed it):
//	                    completed, FinalCode 0, EndedBy from the BYE.
//	in-setup            responses were seen (even only 100 Trying), none final.
//	no-response         the INVITE never got any response.
//
// State for every other Kind is decided by the final response of the deciding
// transaction: ok (2xx), redirected (3xx), failed (>= 400), no-response (no
// final response; provisional-only counts as no response).
//
// FinalCode, FinalReason and Result describe the final response of the
// deciding transaction (for answered calls the first 2xx; zero if the capture
// has no initial INVITE or no final response).
//
// Timings (INVITE calls only; zero when the events were not captured). T0 is
// the first initial INVITE (not the retry after a challenge). PDD is T0 to the
// first 101-199 response other than 100 Trying, or to the final response when
// that came first or no ringing was seen. RingTime is that first provisional
// response to the first 2xx or final response (zero without one). SetupTime is
// T0 to the first 2xx. Answered is the time of that 2xx. Ended is the time of
// the first BYE (a CANCEL for cancelled calls): EndMethod "BYE" / "CANCEL".
// TalkTime is Answered to the first BYE. Start and End are the first and last
// message of the Call-ID.
//
// EndedBy: BYE direction is decided from the dialog tags because source
// addresses lie behind proxies, SBCs and NAT. The sender of a BYE is the
// "caller" if its From tag equals the From tag of the initial INVITE (or of
// the first ACK/response when the INVITE was not captured), the "callee" if
// its From tag differs or its To tag equals the caller's tag. Without tags
// the exact source address:port is compared with the initial INVITE's
// source and destination, then the address alone. EndedBy stays "" when it
// cannot be decided. For a response-only BYE the response's destination plays
// the role of the sender. For CANCEL EndedBy is always "caller".
// Caller/Callee are the source and destination of the first initial request
// and zero for calls captured mid-dialog.
//
// Reason is the Reason header (RFC 3326; several joined by ", ") of the
// terminating message: the first BYE, or the CANCEL (falling back to the 487),
// or the failure/redirect response.
//
// Retransmissions counts messages repeating an earlier message with the same
// kind, method or status, CSeq, topmost Via branch, source and destination
// (for responses also the To tag and, for provisional ones, RSeq).
// MissingACK is set when a 2xx to the INVITE was retransmitted and no ACK for
// it was captured. Forks is the number of distinct To tags in the 101-299
// responses of the answered (or deciding) INVITE.
//
// UserAgents are the User-Agent of requests and the Server of responses
// (each falling back to the other header), distinct, first seen first.
// Endpoints are the distinct source and destination address:port pairs of the
// messages in first-seen order (at most 64).
//
// Media follows the SDP offer/answer exchanges of INVITE, UPDATE, PRACK, ACK and
// their 1xx/2xx responses (delayed offer: offer in the 2xx or reliable 18x,
// answer in the ACK or PRACK; early media: an answer in a 18x), see Media.
func Build(msgs []trace.Message, opt Options) []Call {
	calls := group(msgs)
	if len(calls) == 0 {
		return nil
	}
	analyzeAll(calls, &opt)
	if !slices.IsSortedFunc(calls, cmpStart) {
		slices.SortStableFunc(calls, cmpStart)
	}
	if len(opt.CorrelateHeaders) > 0 {
		correlate(calls, opt.CorrelateHeaders)
	}
	return calls
}

func cmpStart(a, b Call) int { return a.Start.Compare(b.Start) }

func cmpTime(a, b trace.Message) int { return a.Time.Compare(b.Time) }

// group copies msgs into per-Call-ID slices carved from one backing array.
// Calls are in first-seen order.
func group(msgs []trace.Message) []Call {
	var (
		index  = make(map[string]int32, len(msgs)/8+16)
		calls  []Call
		counts []int32
		which  = make([]int32, len(msgs)) // call index per message, -1 if ignored
		total  int
	)
	for k := range msgs {
		id := msgs[k].CallID
		if id == "" {
			which[k] = -1
			continue
		}
		i, ok := index[id]
		if !ok {
			i = int32(len(calls))
			index[id] = i
			calls = append(calls, Call{CallID: id})
			counts = append(counts, 0)
		}
		which[k] = i
		counts[i]++
		total++
	}
	backing := make([]trace.Message, total)
	off := 0
	for i := range calls {
		// Full slice expression: appending to a call's Messages must never
		// overwrite its neighbour.
		calls[i].Messages = backing[off : off : off+int(counts[i])]
		off += int(counts[i])
	}
	for k := range msgs {
		if i := which[k]; i >= 0 {
			calls[i].Messages = append(calls[i].Messages, msgs[k])
		}
	}
	return calls
}

// analyzeAll runs the per-call analysis, in parallel for large inputs. Every
// worker only touches the calls it picks up, so the result is deterministic.
func analyzeAll(calls []Call, opt *Options) {
	const chunk = 256
	workers := min(runtime.GOMAXPROCS(0), (len(calls)+chunk-1)/chunk)
	if workers <= 1 {
		w := newWorker()
		for i := range calls {
			w.analyze(&calls[i], opt)
		}
		return
	}
	var (
		next atomic.Int64
		wg   sync.WaitGroup
	)
	for range workers {
		wg.Go(func() {
			w := newWorker()
			for {
				lo := int(next.Add(chunk)) - chunk
				if lo >= len(calls) {
					return
				}
				for i := lo; i < min(lo+chunk, len(calls)); i++ {
					w.analyze(&calls[i], opt)
				}
			}
		})
	}
	wg.Wait()
}
