package main

import (
	"strings"
	"time"

	"github.com/marv2097/siprocket"
)

// Result describes a Result struct.
type Result struct {
	From              []byte
	To                []byte
	CallID            []byte
	Timestamp         time.Duration
	Method            []byte
	StatusCode        []byte
	StatusDescription []byte
}

// Filter serves as an interface for all filters that can be attached on a siptrace.
type Filter interface {
	Search(siprocket.SipMsg, string, chan<- *Result)
	GetCmdParameter(searchParams) string
}

// FromFilter is a placeholder struct for the filter operations for From.
type FromFilter struct{}

// ToFilter is a placeholder struct for the filter operations for To.
type ToFilter struct{}

// CallIDFilter is a placeholder struct for the filter operation for Call-Id.
type CallIDFilter struct{}

// GetCmdParameter returns the command line parameter's value for that filter
func (ff FromFilter) GetCmdParameter(s searchParams) string {
	return s.from
}

// Search will search inside the sipPacket whether the from filter exists.
func (ff FromFilter) Search(sipPacket siprocket.SipMsg, from string, out chan<- *Result) {
	if from == "" {
		out <- nil
	}

	var r Result
	if strings.Contains(strings.ToLower(string(sipPacket.From.User)), from) {
		r.From = sipPacket.From.User
		r.To = sipPacket.To.User
		r.CallID = sipPacket.CallId.Value
		r.StatusCode = sipPacket.Req.StatusCode
		r.StatusDescription = sipPacket.Req.StatusDesc

		out <- &r
	}

	out <- nil
}

// GetCmdParameter returns the command line parameter's value for that filter
func (tf ToFilter) GetCmdParameter(s searchParams) string {
	return s.to
}

// Search will search for the <to> inside the sipPacket
func (tf ToFilter) Search(sipPacket siprocket.SipMsg, to string, out chan<- *Result) {
	if to == "" {
		out <- nil
	}
	var r Result

	if strings.Contains(strings.ToLower(string(sipPacket.To.User)), to) {
		r.From = sipPacket.From.User
		r.To = sipPacket.To.User
		r.CallID = sipPacket.CallId.Value
		r.StatusCode = sipPacket.Req.StatusCode
		r.StatusDescription = sipPacket.Req.StatusDesc

		out <- &r
	}
	out <- nil
}

// GetCmdParameter returns the command line parameter's value for that filter
func (cidf CallIDFilter) GetCmdParameter(s searchParams) string {
	return s.callid
}

// Search will search if the specified packet includes the call id that we are searching.
func (cidf CallIDFilter) Search(sipPacket siprocket.SipMsg, cid string, out chan<- *Result) {
	if cid == "" {
		out <- nil
	}
	var r Result
	if strings.Contains(strings.ToLower(string(sipPacket.CallId.Value)), cid) {
		r.From = sipPacket.From.User
		r.To = sipPacket.To.User
		r.CallID = sipPacket.CallId.Value
		r.StatusCode = sipPacket.Req.StatusCode
		r.StatusDescription = sipPacket.Req.StatusDesc

		out <- &r
	}
	out <- nil
}

func searchFilters(sipPackets []siprocket.SipMsg, sp searchParams) []Result {
	var results []Result

	for _, sipPacket := range sipPackets {
		filters := []Filter{ToFilter{}, FromFilter{}, CallIDFilter{}}
		for _, filter := range filters {
			rc := make(chan *Result)

			go filter.Search(sipPacket, filter.GetCmdParameter(sp), rc)
			res := <-rc
			if res == nil {
				continue
			}
			results = append(results, *res)
		}
		if *unique && len(results) > 0 {
			break
		}
	}
	return results
}
