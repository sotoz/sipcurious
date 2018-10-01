package main

import (
	"strings"
	"time"
)

var (
	filters = []Filter{ToFilter{}, FromFilter{}, CallIDFilter{}}
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
	Contact           []byte
}

// Filter serves as an interface for all filters that can be attached on a siptrace.
type Filter interface {
	Search(sipMessage, string) *Result
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
func (ff FromFilter) Search(sipPacket sipMessage, from string) *Result {
	if from == "" {
		return nil
	}

	var r Result
	if strings.Contains(strings.ToLower(string(sipPacket.pct.From.User)), from) {
		r.From = sipPacket.pct.From.Src
		r.To = sipPacket.pct.To.Src
		r.CallID = sipPacket.pct.CallId.Value
		r.Method = sipPacket.pct.Req.Method
		r.StatusCode = sipPacket.pct.Req.StatusCode
		r.StatusDescription = sipPacket.pct.Req.StatusDesc
		r.Contact = sipPacket.pct.Contact.Src

		return &r
	}

	return nil
}

// GetCmdParameter returns the command line parameter's value for that filter
func (tf ToFilter) GetCmdParameter(s searchParams) string {
	return s.to
}

// Search will search for the <to> inside the sipPacket
func (tf ToFilter) Search(sipPacket sipMessage, to string) *Result {
	if to == "" {
		return nil
	}
	var r Result

	if strings.Contains(strings.ToLower(string(sipPacket.pct.To.User)), to) {
		r.From = sipPacket.pct.From.Src
		r.To = sipPacket.pct.To.Src
		r.CallID = sipPacket.pct.CallId.Value
		r.Method = sipPacket.pct.Req.Method
		r.StatusCode = sipPacket.pct.Req.StatusCode
		r.StatusDescription = sipPacket.pct.Req.StatusDesc
		r.Contact = sipPacket.pct.Contact.Src

		return &r
	}
	return nil
}

// GetCmdParameter returns the command line parameter's value for that filter
func (cidf CallIDFilter) GetCmdParameter(s searchParams) string {
	return s.callid
}

// Search will search if the specified packet includes the call id that we are searching.
func (cidf CallIDFilter) Search(sipPacket sipMessage, cid string) *Result {
	if cid == "" {
		return nil
	}
	var r Result
	if strings.Contains(strings.ToLower(string(sipPacket.pct.CallId.Value)), cid) {
		r.From = sipPacket.pct.From.Src
		r.To = sipPacket.pct.To.Src
		r.CallID = sipPacket.pct.CallId.Value
		r.Method = sipPacket.pct.Req.Method
		r.StatusCode = sipPacket.pct.Req.StatusCode
		r.StatusDescription = sipPacket.pct.Req.StatusDesc
		r.Contact = sipPacket.pct.Contact.Src

		return &r
	}
	return nil
}

func searchFilters(sipPackets []sipMessage, sp searchParams) []Result {
	var results []Result

	for _, sipp := range sipPackets {
		for _, filter := range filters {
			res := filter.Search(sipp, filter.GetCmdParameter(sp))
			if res == nil {
				continue
			}

			if *unique && len(results) > 0 {
				break
			}
			res.Timestamp = sipp.timestamp
			results = append(results, *res)
		}
	}

	return results
}
