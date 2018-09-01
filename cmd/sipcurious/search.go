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
	Search(siprocket.SipMsg, chan<- *Result)
}

// FromFilter is a placeholder struct for the filter operations for From.
type FromFilter struct {
	found bool
}

// ToFilter is a placeholder struct for the filter operations for To.
type ToFilter struct {
	found bool
}

// Search will search inside the sipPacket whether the from filter exists.
func (ff FromFilter) Search(sipPacket siprocket.SipMsg, out chan<- *Result) {
	if *from == "" {
		out <- nil
	}
	var r Result
	if strings.Contains(strings.ToLower(string(sipPacket.From.User)), *from) {
		r.From = sipPacket.From.User
		r.To = sipPacket.To.User
		r.CallID = sipPacket.CallId.Value
		r.StatusCode = sipPacket.Req.StatusCode
		r.StatusDescription = sipPacket.Req.StatusDesc

		if *unique {
			ff.found = true
		}
		out <- &r
	}

	out <- nil
}

// Search will search for the <to> inside the sipPacket
func (tf ToFilter) Search(sipPacket siprocket.SipMsg, out chan<- *Result) {
	if *to == "" {
		out <- nil
	}
	var r Result

	if strings.Contains(strings.ToLower(string(sipPacket.To.User)), *to) {
		r.From = sipPacket.From.User
		r.To = sipPacket.To.User
		r.CallID = sipPacket.CallId.Value
		r.StatusCode = sipPacket.Req.StatusCode
		r.StatusDescription = sipPacket.Req.StatusDesc

		if *unique {
			tf.found = true
		}
		out <- &r
	}
	out <- nil
}

func searchFilters(sipPackets []siprocket.SipMsg) []Result {
	var results []Result

	for _, sipPacket := range sipPackets {
		filters := []Filter{ToFilter{}, FromFilter{}}
		for _, filter := range filters {
			rc := make(chan *Result)

			go filter.Search(sipPacket, rc)
			res := <-rc
			if res == nil {
				continue
			}
			results = append(results, *res)
		}
	}
	return results
}
