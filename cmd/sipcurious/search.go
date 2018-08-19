package main

import (
	"strings"
	"time"

	"github.com/marv2097/siprocket"
)

type Result struct {
	From              string
	To                string
	CallID            string
	Timestamp         time.Duration
	Method            string
	StatusCode        string
	StatusDescription string
}

type Filter interface {
	Search(siprocket.SipMsg) *Result
	Exists(string) bool
}

type FromFilter struct{}
type ToFilter struct{}

func (ff FromFilter) Search(sipPacket siprocket.SipMsg) *Result {
	var r Result
	if strings.Contains(strings.ToLower(string(sipPacket.From.User)), *from) {
		r.From = string(sipPacket.From.User)
		r.To = string(sipPacket.To.User)
		r.CallID = string(sipPacket.CallId.Value)
		r.StatusCode = string(sipPacket.Req.StatusCode)
		r.StatusDescription = string(sipPacket.Req.StatusDesc)

		return &r
	}

	return nil
}

func (ff FromFilter) Exists(s string) bool {

	return false
}

func (tf ToFilter) Search(sipPacket siprocket.SipMsg) *Result {
	var r Result

	if strings.Contains(strings.ToLower(string(sipPacket.To.User)), *to) {
		r.From = string(sipPacket.From.User)
		r.To = string(sipPacket.To.User)
		r.CallID = string(sipPacket.CallId.Value)
		r.StatusCode = string(sipPacket.Req.StatusCode)
		r.StatusDescription = string(sipPacket.Req.StatusDesc)
		return &r
	}
	return nil
}

func (tf ToFilter) Exists(s string) bool {

	return false
}
