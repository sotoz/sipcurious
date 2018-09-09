package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/marv2097/siprocket"
)

func TestSearchFilters(t *testing.T) {

	packet1 := siprocket.SipMsg{}
	packet1.CallId.Value = []byte("callid")
	packet1.From.User = []byte("from123")
	packet1.To.User = []byte("to456")
	packet1.From.Src = []byte("sip:from123@siptest.com")
	packet1.To.Src = []byte("sip:to456@siptest.com")
	packet1.Contact.Src = []byte("contact")
	tests := []struct {
		name       string
		sipPackets []siprocket.SipMsg
		sp         searchParams
		want       []Result
	}{
		{
			"test-two-results",
			[]siprocket.SipMsg{
				packet1,
			},
			searchParams{
				"to456",
				"from123",
				"callidyolo",
			},
			[]Result{
				{
					[]byte("sip:from123@siptest.com"),
					[]byte("sip:to456@siptest.com"),
					[]byte("callid"),
					0 * time.Second,
					nil,
					nil,
					nil,
					[]byte("contact"),
				},
				{
					[]byte("sip:from123@siptest.com"),
					[]byte("sip:to456@siptest.com"),
					[]byte("callid"),
					0 * time.Second,
					nil,
					nil,
					nil,
					[]byte("contact"),
				},
			},
		},
		{
			"test-no-results",
			[]siprocket.SipMsg{
				packet1,
			},
			searchParams{
				"yolo",
				"swag",
				"callidyolo",
			},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := searchFilters(tt.sipPackets, tt.sp); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("\ngot : %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestFromFilterSearch(t *testing.T) {
	packet1 := siprocket.SipMsg{}
	packet1.CallId.Value = []byte("callid")
	packet1.From.User = []byte("from123")
	packet1.To.User = []byte("to456")
	packet1.From.Src = []byte("sip:from123@siptest.com")
	packet1.To.Src = []byte("sip:to456@siptest.com")
	packet1.Contact.Src = []byte("contact")
	out := make(chan *Result)

	type args struct {
		sipPacket siprocket.SipMsg
		from      string
		out       chan<- *Result
	}
	tests := []struct {
		name string
		args args
		want *Result
	}{
		{
			"from-filter-test-1-results",
			args{
				packet1,
				"123",
				out,
			},
			&Result{
				[]byte("sip:from123@siptest.com"),
				[]byte("sip:to456@siptest.com"),
				[]byte("callid"),
				0 * time.Second,
				nil,
				nil,
				nil,
				[]byte("contact"),
			},
		},
		{
			"from-filter-test-2-no-results",
			args{
				packet1,
				"123",
				out,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := FromFilter{}
			go ff.Search(tt.args.sipPacket, tt.args.from, tt.args.out)
			res := <-out
			if !reflect.DeepEqual(res, tt.want) {
				t.Errorf("\ngot : %s\nwant: %s", res, *tt.want)
			}
		})
	}
}

func TestToFilterSearch(t *testing.T) {
	packet1 := siprocket.SipMsg{}
	packet1.CallId.Value = []byte("callid")
	packet1.From.User = []byte("from123")
	packet1.To.User = []byte("to456")
	packet1.From.Src = []byte("sip:from123@siptest.com")
	packet1.To.Src = []byte("sip:to456@siptest.com")
	packet1.Contact.Src = []byte("contact")
	out := make(chan *Result)

	type args struct {
		sipPacket siprocket.SipMsg
		from      string
		out       chan<- *Result
	}
	tests := []struct {
		name string
		args args
		want *Result
	}{
		{
			"to-filter-test-1-results",
			args{
				packet1,
				"456",
				out,
			},
			&Result{
				[]byte("sip:from123@siptest.com"),
				[]byte("sip:to456@siptest.com"),
				[]byte("callid"),
				0 * time.Second,
				nil,
				nil,
				nil,
				[]byte("contact"),
			},
		},
		{
			"to-filter-test-2-no-results",
			args{
				packet1,
				"123",
				out,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := ToFilter{}
			go ff.Search(tt.args.sipPacket, tt.args.from, tt.args.out)
			res := <-out
			if !reflect.DeepEqual(res, tt.want) {
				t.Errorf("\ngot : %s\nwant: %s", res, *tt.want)
			}
		})
	}
}
func TestCallIDFilterSearch(t *testing.T) {
	packet1 := siprocket.SipMsg{}
	packet1.CallId.Value = []byte("wewantthiscallid")
	packet1.From.User = []byte("from123")
	packet1.To.User = []byte("to456")
	packet1.From.Src = []byte("sip:from123@siptest.com")
	packet1.To.Src = []byte("sip:to456@siptest.com")
	packet1.Contact.Src = []byte("contact")
	out := make(chan *Result)

	type args struct {
		sipPacket siprocket.SipMsg
		callid    string
		out       chan<- *Result
	}
	tests := []struct {
		name string
		args args
		want *Result
	}{
		{
			"callid-filter-test-1-results",
			args{
				packet1,
				"wewantthiscallid",
				out,
			},
			&Result{
				[]byte("sip:from123@siptest.com"),
				[]byte("sip:to456@siptest.com"),
				[]byte("wewantthiscallid"),
				0 * time.Second,
				nil,
				nil,
				nil,
				[]byte("contact"),
			},
		},
		{
			"callid-filter-test-2-no-results",
			args{
				packet1,
				"123",
				out,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := CallIDFilter{}
			go ff.Search(tt.args.sipPacket, tt.args.callid, tt.args.out)
			res := <-out
			if !reflect.DeepEqual(res, tt.want) {
				t.Errorf("\ngot : %s\nwant: %s", *res, *tt.want)
			}
		})
	}
}

func TestFromFilterGetCmdParameter(t *testing.T) {

	type args struct {
		s searchParams
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"test-getcmdparameter-from",
			args{
				searchParams{
					"to123",
					"from456",
					"callidyolo",
				},
			},
			"from456",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := FromFilter{}
			if got := ff.GetCmdParameter(tt.args.s); got != tt.want {
				t.Errorf("FromFilter.GetCmdParameter() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestToFilterGetCmdParameter(t *testing.T) {
	type args struct {
		s searchParams
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"test-getcmdparameter-to",
			args{
				searchParams{
					"to123",
					"from456",
					"callidyolo",
				},
			},
			"to123",
		}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := ToFilter{}
			if got := tf.GetCmdParameter(tt.args.s); got != tt.want {
				t.Errorf("ToFilter.GetCmdParameter() = %s, want %s", got, tt.want)
			}
		})
	}
}
