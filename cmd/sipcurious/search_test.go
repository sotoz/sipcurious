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
			},
			[]Result{
				{
					[]byte("from123"),
					[]byte("to456"),
					[]byte("callid"),
					0 * time.Second,
					nil,
					nil,
					nil,
				},
				{
					[]byte("from123"),
					[]byte("to456"),
					[]byte("callid"),
					0 * time.Second,
					nil,
					nil,
					nil,
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
	out := make(chan *Result)

	type fields struct {
		found bool
		param string
	}
	type args struct {
		sipPacket siprocket.SipMsg
		from      string
		out       chan<- *Result
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Result
	}{
		{
			"from-filter-test-1-results",
			fields{
				true,
				"123",
			},
			args{
				packet1,
				"123",
				out,
			},
			&Result{
				[]byte("from123"),
				[]byte("to456"),
				[]byte("callid"),
				0 * time.Second,
				nil,
				nil,
				nil,
			},
		},
		{
			"from-filter-test-2-no-results",
			fields{
				true,
				"123",
			},
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
			ff := FromFilter{
				found: tt.fields.found,
				param: tt.fields.param,
			}
			go ff.Search(tt.args.sipPacket, tt.args.from, tt.args.out)
			res := <-out
			if !reflect.DeepEqual(res, tt.want) {
				t.Errorf("\ngot : %v\nwant: %s", res, *tt.want)
			}
		})
	}
}

func TestToFilterSearch(t *testing.T) {
	packet1 := siprocket.SipMsg{}
	packet1.CallId.Value = []byte("callid")
	packet1.From.User = []byte("from123")
	packet1.To.User = []byte("to456")
	out := make(chan *Result)

	type fields struct {
		found bool
		param string
	}
	type args struct {
		sipPacket siprocket.SipMsg
		from      string
		out       chan<- *Result
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Result
	}{
		{
			"to-filter-test-1-results",
			fields{
				true,
				"456",
			},
			args{
				packet1,
				"456",
				out,
			},
			&Result{
				[]byte("from123"),
				[]byte("to456"),
				[]byte("callid"),
				0 * time.Second,
				nil,
				nil,
				nil,
			},
		},
		{
			"to-filter-test-2-no-results",
			fields{
				true,
				"123",
			},
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
			ff := ToFilter{
				found: tt.fields.found,
				param: tt.fields.param,
			}
			go ff.Search(tt.args.sipPacket, tt.args.from, tt.args.out)
			res := <-out
			if !reflect.DeepEqual(res, tt.want) {
				t.Errorf("\ngot : %v\nwant: %s", res, *tt.want)
			}
		})
	}
}

func TestFromFilterGetCmdParameter(t *testing.T) {
	type fields struct {
		found bool
		param string
	}
	type args struct {
		s searchParams
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			"test-getcmdparameter-from",
			fields{
				true,
				"from456",
			},
			args{
				searchParams{
					"to123",
					"from456",
				},
			},
			"from456",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := FromFilter{
				found: tt.fields.found,
				param: tt.fields.param,
			}
			if got := ff.GetCmdParameter(tt.args.s); got != tt.want {
				t.Errorf("FromFilter.GetCmdParameter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToFilterGetCmdParameter(t *testing.T) {
	type fields struct {
		found bool
		param string
	}
	type args struct {
		s searchParams
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			"test-getcmdparameter-to",
			fields{
				true,
				"to123",
			},
			args{
				searchParams{
					"to123",
					"from456",
				},
			},
			"to123",
		}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := ToFilter{
				found: tt.fields.found,
				param: tt.fields.param,
			}
			if got := tf.GetCmdParameter(tt.args.s); got != tt.want {
				t.Errorf("ToFilter.GetCmdParameter() = %v, want %v", got, tt.want)
			}
		})
	}
}
