package main

import (
	"reflect"
	"testing"
	"time"
)

func TestSearchFilters(t *testing.T) {
	packet1 := sipMessage{}
	packet1.pct.CallId.Value = []byte("callid")
	packet1.pct.From.User = []byte("from123")
	packet1.pct.To.User = []byte("to456")
	packet1.pct.From.Src = []byte("sip:from123@siptest.com")
	packet1.pct.To.Src = []byte("sip:to456@siptest.com")
	packet1.pct.Contact.Src = []byte("contact")
	tests := []struct {
		name       string
		sipPackets []sipMessage
		sp         searchParams
		want       []Result
	}{
		{
			"test-two-results",
			[]sipMessage{
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
			[]sipMessage{
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
	packet1 := sipMessage{}
	packet1.pct.CallId.Value = []byte("callid")
	packet1.pct.From.User = []byte("from123")
	packet1.pct.To.User = []byte("to456")
	packet1.pct.From.Src = []byte("sip:from123@siptest.com")
	packet1.pct.To.Src = []byte("sip:to456@siptest.com")
	packet1.pct.Contact.Src = []byte("contact")

	type args struct {
		sipPacket sipMessage
		from      string
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
				"no-find",
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := FromFilter{}
			res := ff.Search(tt.args.sipPacket, tt.args.from)
			if !reflect.DeepEqual(res, tt.want) {
				t.Errorf("\ngot : %s\nwant: %s", res, *tt.want)
			}
		})
	}
}

func TestToFilterSearch(t *testing.T) {
	packet1 := sipMessage{}
	packet1.pct.CallId.Value = []byte("callid")
	packet1.pct.From.User = []byte("from123")
	packet1.pct.To.User = []byte("to456")
	packet1.pct.From.Src = []byte("sip:from123@siptest.com")
	packet1.pct.To.Src = []byte("sip:to456@siptest.com")
	packet1.pct.Contact.Src = []byte("contact")

	type args struct {
		sipPacket sipMessage
		to        string
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
				"no-find",
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := ToFilter{}
			res := ff.Search(tt.args.sipPacket, tt.args.to)
			if !reflect.DeepEqual(res, tt.want) {
				t.Errorf("\ngot : %s\nwant: %s", res, *tt.want)
			}
		})
	}
}
func TestCallIDFilterSearch(t *testing.T) {
	packet1 := sipMessage{}
	packet1.pct.CallId.Value = []byte("wewantthiscallid")
	packet1.pct.From.User = []byte("from123")
	packet1.pct.To.User = []byte("to456")
	packet1.pct.From.Src = []byte("sip:from123@siptest.com")
	packet1.pct.To.Src = []byte("sip:to456@siptest.com")
	packet1.pct.Contact.Src = []byte("contact")

	type args struct {
		sipPacket sipMessage
		callid    string
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
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := CallIDFilter{}
			res := ff.Search(tt.args.sipPacket, tt.args.callid)
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

func benchmarkSearchFilters(i int, b *testing.B) {

	packet1 := sipMessage{}
	packet1.pct.CallId.Value = []byte("callid")
	packet1.pct.From.User = []byte("from123")
	packet1.pct.To.User = []byte("to456")
	packet1.pct.From.Src = []byte("sip:from123@siptest.com")
	packet1.pct.To.Src = []byte("sip:to456@siptest.com")
	packet1.pct.Contact.Src = []byte("contact")

	var packets []sipMessage

	for k := 0; k <= i; k++ {
		packets = append(packets, packet1)
	}
	sp := searchParams{
		"to123",
		"from456",
		"callidyolo",
	}
	for n := 0; n <= b.N; n++ {
		searchFilters(packets, sp)
	}
}

func BenchmarkSearchFilters10(b *testing.B)    { benchmarkSearchFilters(10, b) }
func BenchmarkSearchFilters100(b *testing.B)   { benchmarkSearchFilters(100, b) }
func BenchmarkSearchFilters1000(b *testing.B)  { benchmarkSearchFilters(1000, b) }
func BenchmarkSearchFilters10000(b *testing.B) { benchmarkSearchFilters(10000, b) }
