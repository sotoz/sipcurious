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
			"testpacket1",
			[]siprocket.SipMsg{
				packet1,
			},
			searchParams{
				"from123",
				"to456",
			},
			[]Result{
				{
					[]byte("from123"),
					[]byte("to456"),
					[]byte("callid"),
					8 * time.Second,
					[]byte("method"),
					[]byte("200"),
					[]byte("OK"),
				},
			},
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
