package main

import (
	"testing"
)

func TestParseSIPTrace(t *testing.T) {
	trace, err := parsePcapFile("aaa.pcap")
	if err != nil {
		t.Errorf("parsePcapFile() error = %v", err)
	}

	t.Run("test-parse-sip-trace", func(t *testing.T) {
		packets, err := parseSIPTrace(trace)
		if err != nil {
			t.Errorf("parseSIPTrace() error = %v", err)
			return
		}
		if len(packets) != 691 {
			t.Errorf("Wrong length of test pcap file detected/")
		}
	})
}

func TestParsePcapFile(t *testing.T) {

	t.Run("test-parse-sip-trace", func(t *testing.T) {
		trace, err := parsePcapFile("aaa.pcap")
		if err != nil {
			t.Errorf("parsePcapFile() error = %v", err)
		}
		if len(trace.Packets) != 692 {
			t.Errorf("Wrong length of test pcap file detected. Found %v, wanted %v", len(trace.Packets), 692)
		}
	})
}
