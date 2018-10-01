package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/marv2097/siprocket"
	"github.com/sotoz/gopcap/pkg/gopcap"
)

type sipMessage struct {
	pct       siprocket.SipMsg
	timestamp time.Duration
}

func parsePcapFile(file string) (gopcap.PcapFile, error) {
	if file == "" {
		return gopcap.PcapFile{}, errors.New("empty file specified")
	}

	pcapfile, _ := os.Open(file)
	parsed, err := gopcap.Parse(pcapfile)
	if err != nil {
		return gopcap.PcapFile{}, fmt.Errorf("cannot parse the pcap file: %s", err)
	}
	return parsed, nil
}

func parseSIPTrace(trace gopcap.PcapFile) ([]sipMessage, error) {
	var results []sipMessage
	for _, packet := range trace.Packets {
		var r sipMessage
		d := packet.Data
		if d == nil {
			continue
		}

		td := d.LinkData().InternetData().TransportData()
		if td == nil {
			warnOut("unexpected transport data")
			continue
		}

		sipPacket := siprocket.Parse(td)
		r.pct = sipPacket
		r.timestamp = packet.Timestamp
		results = append(results, r)
	}
	return results, nil
}
