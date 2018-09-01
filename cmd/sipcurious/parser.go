package main

import (
	"errors"
	"os"

	"github.com/marv2097/siprocket"
	"github.com/sotoz/gopcap/pkg/gopcap"
)

func parsePcapFile(file string) (gopcap.PcapFile, error) {
	if file == "" {
		return gopcap.PcapFile{}, errors.New("empty file specified")
	}

	pcapfile, _ := os.Open(file)
	parsed, err := gopcap.Parse(pcapfile)
	if err != nil {
		return gopcap.PcapFile{}, errors.New("cannot parse the pcap file")
	}
	return parsed, nil
}

func parseSIPTrace(trace gopcap.PcapFile) ([]siprocket.SipMsg, error) {
	var results []siprocket.SipMsg
	for _, packet := range trace.Packets {
		d := packet.Data
		if d == nil {
			warnOut("unexpected packet data")
			continue
		}

		td := d.LinkData().InternetData().TransportData()
		if td == nil {
			warnOut("unexpected transport data")
			continue
		}

		sipPacket := siprocket.Parse(td)
		results = append(results, sipPacket)
	}
	return results, nil
}
