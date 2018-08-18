package main

import (
	"errors"
	"os"
	"strings"

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

func parseSIPTrace(trace gopcap.PcapFile, sipTo string, sipFrom string) ([]siprocket.SipMsg, error) {
	var fp []siprocket.SipMsg
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
		if sipTo == "" {
			if strings.Contains(string(sipPacket.From.User), sipFrom) {
				fp = append(fp, sipPacket)
			}
			continue
		}
		if sipFrom == "" {
			if strings.Contains(string(sipPacket.To.User), sipTo) {
				fp = append(fp, sipPacket)
			}
			continue
		}
	}
	return fp, nil
}
