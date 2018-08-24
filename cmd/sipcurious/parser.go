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

func parseSIPTrace(trace gopcap.PcapFile) ([]Result, error) {
	var results []Result
	for _, packet := range trace.Packets {
		d := packet.Data
		packetTimestamp := packet.Timestamp
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

		results = searchFilters(sipPacket, packetTimestamp, results)
	}
	return results, nil
}

//
// type UniqueFilter string
//
// const (
// 	fromUniqueFilter UniqueFilter = "from"
// 	toUniqueFilter   UniqueFilter = "to"
// )

//
// func contains(ap SIPMsgs, ufilter UniqueFilter, f string) bool {
// 	for _, s := range ap {
// 		switch ufilter {
// 		case "from":
// 			if string(s.From.User) == f {
// 				return true
// 			}
// 		case "to":
// 			if string(s.To.User) == f {
// 				return true
// 			}
// 		}
// 	}
// 	return false
// }
