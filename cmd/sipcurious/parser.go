package main

import (
	"os"
	"errors"

	"github.com/sotoz/gopcap/pkg/gopcap"
)

func parsePcapFile(file string) (gopcap.PcapFile,error) {
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