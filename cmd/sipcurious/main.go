package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/marv2097/siprocket"
)

var (
	file = flag.String("file", "", "The SIP pcap file that will be parsed")
	to = flag.String("to", "", "SIP `To:` destination")
	from = flag.String("from", "", "SIP `From:` destination")
	help = flag.Bool("help", false, "Display usage help")
)


func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s \n\n", os.Args[0])
		fmt.Println("If no `--to` and `--from` are specified then the program will output `To:` and `From:` from all SIP dialogs.")
		fmt.Println("Parameters:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	if *file == "" {
		errorOut("you need to specify the file with --file")
	}

	sipFrom := strings.ToLower(*from)
	sipTo := strings.ToLower(*to)

	trace, err := parsePcapFile(*file)
	if err != nil {
		errorOut(fmt.Sprintf("cannot parse SIP trace: %s",err))
	}

	// Parse the sip data
	var sipPacket siprocket.SipMsg
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

		sipPacket = siprocket.Parse(td)
		if string(sipPacket.Req.Method) == "INVITE" {
			if sipTo == string(sipPacket.To.User) || sipFrom == string(sipPacket.From.User) {
				fp = append(fp, sipPacket)
			}
		}

	}

	fmt.Printf("Found %v packets\n", len(fp))
	for _, pk := range fp {
		fmt.Printf("CallID: %s\tFrom: %s\tTo: %s\n", string(pk.CallId.Value), string(pk.From.User), string(pk.To.User))
	}
}

func errorOut(msg string) {
	fmt.Printf("error: %s\n", msg)
	os.Exit(-1)
}

func warnOut(msg string) {
	fmt.Printf("warning: %s\n", msg)
}