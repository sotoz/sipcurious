package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"text/tabwriter"

	"github.com/marv2097/siprocket"
)

var (
	file = flag.String("file", "", "The SIP pcap file that will be parsed")
	to   = flag.String("to", "", "SIP `To:` destination")
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
		errorOut(fmt.Sprintf("cannot parse SIP trace: %s", err))
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

	fmt.Printf("Found %v packets\n", len(fp))

	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, '\t', tabwriter.AlignRight)

	fmt.Fprintln(w, fmt.Sprintf("Info\tCallID\tFrom\tTo\t"))

	var info string
	for _, pk := range fp {
		if len(string(pk.Req.Method)) == 0 {
			info = fmt.Sprintf("%s %s", pk.Req.StatusCode, pk.Req.StatusDesc)
		} else {
			info = fmt.Sprintf("%s", string(pk.Req.Method))
		}
		fmt.Fprintln(w, fmt.Sprintf("%s\t%s\t%s\t%s\t", info, string(pk.CallId.Value), string(pk.From.User), string(pk.To.User)))
	}
	w.Flush()
}

func errorOut(msg string) {
	fmt.Printf("error: %s\n", msg)
	os.Exit(-1)
}

func warnOut(msg string) {
	fmt.Printf("warning: %s\n", msg)
}