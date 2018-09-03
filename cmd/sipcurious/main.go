package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

var (
	file   = flag.String("file", "", "The SIP pcap file that will be parsed")
	to     = flag.String("to", "", "SIP To: Header")
	from   = flag.String("from", "", "SIP From: Header")
	unique = flag.Bool("unique", false, "Show only the first instance of found packets based on a unique call-id. Usually this is the INVITE. This parameter will make sipcurious to be faster and return the first result for each occurence.")
	help   = flag.Bool("help", false, "Display usage help")
)

type searchParams struct {
	to   string
	from string
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s \n", os.Args[0])
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

	*from = strings.ToLower(*from)
	*to = strings.ToLower(*to)

	trace, err := parsePcapFile(*file)
	if err != nil {
		errorOut(fmt.Sprintf("cannot parse SIP trace: %s", err))
	}

	// Parse the the SIP data
	fp, err := parseSIPTrace(trace)
	if err != nil {
		errorOut(err.Error())
	}

	sp := searchParams{
		*from,
		*to,
	}
	// Search the SIP packets for the filters
	fr := searchFilters(fp, sp)

	showResults(fr)
}

func showResults(fp []Result) {
	totalPackets := len(fp)
	if totalPackets <= 0 {
		fmt.Println("No Packets found for the filters you provided.")
		os.Exit(0)
	}
	if *unique {
		fmt.Println("The --unique flag was used. Showing only the first packet found.")
	} else {
		fmt.Printf("Found %v packets\n", len(fp))
	}
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, '\t', tabwriter.AlignRight)
	fmt.Fprintln(w, fmt.Sprintf("Time\tInfo\tCallID\tFrom\tTo\t"))
	var info string
	for _, pk := range fp {
		if len(pk.Method) == 0 {
			info = fmt.Sprintf("%s %s", pk.StatusCode, pk.StatusDescription)
		} else {
			info = fmt.Sprintf("%s", string(pk.Method))
		}
		fmt.Fprintln(w, fmt.Sprintf("%s\t%s\t%s\t%s\t", info, pk.CallID, pk.From, pk.To))
	}
	w.Flush()
}
