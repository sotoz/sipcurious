# sipcurious [![Build Status](https://travis-ci.org/sotoz/sipcurious.svg?branch=master)](https://travis-ci.org/sotoz/sipcurious) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/sotoz/sipcurious/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/sotoz/sipcurious/?branch=master) [![Code Coverage](https://scrutinizer-ci.com/g/sotoz/sipcurious/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/sotoz/sipcurious/?branch=master)
Sipcurious is a command line utility that parses SIP pcap files and filters out SIP packets based on the parameters given.
It can be used for searching if a number exists in dialogs in big pcap files that are hard to open with wireshark or other SIP trace viewing utilities.

### Usage
```
$ sipcurious --file my_super_trace.pcap --to 12345 --from 67890
Found 3 packets
Info		CallID					From		To
INVITE		533788078C449C0BB69E5497@0270ffffffff	+123458861760	+678903997371
403 Forbidden	533788078C449C0BB69E5497@0270ffffffff	+123458861760	+678903997371
ACK		533788078C449C0BB69E5497@0270ffffffff	+123458861760	+678903997371
```

### Building from source
```
$ git clone git@github.com:sotoz/sipcurious.git
$ go build -o sipcurious github.com/sotoz/sipcurious/cmd/sipcurious
```
Or instead of doing the `go build`, you can use the Makefile by doing a
```
$ make all
```
## Todo:
- Correctly show the timestamp of a packet.
- Parse more than one files at the same time.
- Add filters based on Request URI, Source IP.
- Properly show results per dialog and show the dialog in a graph as well.
