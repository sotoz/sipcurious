# sipcurious [![Build Status](https://travis-ci.org/sotoz/sipcurious.svg?branch=master)](https://travis-ci.org/sotoz/sipcurious) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/sotoz/sipcurious/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/sotoz/sipcurious/?branch=master) [![Code Coverage](https://scrutinizer-ci.com/g/sotoz/sipcurious/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/sotoz/sipcurious/?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/sotoz/sipcurious)](https://goreportcard.com/report/github.com/sotoz/sipcurious) [![GPLv3 license](https://img.shields.io/badge/License-GPLv3-blue.svg)](http://perso.crans.org/besson/LICENSE.html)

Sipcurious is a command line utility that parses SIP pcap files and filters out SIP packets based on the parameters given.
It can be used for searching if a number exists in dialogs in big pcap files that are hard to open with wireshark or other SIP trace viewing utilities.

Latest version v1.1

### Usage
```
$ sipcurious --file my_super_trace.pcap --to 12345 --from 67890
Found 3 packets
Timestamp                       Info		CallID					From		To
2005-07-04T11:56:58+02:00       INVITE		533788078C449C0BB69E5497@0270ffffffff	+123458861760	+678903997371
2005-07-04T11:56:59+02:00       403 Forbidden	533788078C449C0BB69E5497@0270ffffffff	+123458861760	+678903997371
2005-07-04T11:57:00+02:00       ACK		533788078C449C0BB69E5497@0270ffffffff	+123458861760	+678903997371
```

Another example of usage that shows the `unique` flag and the `callid` filter:
```
$ sipcurious --file cmd/sipcurious/aaa.pcap --callid 29858 -unique
The --unique flag was used. Showing only the first packet found.
Timestamp                        Info    CallID                                  From            To
2005-07-04T11:56:58+02:00        29858147-465b0752@29858051-465b07b2     35104723        35104723
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
- Parse more than one files at the same time.
- Add filters based on Request URI, Source IP.
- Properly show results per SIP dialog and show the dialog in a graph as well.
- Add a different export type (ex csv, json). Now it's just tabular data.

## Copyright
Sotiris Gkanouris 2018. Read the LICENSE to learn about the GNU GENERAL PUBLIC LICENSE.

## Contribution
Feel free to add issues, questions, pull requests. Just fork it, code, and create a PR and I'll be happy to review and merge.
