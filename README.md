# sipcurious
Sipcurious is a command line utility that parses SIP pcap files and filters out SIP packets based on the parameters given.

### Example
```
$ sipcurious --file my_super_trace.pcap --to 12345 --from 67890
Found 3 packets
Info		CallID					From		To
INVITE		533788078C449C0BB69E5497@0270ffffffff	+123458861760	+678903997371
403 Forbidden	533788078C449C0BB69E5497@0270ffffffff	+123458861760	+678903997371
ACK		533788078C449C0BB69E5497@0270ffffffff	+123458861760	+678903997371
```

## Todo:
- Parse more than one files at the same time
- Add filters based on Request URI, Source IP.