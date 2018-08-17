# sipcurious
Sipcurious is a command line utility that parses SIP pcap files and filters out results based on the parameters given.

### example
```
$ sipcurious --file my_super_trace.pcap --to 12345 --from 67890
```

## Todo:
- Parse more than one files at the same time
- Add filters based on Request URI, Source IP.