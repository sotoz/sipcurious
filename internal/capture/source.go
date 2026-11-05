package capture

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// ctxCheckInterval is how many packets are processed between ctx checks.
const ctxCheckInterval = 1024

// maxSnaplen is libpcap's MAXIMUM_SNAPLEN, the largest packet record accepted
// from a classic pcap file even when its header announces a smaller snaplen.
const maxSnaplen = 262144

// readBufSize is the size of the buffered reader in front of every file.
const readBufSize = 1 << 18

// pcapngMagic is the block type of the pcapng Section Header Block, which
// is the first four bytes of every pcapng file.
var pcapngMagic = [4]byte{0x0a, 0x0d, 0x0d, 0x0a}

// rawPacket is one record of a capture file.
type rawPacket struct {
	data    []byte // valid until the next call to next
	ts      time.Time
	capLen  int // len(data)
	origLen int // length on the wire
	lt      layers.LinkType
}

// packetSource yields the packets of one capture file.
type packetSource interface {
	// next returns the next packet. io.EOF marks a clean end of file; any
	// other error is a damaged tail.
	next() (rawPacket, error)
}

type ngSource struct{ r *pcapgo.NgReader }

func (s ngSource) next() (rawPacket, error) {
	data, ci, err := s.r.ZeroCopyReadPacketData()
	if err != nil {
		return rawPacket{}, err
	}
	lt := s.r.LinkType()
	if len(ci.AncillaryData) > 0 {
		if v, ok := ci.AncillaryData[0].(layers.LinkType); ok {
			lt = v
		}
	}
	return rawPacket{data: data, ts: ci.Timestamp.UTC(), capLen: ci.CaptureLength, origLen: ci.Length, lt: lt}, nil
}

// newSource detects gzip compression and the capture format (classic pcap or
// pcapng) by magic number.
func newSource(r io.Reader) (packetSource, error) {
	br := bufio.NewReaderSize(r, readBufSize)
	if gz, err := br.Peek(2); err == nil && gz[0] == 0x1f && gz[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		br = bufio.NewReaderSize(zr, readBufSize)
	}
	magic, err := br.Peek(len(pcapngMagic))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("not a pcap or pcapng file: file too short")
		}
		return nil, err
	}
	if [4]byte(magic) == pcapngMagic {
		opts := pcapgo.DefaultNgReaderOptions
		opts.WantMixedLinkType = true
		opts.SkipUnknownVersion = true
		ng, err := pcapgo.NewNgReader(br, opts)
		if err != nil {
			return nil, err
		}
		return ngSource{ng}, nil
	}
	cr, err := newClassicReader(br)
	if err != nil {
		return nil, err
	}
	return cr, nil
}
