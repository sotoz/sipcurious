package capture

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket/layers"
)

// Classic pcap magic numbers as read in little-endian byte order. The byte
// swapped values identify a file written on a machine of the other endianness.
const (
	magicMicro   = 0xa1b2c3d4 // microsecond timestamps
	magicNano    = 0xa1b23c4d // nanosecond timestamps
	magicKuz     = 0xa1b2cd34 // libpcap "modified" format (Alexey Kuznetsov's patches)
	magicMicroBE = 0xd4c3b2a1
	magicNanoBE  = 0x4d3cb2a1
	magicKuzBE   = 0x34cdb2a1
)

const (
	pcapFileHeaderLen = 24
	pcapRecHeaderLen  = 16
	// The modified format appends ifindex (u32), protocol (u16), pkt_type (u8)
	// and a pad byte to every record header.
	pcapKuzExtraLen = 8
	pcapMajor       = 2
)

// classicReader reads classic pcap files the way libpcap does, which is more
// lenient than gopacket's pcapgo.Reader: any 2.x version is accepted and a
// record whose captured length exceeds its original length is read using the
// captured length. Only a captured length above maxSnaplen is refused, so a
// corrupt record cannot trigger a huge allocation.
//
// Supported: microsecond and nanosecond timestamps in either byte order, the
// modified libpcap format. Gzip is handled by newSource.
type classicReader struct {
	r        io.Reader
	order    binary.ByteOrder
	nanoMul  int64 // multiplier from the sub-second field to nanoseconds
	hdrLen   int   // length of one record header
	linkType layers.LinkType
	hdr      [pcapRecHeaderLen + pcapKuzExtraLen]byte
	buf      []byte // reused packet buffer
}

// newClassicReader parses the file header from br, which must be positioned at
// the start of the file.
func newClassicReader(br *bufio.Reader) (*classicReader, error) {
	var h [pcapFileHeaderLen]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return nil, fmt.Errorf("reading pcap file header: %w", err)
	}
	c := &classicReader{r: br, hdrLen: pcapRecHeaderLen}
	switch magic := binary.LittleEndian.Uint32(h[0:4]); magic {
	case magicMicro:
		c.order, c.nanoMul = binary.LittleEndian, 1000
	case magicNano:
		c.order, c.nanoMul = binary.LittleEndian, 1
	case magicMicroBE:
		c.order, c.nanoMul = binary.BigEndian, 1000
	case magicNanoBE:
		c.order, c.nanoMul = binary.BigEndian, 1
	case magicKuz:
		c.order, c.nanoMul, c.hdrLen = binary.LittleEndian, 1000, pcapRecHeaderLen+pcapKuzExtraLen
	case magicKuzBE:
		c.order, c.nanoMul, c.hdrLen = binary.BigEndian, 1000, pcapRecHeaderLen+pcapKuzExtraLen
	default:
		return nil, fmt.Errorf("unknown pcap magic %#08x", magic)
	}
	if major := c.order.Uint16(h[4:6]); major != pcapMajor {
		return nil, fmt.Errorf("unsupported pcap major version %d", major)
	}
	// Minor version, timezone, sigfigs and snaplen are ignored: libpcap does
	// not honour them either, packets are bounded by maxSnaplen instead.
	c.linkType = layers.LinkType(c.order.Uint32(h[20:24]))
	return c, nil
}

// next returns the next packet. The returned data aliases an internal buffer
// that is overwritten by the following call. It returns io.EOF only at a clean
// end of file; a file ending inside a record yields io.ErrUnexpectedEOF.
func (c *classicReader) next() (rawPacket, error) {
	h := c.hdr[:c.hdrLen]
	if _, err := io.ReadFull(c.r, h); err != nil {
		return rawPacket{}, err
	}
	sec := int64(c.order.Uint32(h[0:4]))
	sub := int64(c.order.Uint32(h[4:8])) * c.nanoMul
	caplen := c.order.Uint32(h[8:12])
	if caplen > maxSnaplen {
		return rawPacket{}, fmt.Errorf("capture length %d exceeds the maximum of %d", caplen, maxSnaplen)
	}
	rp := rawPacket{
		ts:      time.Unix(sec, sub).UTC(),
		capLen:  int(caplen),
		origLen: int(c.order.Uint32(h[12:16])),
		lt:      c.linkType,
	}

	if cap(c.buf) < rp.capLen {
		c.buf = make([]byte, max(rp.capLen, min(2*cap(c.buf), maxSnaplen)))
	}
	rp.data = c.buf[:rp.capLen]
	if _, err := io.ReadFull(c.r, rp.data); err != nil {
		if err == io.EOF {
			// The header was complete, so the file ends mid-record.
			err = io.ErrUnexpectedEOF
		}
		return rawPacket{}, err
	}
	return rp, nil
}
