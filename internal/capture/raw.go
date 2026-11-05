package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket/layers"
)

// ErrTruncated is wrapped by the error ReadRaw returns when a capture ends or
// breaks in the middle of a record. Every intact packet before the damage has
// been delivered; Read treats the same condition as a warning.
var ErrTruncated = errors.New("capture ends abruptly")

// RawPacket is one undecoded record of a capture file, exactly as stored.
type RawPacket struct {
	Index       int             // 1-based record number inside the file, the same numbering as Packet.Index
	Time        time.Time       // capture timestamp (UTC), full nanosecond precision
	LinkType    layers.LinkType // link type of the interface the record belongs to
	Data        []byte          // the captured frame; only valid during the callback, copy what you keep
	OrigLen     int             // length of the frame on the wire (may be larger than len(Data))
	InterfaceID int             // pcapng interface number inside the file; always 0 for classic pcap
}

// ReadRaw streams the records of one capture file to fn without decoding
// them, so a caller can copy selected frames byte for byte. It understands
// the same inputs as Read (pcap, pcapng, gzip, "-" for standard input) and
// numbers records exactly as Read numbers Packet.Index. fn returning false
// stops the read and ReadRaw returns nil.
//
// A file that cannot be opened or is not a capture file fails with an error
// wrapping the path. A damaged tail yields an error wrapping ErrTruncated
// after all intact records were delivered. A cancelled ctx stops the read
// promptly and returns ctx's error wrapped with the path.
func ReadRaw(ctx context.Context, path string, fn func(RawPacket) bool) error {
	if path == "-" {
		return ReadRawFrom(ctx, path, os.Stdin, fn)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer f.Close()
	return ReadRawFrom(ctx, path, f, fn)
}

// ReadRawFrom is ReadRaw for a capture read from r; name only labels errors.
func ReadRawFrom(ctx context.Context, name string, r io.Reader, fn func(RawPacket) bool) error {
	src, err := newSource(r)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for n := 0; ; n++ {
		if n%ctxCheckInterval == 0 {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		rp, ifid, rerr := nextWithInterface(src)
		if errors.Is(rerr, io.EOF) {
			return nil
		}
		if rerr != nil {
			return fmt.Errorf("%s: record %d (%v); %d records read: %w", name, n+1, rerr, n, ErrTruncated)
		}
		if !fn(RawPacket{Index: n + 1, Time: rp.ts, LinkType: rp.lt, Data: rp.data, OrigLen: rp.origLen, InterfaceID: ifid}) {
			return nil
		}
	}
}

// nextWithInterface is packetSource.next that also reports the pcapng
// interface number of the record (0 for classic pcap).
func nextWithInterface(src packetSource) (rawPacket, int, error) {
	ng, ok := src.(ngSource)
	if !ok {
		rp, err := src.next()
		return rp, 0, err
	}
	data, ci, err := ng.r.ZeroCopyReadPacketData()
	if err != nil {
		return rawPacket{}, 0, err
	}
	lt := ng.r.LinkType()
	if len(ci.AncillaryData) > 0 {
		if v, ok := ci.AncillaryData[0].(layers.LinkType); ok {
			lt = v
		}
	}
	return rawPacket{data: data, ts: ci.Timestamp.UTC(), capLen: ci.CaptureLength, origLen: ci.Length, lt: lt}, ci.InterfaceIndex, nil
}
