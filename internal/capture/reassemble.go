package capture

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/gopacket/gopacket/layers"
)

const (
	// maxPendingDatagrams bounds the number of incomplete fragmented
	// datagrams held at once; the oldest is dropped beyond it.
	maxPendingDatagrams = 512
	// maxDatagramSize is the largest IP payload we reassemble.
	maxDatagramSize = 65535
	// maxFragments bounds the fragments kept for one datagram.
	maxFragments = 1024
)

// fragKey identifies the datagram a fragment belongs to. For IPv4 proto is the
// IP protocol; for IPv6 it is zero and v6 is set.
type fragKey struct {
	src, dst netip.Addr
	id       uint32
	proto    uint8
	v6       bool
}

type fragPart struct {
	off  int
	data []byte
}

type fragSet struct {
	parts []fragPart
	bytes int // bytes stored, overlaps counted twice
	total int // payload length once the last fragment was seen, else -1
	proto layers.IPProtocol
}

// A nil *reassembler drops every fragment.
//
// reassembler puts IPv4 and IPv6 fragments back together. It is used by one
// ReadFile call only, so it needs no locking and no timeouts: a capture file
// has its own clock and incomplete datagrams are simply evicted when too many
// pile up. Overlapping fragments: the earliest received bytes win.
type reassembler struct {
	sets  map[fragKey]*fragSet
	order []fragKey // creation order, may hold keys already completed or evicted
}

func newReassembler() *reassembler {
	return &reassembler{sets: make(map[fragKey]*fragSet)}
}

// add stores one fragment (data is copied) and reports whether the datagram is
// now complete, in which case it returns the whole payload and the protocol
// of the first fragment's next header. proto is the protocol or next-header
// field of this fragment, only meaningful for the one at offset 0.
func (r *reassembler) add(k fragKey, off int, more bool, data []byte, proto layers.IPProtocol) ([]byte, layers.IPProtocol, bool) {
	end := off + len(data)
	if r == nil || len(data) == 0 || end > maxDatagramSize || (more && len(data)%8 != 0) {
		return nil, 0, false
	}
	fs := r.sets[k]
	if fs == nil {
		fs = &fragSet{total: -1}
		r.sets[k] = fs
		r.order = append(r.order, k)
		for len(r.sets) > maxPendingDatagrams {
			old := r.order[0]
			r.order = r.order[1:]
			delete(r.sets, old)
		}
		if len(r.order) > 4*maxPendingDatagrams {
			r.order = slices.DeleteFunc(r.order, func(k fragKey) bool { return r.sets[k] == nil })
		}
	}
	for _, p := range fs.parts {
		if p.off == off && len(p.data) == len(data) {
			return nil, 0, false // duplicate
		}
	}
	if len(fs.parts) >= maxFragments {
		delete(r.sets, k)
		return nil, 0, false
	}
	fs.parts = append(fs.parts, fragPart{off, slices.Clone(data)})
	fs.bytes += len(data)
	if off == 0 {
		fs.proto = proto
	}
	if !more {
		fs.total = end
	}
	if fs.total < 0 || fs.bytes < fs.total {
		return nil, 0, false
	}

	parts := slices.Clone(fs.parts)
	slices.SortStableFunc(parts, func(a, b fragPart) int { return cmp.Compare(a.off, b.off) })
	out := make([]byte, 0, fs.total)
	for _, p := range parts {
		if p.off > len(out) {
			return nil, 0, false // hole
		}
		if end := p.off + len(p.data); end > len(out) {
			out = append(out, p.data[len(out)-p.off:]...)
		}
	}
	if len(out) != fs.total {
		return nil, 0, false // a fragment extends past the last one, or hole at the end
	}
	delete(r.sets, k)
	return out, fs.proto, true
}
