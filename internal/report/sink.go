package report

import "io"

// flushThreshold is the buffered size at which a sink hands data to its writer.
const flushThreshold = 32 << 10

// sink is a buffered writer with a sticky error. Writers append straight to
// buf and call maybeFlush at record boundaries, so output is streamed in
// ~32 KiB chunks and a single record is never split across two Write calls.
type sink struct {
	w   io.Writer
	buf []byte
	err error
}

func newSink(w io.Writer) *sink {
	return &sink{w: w, buf: make([]byte, 0, flushThreshold+4<<10)}
}

// maybeFlush writes the buffer out once it is large enough.
func (s *sink) maybeFlush() {
	if len(s.buf) >= flushThreshold {
		s.flush()
	}
}

// flush writes any buffered data and returns the first error seen.
func (s *sink) flush() error {
	if len(s.buf) > 0 && s.err == nil {
		_, s.err = s.w.Write(s.buf)
	}
	s.buf = s.buf[:0]
	return s.err
}

// str appends str.
func (s *sink) str(str string) { s.buf = append(s.buf, str...) }

// indent appends n levels of two-space indentation.
func (s *sink) indent(n int) {
	for range n {
		s.buf = append(s.buf, ' ', ' ')
	}
}
