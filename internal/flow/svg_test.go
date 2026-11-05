package flow

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"

	"github.com/sotoz/sipcurious/internal/call"
)

type svgStats struct {
	root                        xml.StartElement
	lines, rects, texts, titles int
	paths, markers              int
	classes                     map[string]int
	textBody                    strings.Builder
}

// parseSVG decodes s with encoding/xml in strict mode and fails on any
// element or attribute that could execute code or fetch a resource.
func parseSVG(t testing.TB, s string) svgStats {
	t.Helper()
	st := svgStats{classes: map[string]int{}}
	dec := xml.NewDecoder(strings.NewReader(s))
	first := true
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid XML: %v\n%s", err, s)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			if first {
				st.root, first = e, false
			}
			switch e.Name.Local {
			case "script", "foreignObject", "image", "use", "a", "iframe", "animate", "set":
				t.Fatalf("forbidden element <%s>", e.Name.Local)
			case "line":
				st.lines++
			case "rect":
				st.rects++
			case "text":
				st.texts++
			case "title":
				st.titles++
			case "path":
				st.paths++
			case "marker":
				st.markers++
			}
			for _, a := range e.Attr {
				n := strings.ToLower(a.Name.Local)
				if strings.HasPrefix(n, "on") || n == "href" || a.Name.Space == "http://www.w3.org/1999/xlink" {
					t.Fatalf("forbidden attribute %s on <%s>", a.Name.Local, e.Name.Local)
				}
				if n == "class" {
					for _, c := range strings.Fields(a.Value) {
						st.classes[c]++
					}
				}
				if strings.Contains(strings.ToLower(a.Value), "http") && a.Name.Local != "xmlns" {
					t.Fatalf("external reference in %s=%q", a.Name.Local, a.Value)
				}
			}
		case xml.CharData:
			st.textBody.Write(e)
		}
	}
	if st.root.Name.Local != "svg" {
		t.Fatalf("root is %q", st.root.Name.Local)
	}
	return st
}

func attr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func TestSVGStructure(t *testing.T) {
	svg, err := SVG(withStreams(answered()), Options{UTC: true, SDP: true, Media: true})
	if err != nil {
		t.Fatal(err)
	}
	st := parseSVG(t, svg)
	if !strings.HasPrefix(svg, "<svg ") || attr(st.root, "xmlns") != "http://www.w3.org/2000/svg" {
		t.Error("missing svg namespace")
	}
	if st.classes["fl-life"] != 2 {
		t.Errorf("lifelines = %d, want 2", st.classes["fl-life"])
	}
	if st.classes["fl-box"] != 2 {
		t.Errorf("participant boxes = %d, want 2", st.classes["fl-box"])
	}
	// 7 SIP messages (3 requests, 4 responses) + 2 RTP streams: one arrow each.
	arrows := st.classes["fl-req"] + st.classes["fl-res"] + st.classes["fl-fail"] + st.classes["fl-rtp"]
	if arrows != 9 || st.classes["fl-rtp"] != 2 || st.classes["fl-req"] != 3 || st.classes["fl-res"] != 4 {
		t.Errorf("arrow classes = %v", st.classes)
	}
	if st.classes["fl-time"] < 9 {
		t.Errorf("time labels = %d", st.classes["fl-time"])
	}
	if st.classes["fl-gap"] != 2 {
		t.Errorf("gap labels = %d, want 2", st.classes["fl-gap"])
	}
	if st.markers != 4 {
		t.Errorf("markers = %d", st.markers)
	}
	if !strings.Contains(st.textBody.String(), "RTP streams") {
		t.Error("RTP table missing")
	}
}

// answeredWithBadRow is the answered call with correlated RTP.
func answeredWithBadRow() call.Call { return withStreams(answered()) }

func TestSVGScalesWithParticipants(t *testing.T) {
	w := func(c call.Call) int {
		st := parseSVG(t, mustSVG(t, c))
		n := 0
		for _, ch := range attr(st.root, "width") {
			n = n*10 + int(ch-'0')
		}
		return n
	}
	w2, w3 := w(failed()), w(proxied())
	if w3 <= w2 {
		t.Errorf("3 participants (%d px) not wider than 2 (%d px)", w3, w2)
	}
}

func mustSVG(t testing.TB, c call.Call) string {
	t.Helper()
	s, err := SVG(c, Options{UTC: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSVGFailureAndRetrans(t *testing.T) {
	svg := mustSVG(t, failed())
	st := parseSVG(t, svg)
	if st.classes["fl-fail"] != 2 || st.classes["fl-failbg"] != 2 || st.classes["fl-failtx"] != 2 {
		t.Errorf("failure classes: %v", st.classes)
	}
	if st.classes["fl-retx"] != 1 || strings.Count(svg, `opacity=".6"`) != 2 {
		t.Errorf("retransmission classes: %v", st.classes)
	}
}

func TestSVGLongCallID(t *testing.T) {
	id := strings.Repeat("abcdef0123456789", 20) + "@host"
	c := build(
		sg{callID: id, at: 0, src: alice, dst: bob, method: "INVITE", cseq: 1, branch: "z9hG4bKa"},
		sg{callID: id, at: ms(5), src: bob, dst: alice, code: 200, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "t"},
	)
	svg := mustSVG(t, c)
	st := parseSVG(t, svg)
	if st.titles < 2 {
		t.Errorf("no tooltip title for ellipsised Call-ID (%d titles)", st.titles)
	}
	if !strings.Contains(svg, "…") {
		t.Error("Call-ID not ellipsised")
	}
}

func TestSVGHostile(t *testing.T) {
	svg, err := SVG(hostile(), Options{UTC: true, SDP: true, Media: true, MaxLabel: 10})
	if err != nil {
		t.Fatal(err)
	}
	parseSVG(t, svg)
	checkSafe(t, "svg", svg, true)
}
