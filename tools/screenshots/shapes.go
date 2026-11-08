package main

import (
	"sort"
	"strings"
)

// segKind is the kind of a path segment.
type segKind uint8

const (
	segH segKind = iota + 1
	segV
	segRect
	segRaw
)

// seg is one piece of a path: a horizontal line from (x1, y1) to (x2, y1),
// a vertical line from (x1, y1) to (x1, y2), a rectangle with corners
// (x1, y1) and (x2, y2), or raw path data.
type seg struct {
	kind           segKind
	x1, y1, x2, y2 float64
	raw            string
}

// path collects the segments drawn in one color. Lines and rectangles that
// continue the previous one are merged, which keeps borders and QR codes
// small.
type path struct {
	segs []seg
	ends map[[4]float64]int
}

func (p *path) add(s seg) {
	if p.ends == nil {
		p.ends = map[[4]float64]int{}
	}
	var start, end [4]float64
	switch s.kind {
	case segH:
		start, end = [4]float64{1, s.y1, s.x1}, [4]float64{1, s.y1, s.x2}
	case segV:
		start, end = [4]float64{2, s.x1, s.y1}, [4]float64{2, s.x1, s.y2}
	case segRect:
		start, end = [4]float64{3, s.y1, s.y2, s.x1}, [4]float64{3, s.y1, s.y2, s.x2}
	default:
		p.segs = append(p.segs, s)
		return
	}
	if i, ok := p.ends[start]; ok {
		delete(p.ends, start)
		if s.kind == segV {
			p.segs[i].y2 = s.y2
		} else {
			p.segs[i].x2 = s.x2
		}
		p.ends[end] = i
		return
	}
	p.segs = append(p.segs, s)
	p.ends[end] = len(p.segs) - 1
}

func (p *path) String() string {
	var b strings.Builder
	for _, s := range p.segs {
		switch s.kind {
		case segH:
			b.WriteString("M" + num(s.x1) + " " + num(s.y1) + "H" + num(s.x2))
		case segV:
			b.WriteString("M" + num(s.x1) + " " + num(s.y1) + "V" + num(s.y2))
		case segRect:
			w := num(s.x2 - s.x1)
			b.WriteString("M" + num(s.x1) + " " + num(s.y1) + "h" + w + "v" + num(s.y2-s.y1) + "h-" + w + "z")
		default:
			b.WriteString(s.raw)
		}
	}
	return b.String()
}

// paths maps a style key, such as a color, to its path.
type paths map[string]*path

func (ps paths) add(key string, s seg) {
	p := ps[key]
	if p == nil {
		p = &path{}
		ps[key] = p
	}
	p.add(s)
}

func (ps paths) keys() []string {
	keys := make([]string, 0, len(ps))
	for k := range ps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
