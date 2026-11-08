package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"charm.land/lipgloss/v2"
)

// Geometry of the SVG terminal. A cell is twice as high as it is wide, so
// the two half-block modules of a QR code row are square.
const (
	cellW    = 9.0
	cellH    = 18.0
	fontSize = 15.0
	baseline = 13.5
	padding  = 16.0
	titleH   = 34.0
	radius   = 10.0
)

const fontStack = `ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace`

// svgOptions are the colors and title of the window.
type svgOptions struct {
	title      string
	background string
	foreground string
}

// cellStyle is the SGR state of a cell. Empty colors mean the default.
type cellStyle struct {
	fg, bg                                          string
	bold, faint, italic, underline, reverse, strike bool
}

// cell is one terminal column. A wide character occupies its first cell;
// the following cell has cont set.
type cell struct {
	text  string
	style cellStyle
	cont  bool
}

// cluster is a grapheme cluster with its style, before it is placed on the
// grid.
type cluster struct {
	text  string
	style cellStyle
}

// parseANSI splits an ANSI line into grapheme clusters with their styles.
// Control sequences other than SGR are skipped.
func parseANSI(line string) []cluster {
	var out []cluster
	var st cellStyle
	joinNext := false
	for i := 0; i < len(line); {
		if line[i] == 0x1b && i+1 < len(line) {
			switch line[i+1] {
			case '[':
				j := i + 2
				for j < len(line) && (line[j] < 0x40 || line[j] > 0x7e) {
					j++
				}
				if j < len(line) && line[j] == 'm' {
					st = applySGR(st, line[i+2:j])
				}
				i = j + 1
			case ']', 'P', '_', '^':
				j := i + 2
				for j < len(line) {
					if line[j] == 0x07 {
						j++
						break
					}
					if line[j] == 0x1b && j+1 < len(line) && line[j+1] == '\\' {
						j += 2
						break
					}
					j++
				}
				i = j
			default:
				i += 2
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		i += size
		if r < 0x20 || r == 0x7f {
			continue
		}
		s := string(r)
		if len(out) > 0 && (joinNext || (r != ' ' && lipgloss.Width(s) == 0)) {
			out[len(out)-1].text += s
			joinNext = r == 0x200d
			continue
		}
		joinNext = false
		out = append(out, cluster{text: s, style: st})
	}
	return out
}

// applySGR applies the parameters of one SGR sequence.
func applySGR(st cellStyle, params string) cellStyle {
	if params == "" {
		return cellStyle{}
	}
	fields := strings.FieldsFunc(params, func(r rune) bool { return r == ';' || r == ':' })
	nums := make([]int, len(fields))
	for i, f := range fields {
		nums[i], _ = strconv.Atoi(f)
	}
	for i := 0; i < len(nums); i++ {
		n := nums[i]
		switch {
		case n == 0:
			st = cellStyle{}
		case n == 1:
			st.bold = true
		case n == 2:
			st.faint = true
		case n == 3:
			st.italic = true
		case n == 4:
			st.underline = true
		case n == 7:
			st.reverse = true
		case n == 9:
			st.strike = true
		case n == 22:
			st.bold, st.faint = false, false
		case n == 23:
			st.italic = false
		case n == 24:
			st.underline = false
		case n == 27:
			st.reverse = false
		case n == 29:
			st.strike = false
		case n >= 30 && n <= 37:
			st.fg = basicColors[n-30]
		case n >= 90 && n <= 97:
			st.fg = basicColors[n-90+8]
		case n >= 40 && n <= 47:
			st.bg = basicColors[n-40]
		case n >= 100 && n <= 107:
			st.bg = basicColors[n-100+8]
		case n == 39:
			st.fg = ""
		case n == 49:
			st.bg = ""
		case n == 38 || n == 48 || n == 58:
			c, used := extendedColor(nums[i+1:])
			i += used
			switch n {
			case 38:
				st.fg = c
			case 48:
				st.bg = c
			}
		}
	}
	return st
}

// extendedColor parses the arguments of 38, 48 or 58: "5;n" or "2;r;g;b".
// It returns the color and the number of arguments used.
func extendedColor(args []int) (string, int) {
	if len(args) >= 2 && args[0] == 5 {
		return xterm256(args[1]), 2
	}
	if len(args) >= 4 && args[0] == 2 {
		return fmt.Sprintf("#%02x%02x%02x", clampByte(args[1]), clampByte(args[2]), clampByte(args[3])), 4
	}
	return "", len(args)
}

func clampByte(n int) int { return max(0, min(255, n)) }

// basicColors are the 16 ANSI colors, as xterm draws them.
var basicColors = [16]string{
	"#000000", "#cd0000", "#00cd00", "#cdcd00", "#0000ee", "#cd00cd", "#00cdcd", "#e5e5e5",
	"#7f7f7f", "#ff0000", "#00ff00", "#ffff00", "#5c5cff", "#ff00ff", "#00ffff", "#ffffff",
}

// xterm256 returns color n of the xterm 256-color palette.
func xterm256(n int) string {
	switch {
	case n < 0 || n > 255:
		return ""
	case n < 16:
		return basicColors[n]
	case n < 232:
		n -= 16
		level := func(v int) int {
			if v == 0 {
				return 0
			}
			return 55 + 40*v
		}
		return fmt.Sprintf("#%02x%02x%02x", level(n/36), level(n/6%6), level(n%6))
	}
	g := 8 + 10*(n-232)
	return fmt.Sprintf("#%02x%02x%02x", g, g, g)
}

// grid places the clusters of each line on a cols-wide grid, using the
// same width rules as the interface.
func grid(screen string) ([][]cell, int) {
	lines := strings.Split(strings.TrimRight(screen, "\n"), "\n")
	rows := make([][]cell, len(lines))
	cols := 0
	for y, line := range lines {
		var row []cell
		for _, c := range parseANSI(line) {
			w := lipgloss.Width(c.text)
			if w == 0 {
				continue
			}
			row = append(row, cell{text: c.text, style: c.style})
			for range w - 1 {
				row = append(row, cell{style: c.style, cont: true})
			}
		}
		rows[y] = row
		cols = max(cols, len(row))
	}
	return rows, cols
}

// resolved returns the foreground and background of a style, with
// defaults filled in and reverse video applied.
func resolved(st cellStyle, opt svgOptions) (fg, bg string) {
	fg, bg = st.fg, st.bg
	if fg == "" {
		fg = opt.foreground
	}
	if bg == "" {
		bg = opt.background
	}
	if st.reverse {
		fg, bg = bg, fg
	}
	return fg, bg
}

// svgWriter accumulates the elements of the image.
type svgWriter struct {
	opt   svgOptions
	rects strings.Builder
	text  strings.Builder
	// blocks, lines and curves group shapes by color (and stroke width),
	// so that each color needs one element only.
	blocks, lines, curves paths
}

func num(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func xmlEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// renderSVG converts an ANSI screen into an SVG terminal window.
func renderSVG(screen string, opt svgOptions) string {
	rows, cols := grid(screen)
	w := &svgWriter{
		opt:    opt,
		blocks: paths{},
		lines:  paths{},
		curves: paths{},
	}
	ox, oy := padding, titleH+padding
	for y, row := range rows {
		top := oy + float64(y)*cellH
		w.backgrounds(row, ox, top)
		w.glyphs(row, ox, top)
	}

	width := 2*padding + float64(cols)*cellW
	height := titleH + 2*padding + float64(len(rows))*cellH
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%s" height="%s" viewBox="0 0 %s %s" role="img" aria-label="%s">`+"\n",
		num(width), num(height), num(width), num(height), xmlEscape(opt.title))
	fmt.Fprintf(&b, "<title>%s</title>\n", xmlEscape(opt.title))
	fmt.Fprintf(&b, `<rect width="%s" height="%s" rx="%s" fill="%s"/>`+"\n", num(width), num(height), num(radius), opt.background)
	fmt.Fprintf(&b, `<path d="M0 %s A%s %s 0 0 1 %s 0 H%s A%s %s 0 0 1 %s %s V%s H0 Z" fill="#1b1b1f"/>`+"\n",
		num(radius), num(radius), num(radius), num(radius), num(width-radius), num(radius), num(radius), num(width), num(radius), num(titleH))
	fmt.Fprintf(&b, `<path d="M0 %s H%s" stroke="#000000" stroke-opacity="0.6"/>`+"\n", num(titleH-0.5), num(width))
	for i, c := range []string{"#ff5f57", "#febc2e", "#28c840"} {
		fmt.Fprintf(&b, `<circle cx="%s" cy="%s" r="6" fill="%s"/>`+"\n", num(20+float64(i)*20), num(titleH/2), c)
	}
	fmt.Fprintf(&b, `<text x="%s" y="%s" text-anchor="middle" font-family="%s" font-size="13" fill="#a8a8b0">%s</text>`+"\n",
		num(width/2), num(titleH/2+4.5), fontStack, xmlEscape(opt.title))
	fmt.Fprintf(&b, `<rect x="0.5" y="0.5" width="%s" height="%s" rx="%s" fill="none" stroke="#ffffff" stroke-opacity="0.12"/>`+"\n",
		num(width-1), num(height-1), num(radius-0.5))

	b.WriteString(`<g shape-rendering="crispEdges">` + "\n")
	b.WriteString(w.rects.String())
	for _, key := range w.blocks.keys() {
		fill, opacity, _ := strings.Cut(key, "/")
		extra := ""
		if opacity != "1" {
			extra = ` fill-opacity="` + opacity + `"`
		}
		fmt.Fprintf(&b, `<path fill="%s"%s d="%s"/>`+"\n", fill, extra, w.blocks[key].String())
	}
	b.WriteString("</g>\n")
	for _, key := range w.lines.keys() {
		stroke, sw, _ := strings.Cut(key, "/")
		fmt.Fprintf(&b, `<path fill="none" stroke="%s" stroke-width="%s" d="%s"/>`+"\n", stroke, sw, w.lines[key].String())
	}
	for _, key := range w.curves.keys() {
		fmt.Fprintf(&b, `<path fill="none" stroke="%s" stroke-width="1" d="%s"/>`+"\n", key, w.curves[key].String())
	}
	fmt.Fprintf(&b, `<g font-family="%s" font-size="%s" fill="%s" xml:space="preserve" style="white-space:pre">`+"\n",
		fontStack, num(fontSize), opt.foreground)
	b.WriteString(w.text.String())
	b.WriteString("</g>\n</svg>\n")
	return b.String()
}

// backgrounds draws one rectangle per run of cells that share a
// background other than the window's.
func (w *svgWriter) backgrounds(row []cell, ox, top float64) {
	for x := 0; x < len(row); {
		_, bg := resolved(row[x].style, w.opt)
		end := x + 1
		for end < len(row) {
			_, next := resolved(row[end].style, w.opt)
			if next != bg {
				break
			}
			end++
		}
		if !strings.EqualFold(bg, w.opt.background) {
			fmt.Fprintf(&w.rects, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s"/>`+"\n",
				num(ox+float64(x)*cellW), num(top), num(float64(end-x)*cellW), num(cellH), bg)
		}
		x = end
	}
}

// textRun is a run of narrow cells drawn as one tspan.
type textRun struct {
	start int
	cells []cell
}

// glyphs draws the characters of a row: block and box-drawing characters
// as shapes, everything else as text.
func (w *svgWriter) glyphs(row []cell, ox, top float64) {
	var runs []textRun
	for x := 0; x < len(row); x++ {
		c := row[x]
		if c.cont {
			continue
		}
		fg, _ := resolved(c.style, w.opt)
		left := ox + float64(x)*cellW
		if w.block(c.text, fg, left, top) || w.box(c.text, fg, left, top) {
			continue
		}
		wide := x+1 < len(row) && row[x+1].cont
		if c.text == " " && !c.style.underline && !c.style.strike {
			continue
		}
		if !wide && len(runs) > 0 {
			last := &runs[len(runs)-1]
			end := last.start + len(last.cells)
			if end == x && sameText(last.cells[0].style, c.style) && lipgloss.Width(last.cells[len(last.cells)-1].text) == 1 {
				last.cells = append(last.cells, c)
				continue
			}
			if gap := x - end; gap > 0 && gap <= 3 && sameText(last.cells[0].style, c.style) && lipgloss.Width(last.cells[len(last.cells)-1].text) == 1 && allSpaces(row[end:x]) {
				for i := end; i < x; i++ {
					last.cells = append(last.cells, row[i])
				}
				last.cells = append(last.cells, c)
				continue
			}
		}
		runs = append(runs, textRun{start: x, cells: []cell{c}})
		if wide {
			runs = append(runs, textRun{start: -1})
		}
	}
	var spans strings.Builder
	for _, run := range runs {
		if run.start < 0 {
			continue
		}
		w.span(&spans, run, ox)
	}
	if spans.Len() == 0 {
		return
	}
	fmt.Fprintf(&w.text, `<text y="%s">%s</text>`+"\n", num(top+baseline), spans.String())
}

func allSpaces(cells []cell) bool {
	for _, c := range cells {
		if c.text != " " || c.style.underline || c.style.strike {
			return false
		}
	}
	return true
}

// sameText reports whether two styles draw text identically. Backgrounds
// do not matter here; they are drawn separately.
func sameText(a, b cellStyle) bool {
	return a.fg == b.fg && a.bold == b.bold && a.faint == b.faint && a.italic == b.italic &&
		a.underline == b.underline && a.reverse == b.reverse && a.strike == b.strike && (!a.reverse || a.bg == b.bg)
}

// span writes one tspan, stretched to exactly its number of cells so that
// columns stay aligned whatever the font.
func (w *svgWriter) span(b *strings.Builder, run textRun, ox float64) {
	var text strings.Builder
	cells := 0
	for _, c := range run.cells {
		text.WriteString(c.text)
		cells += lipgloss.Width(c.text)
	}
	st := run.cells[0].style
	fg, _ := resolved(st, w.opt)
	fmt.Fprintf(b, `<tspan x="%s"`, num(ox+float64(run.start)*cellW))
	if cells > 1 && len(run.cells) > 1 {
		fmt.Fprintf(b, ` textLength="%s"`, num(float64(cells)*cellW))
	}
	if !strings.EqualFold(fg, w.opt.foreground) {
		fmt.Fprintf(b, ` fill="%s"`, fg)
	}
	if st.bold {
		b.WriteString(` font-weight="bold"`)
	}
	if st.italic {
		b.WriteString(` font-style="italic"`)
	}
	if st.faint {
		b.WriteString(` fill-opacity="0.6"`)
	}
	switch {
	case st.underline && st.strike:
		b.WriteString(` text-decoration="underline line-through"`)
	case st.underline:
		b.WriteString(` text-decoration="underline"`)
	case st.strike:
		b.WriteString(` text-decoration="line-through"`)
	}
	b.WriteString(">")
	b.WriteString(xmlEscape(text.String()))
	b.WriteString("</tspan>")
}

// blockShapes maps block elements to the rectangles they fill, in eighths
// of the cell: x, y, width, height. Shades fill the whole cell with an
// opacity.
var blockShapes = map[string][][4]int{
	"█": {{0, 0, 8, 8}},
	"▀": {{0, 0, 8, 4}},
	"▄": {{0, 4, 8, 4}},
	"▌": {{0, 0, 4, 8}},
	"▐": {{4, 0, 4, 8}},
	"▁": {{0, 7, 8, 1}},
	"▂": {{0, 6, 8, 2}},
	"▃": {{0, 5, 8, 3}},
	"▅": {{0, 3, 8, 5}},
	"▆": {{0, 2, 8, 6}},
	"▇": {{0, 1, 8, 7}},
	"▔": {{0, 0, 8, 1}},
	"▏": {{0, 0, 1, 8}},
	"▕": {{7, 0, 1, 8}},
	"▖": {{0, 4, 4, 4}},
	"▗": {{4, 4, 4, 4}},
	"▘": {{0, 0, 4, 4}},
	"▝": {{4, 0, 4, 4}},
	"▙": {{0, 0, 4, 8}, {4, 4, 4, 4}},
	"▛": {{0, 0, 8, 4}, {0, 4, 4, 4}},
	"▜": {{0, 0, 8, 4}, {4, 4, 4, 4}},
	"▟": {{4, 0, 4, 8}, {0, 4, 4, 4}},
	"▚": {{0, 0, 4, 4}, {4, 4, 4, 4}},
	"▞": {{4, 0, 4, 4}, {0, 4, 4, 4}},
	"░": {{0, 0, 8, 8}},
	"▒": {{0, 0, 8, 8}},
	"▓": {{0, 0, 8, 8}},
}

var shadeOpacity = map[string]string{"░": "0.25", "▒": "0.5", "▓": "0.75"}

// block draws a block element as filled rectangles.
func (w *svgWriter) block(text, fg string, left, top float64) bool {
	shapes, ok := blockShapes[text]
	if !ok {
		return false
	}
	opacity := "1"
	if o, ok := shadeOpacity[text]; ok {
		opacity = o
	}
	for _, s := range shapes {
		x, y := left+float64(s[0])*cellW/8, top+float64(s[1])*cellH/8
		w.blocks.add(fg+"/"+opacity, seg{kind: segRect, x1: x, y1: y, x2: x + float64(s[2])*cellW/8, y2: y + float64(s[3])*cellH/8})
	}
	return true
}

// Arm weights of box-drawing characters.
const (
	light  = 1
	heavy  = 2
	double = 3
)

// boxArms maps box-drawing characters to the weight of their arms: left,
// right, up, down.
var boxArms = map[string][4]int{
	"─": {light, light, 0, 0}, "│": {0, 0, light, light},
	"┌": {0, light, 0, light}, "┐": {light, 0, 0, light}, "└": {0, light, light, 0}, "┘": {light, 0, light, 0},
	"├": {0, light, light, light}, "┤": {light, 0, light, light}, "┬": {light, light, 0, light}, "┴": {light, light, light, 0},
	"┼": {light, light, light, light},
	"╴": {light, 0, 0, 0}, "╶": {0, light, 0, 0}, "╵": {0, 0, light, 0}, "╷": {0, 0, 0, light},
	"━": {heavy, heavy, 0, 0}, "┃": {0, 0, heavy, heavy},
	"┏": {0, heavy, 0, heavy}, "┓": {heavy, 0, 0, heavy}, "┗": {0, heavy, heavy, 0}, "┛": {heavy, 0, heavy, 0},
	"┣": {0, heavy, heavy, heavy}, "┫": {heavy, 0, heavy, heavy}, "┳": {heavy, heavy, 0, heavy}, "┻": {heavy, heavy, heavy, 0},
	"╋": {heavy, heavy, heavy, heavy},
	"╸": {heavy, 0, 0, 0}, "╺": {0, heavy, 0, 0}, "╹": {0, 0, heavy, 0}, "╻": {0, 0, 0, heavy},
	"┠": {0, light, heavy, heavy}, "┨": {light, 0, heavy, heavy}, "┯": {light, light, 0, heavy}, "┷": {light, light, heavy, 0},
	"┝": {0, heavy, light, light}, "┥": {heavy, 0, light, light},
	"═": {double, double, 0, 0}, "║": {0, 0, double, double},
	"╔": {0, double, 0, double}, "╗": {double, 0, 0, double}, "╚": {0, double, double, 0}, "╝": {double, 0, double, 0},
}

// roundCorners are the rounded corners, drawn as arcs: the direction of
// the horizontal arm (+1 right) and of the vertical arm (+1 down).
var roundCorners = map[string][2]int{
	"╭": {1, 1}, "╮": {-1, 1}, "╰": {1, -1}, "╯": {-1, -1},
}

// box draws a box-drawing character as strokes, so borders join without
// gaps between lines.
func (w *svgWriter) box(text, fg string, left, top float64) bool {
	cx, cy := left+cellW/2, top+cellH/2
	right, bottom := left+cellW, top+cellH
	if rc, ok := roundCorners[text]; ok {
		cy := lineY(cy, light)
		r := cellW / 2
		hx := left
		if rc[0] > 0 {
			hx = right
		}
		vy := top
		if rc[1] > 0 {
			vy = bottom
		}
		sweep := 0
		if rc[0]*rc[1] < 0 {
			sweep = 1
		}
		d := fmt.Sprintf("M%s %sH%sA%s %s 0 0 %d %s %sV%s",
			num(hx), num(cy), num(cx+float64(rc[0])*r), num(r), num(r), sweep, num(cx), num(cy+float64(rc[1])*r), num(vy))
		w.curves.add(fg, seg{kind: segRaw, raw: d})
		return true
	}
	arms, ok := boxArms[text]
	if !ok {
		return false
	}
	if arms[0] == double || arms[1] == double || arms[2] == double || arms[3] == double {
		return w.doubleBox(text, fg, left, top)
	}
	hc := lineY(cy, max(arms[0], arms[1]))
	vc := lineX(cx, max(arms[2], arms[3]))
	hext := float64(max(arms[2], arms[3])) / 2
	vext := float64(max(arms[0], arms[1])) / 2
	for i, weight := range arms {
		if weight == 0 {
			continue
		}
		var s seg
		switch i {
		case 0:
			s = seg{kind: segH, x1: left, y1: lineY(cy, weight), x2: vc + hext}
		case 1:
			s = seg{kind: segH, x1: vc - hext, y1: lineY(cy, weight), x2: right}
		case 2:
			s = seg{kind: segV, x1: lineX(cx, weight), y1: top, y2: hc + vext}
		case 3:
			s = seg{kind: segV, x1: lineX(cx, weight), y1: hc - vext, y2: bottom}
		}
		w.lines.add(fg+"/"+strconv.Itoa(weight), s)
	}
	return true
}

// lineY is the y of a horizontal line through a cell whose centre is at
// cy, placed so that the stroke covers whole pixels.
func lineY(cy float64, weight int) float64 {
	if weight == heavy {
		return cy
	}
	return cy + 0.5
}

// lineX is the x of a vertical line through a cell whose centre is at cx,
// placed so that the stroke covers whole pixels.
func lineX(cx float64, weight int) float64 {
	if weight == heavy {
		return cx - 0.5
	}
	return cx
}

// doubleBox draws the double-line characters used by the large logo.
func (w *svgWriter) doubleBox(text, fg string, left, top float64) bool {
	const g = 1.5
	cx, cy := left+cellW/2, top+cellH/2
	right, bottom := left+cellW, top+cellH
	key := fg + "/1"
	var d string
	switch text {
	case "═":
		w.lines.add(key, seg{kind: segH, x1: left, y1: cy - g, x2: right})
		w.lines.add(key, seg{kind: segH, x1: left, y1: cy + g, x2: right})
		return true
	case "║":
		w.lines.add(key, seg{kind: segV, x1: cx - g, y1: top, y2: bottom})
		w.lines.add(key, seg{kind: segV, x1: cx + g, y1: top, y2: bottom})
		return true
	case "╔":
		d = fmt.Sprintf("M%s %sH%sV%sM%s %sH%sV%s", num(right), num(cy-g), num(cx-g), num(bottom), num(right), num(cy+g), num(cx+g), num(bottom))
	case "╗":
		d = fmt.Sprintf("M%s %sH%sV%sM%s %sH%sV%s", num(left), num(cy-g), num(cx+g), num(bottom), num(left), num(cy+g), num(cx-g), num(bottom))
	case "╚":
		d = fmt.Sprintf("M%s %sH%sV%sM%s %sH%sV%s", num(right), num(cy+g), num(cx-g), num(top), num(right), num(cy-g), num(cx+g), num(top))
	case "╝":
		d = fmt.Sprintf("M%s %sH%sV%sM%s %sH%sV%s", num(left), num(cy+g), num(cx+g), num(top), num(left), num(cy-g), num(cx-g), num(top))
	default:
		return false
	}
	w.lines.add(key, seg{kind: segRaw, raw: d})
	return true
}
