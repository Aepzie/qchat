package tui

import (
	"fmt"
	"image/color"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/glamour/v2"
	gansi "charm.land/glamour/v2/ansi"
	"charm.land/lipgloss/v2"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// Message bodies are untrusted, so Markdown is rendered in two stages.
//
// First the sanitised body is parsed with a plain CommonMark parser and
// written back as a normalised document that uses only the safe subset:
// paragraphs, emphasis, strong emphasis, code spans, code blocks, lists and
// block quotes. Every other construct becomes escaped literal text: a link
// becomes its text followed by the address in brackets, an image becomes
// "[image: alt]", HTML is shown as typed, and a heading becomes strong
// text. All literal text is escaped, so the second stage cannot find links,
// autolinks, tables or HTML in it.
//
// Then glamour renders the normalised document with a style derived from
// the theme. Its output passes a final filter that keeps only SGR (color
// and attribute) escape sequences and drops every other escape sequence and
// control character, so no hyperlink (OSC 8) or other terminal command can
// reach the screen whatever the body contains.
//
// Bodies that are very long, that fail to render, or that render to
// nothing are shown as plain text.

const (
	// maxMarkdownBytes is the size from which a body is shown as plain
	// text. Bodies are capped at maxEntryText when they are sanitised, so a
	// body that reaches it was probably cut.
	maxMarkdownBytes = maxEntryText
	// maxMarkdownCache bounds the cache of rendered bodies.
	maxMarkdownCache = 2048
	// minMarkdownWidth is the narrowest width glamour renders at.
	minMarkdownWidth = 8
)

// markdownCommands are the /markdown palette entries.
var markdownCommands = []command{
	{"/markdown on", "format emphasis, code, lists and quotes"},
	{"/markdown off", "show message text exactly as typed"},
}

// markdownRenderer renders message bodies for one theme. It caches
// renderers per width and rendered bodies, because the history is
// re-rendered on every resize and conversation switch.
type markdownRenderer struct {
	mu        sync.Mutex
	style     gansi.StyleConfig
	renderers map[int]*glamour.TermRenderer
	cache     map[markdownKey][]string
}

type markdownKey struct {
	width int
	body  string
}

func newMarkdownRenderer(t Theme) *markdownRenderer {
	return &markdownRenderer{
		style:     markdownStyle(t),
		renderers: map[int]*glamour.TermRenderer{},
		cache:     map[markdownKey][]string{},
	}
}

// render returns body rendered to lines of at most width cells, or false
// when the body should be shown as plain text.
func (r *markdownRenderer) render(body string, width int) ([]string, bool) {
	if r == nil || width < minMarkdownWidth || len(body) >= maxMarkdownBytes || !hasMarkdown(body) {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := markdownKey{width: width, body: body}
	if lines, ok := r.cache[key]; ok {
		return lines, lines != nil
	}
	lines := r.renderLocked(body, width)
	if len(r.cache) >= maxMarkdownCache {
		clear(r.cache)
	}
	r.cache[key] = lines
	return lines, lines != nil
}

func (r *markdownRenderer) renderLocked(body string, width int) (lines []string) {
	defer func() {
		if recover() != nil {
			lines = nil
		}
	}()
	tr, ok := r.renderers[width]
	if !ok {
		var err error
		tr, err = glamour.NewTermRenderer(glamour.WithStyles(r.style), glamour.WithWordWrap(width))
		if err != nil {
			return nil
		}
		r.renderers[width] = tr
	}
	out, err := tr.Render(safeMarkdown(body))
	if err != nil {
		return nil
	}
	return fitLines(keepSGR(out), width)
}

// hasMarkdown reports whether body contains a character that can start
// Markdown syntax. Bodies without one render as plain text, which is the
// same result, only faster.
func hasMarkdown(body string) bool {
	return strings.ContainsAny(body, "*_`>#-+[]!<|~\\&=:.)")
}

// fitLines splits rendered text into lines, drops blank lines around it and
// trailing padding, and wraps any line that is still wider than width.
func fitLines(rendered string, width int) []string {
	raw := strings.Split(rendered, "\n")
	var lines []string
	for _, l := range raw {
		l = trimTrailingSpace(l)
		if lipgloss.Width(l) <= width {
			lines = append(lines, l)
			continue
		}
		lines = append(lines, strings.Split(lipgloss.Wrap(l, width, ""), "\n")...)
	}
	for len(lines) > 0 && strings.TrimSpace(stripSGR(lines[0])) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(stripSGR(lines[len(lines)-1])) == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return nil
	}
	return lines
}

// trimTrailingSpace removes spaces at the end of a line, also when they are
// followed or interleaved by SGR sequences, keeping the sequences.
func trimTrailingSpace(line string) string {
	end := len(line)
	for end > 0 {
		switch {
		case line[end-1] == ' ':
			line = line[:end-1] + line[end:]
			end--
		case line[end-1] == 'm':
			start := strings.LastIndex(line[:end], "\x1b[")
			if start < 0 || strings.ContainsFunc(line[start+2:end-1], func(r rune) bool { return (r < '0' || r > '9') && r != ';' && r != ':' }) {
				return line
			}
			end = start
		default:
			return line
		}
	}
	return line
}

// keepSGR returns s with every escape sequence removed except SGR
// sequences, and with every control character removed except newlines.
// Bidirectional formatting characters are removed too.
func keepSGR(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0x1b {
			n, keep := escapeLength(s[i:])
			if keep {
				b.WriteString(s[i : i+n])
			}
			i += n
			continue
		}
		if c < 0x80 {
			if c == '\n' || (c >= 0x20 && c != 0x7f) {
				b.WriteByte(c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if !unicode.IsControl(r) && !unicode.Is(unicode.Bidi_Control, r) {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// escapeLength returns the length of the escape sequence at the start of s
// and whether it is an SGR sequence.
func escapeLength(s string) (int, bool) {
	if len(s) < 2 {
		return len(s), false
	}
	switch s[1] {
	case '[':
		for j := 2; j < len(s); j++ {
			c := s[j]
			if c >= 0x40 && c <= 0x7e {
				params := s[2:j]
				sgr := c == 'm' && !strings.ContainsFunc(params, func(r rune) bool { return (r < '0' || r > '9') && r != ';' && r != ':' })
				return j + 1, sgr
			}
			if c < 0x20 || c > 0x3f {
				return j, false
			}
		}
		return len(s), false
	case ']', 'P', '_', '^', 'X':
		for j := 2; j < len(s); j++ {
			if s[j] == 0x07 {
				return j + 1, false
			}
			if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
				return j + 2, false
			}
		}
		return len(s), false
	}
	return 2, false
}

// stripSGR removes every escape sequence from s.
func stripSGR(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			n, _ := escapeLength(s[i:])
			i += n
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// markdownStyle derives glamour's style from a theme. Margins are zero so
// that the caller controls the layout.
func markdownStyle(t Theme) gansi.StyleConfig {
	t = t.complete()
	hex := func(c color.Color) *string {
		r, g, b, _ := c.RGBA()
		s := fmt.Sprintf("#%02X%02X%02X", r>>8, g>>8, b>>8)
		return &s
	}
	yes := true
	zero, one, two := uint(0), uint(1), uint(2)
	quote := "│ "
	return gansi.StyleConfig{
		Document:    gansi.StyleBlock{StylePrimitive: gansi.StylePrimitive{Color: hex(t.Text)}, Margin: &zero},
		BlockQuote:  gansi.StyleBlock{StylePrimitive: gansi.StylePrimitive{Color: hex(t.Muted)}, Indent: &one, IndentToken: &quote},
		Paragraph:   gansi.StyleBlock{},
		List:        gansi.StyleList{LevelIndent: 2},
		Text:        gansi.StylePrimitive{},
		Emph:        gansi.StylePrimitive{Italic: &yes},
		Strong:      gansi.StylePrimitive{Bold: &yes},
		Item:        gansi.StylePrimitive{BlockPrefix: "• "},
		Enumeration: gansi.StylePrimitive{BlockPrefix: ". "},
		Code: gansi.StyleBlock{StylePrimitive: gansi.StylePrimitive{
			Color: hex(t.Accent), BackgroundColor: hex(t.Highlight),
		}},
		CodeBlock: gansi.StyleCodeBlock{StyleBlock: gansi.StyleBlock{
			StylePrimitive: gansi.StylePrimitive{Color: hex(t.Muted)},
			Margin:         &zero,
			Indent:         &two,
		}},
		HorizontalRule: gansi.StylePrimitive{Color: hex(t.Faint), Format: "\n────\n"},
	}
}

// renderBody draws a message body at width cells: through Markdown when it
// is on and the body renders, as wrapped plain text otherwise.
func renderBody(body string, width int, st styles) []string {
	if st.markdown {
		if lines, ok := st.md.render(body, width); ok {
			return lines
		}
	}
	lines := wrapLines(body, width)
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = st.text.Render(l)
	}
	return out
}

// mdParser parses message bodies. It is a plain CommonMark parser without
// extensions: no tables, no autolinked URLs, no raw HTML rendering.
var (
	mdParserMu sync.Mutex
	mdParser   = goldmark.New().Parser()
)

// safeMarkdown parses a sanitised body and writes it back using only the
// safe subset, with every other construct turned into escaped text.
func safeMarkdown(body string) string {
	src := []byte(body)
	mdParserMu.Lock()
	doc := mdParser.Parse(text.NewReader(src), parser.WithContext(parser.NewContext()))
	mdParserMu.Unlock()
	w := mdWriter{src: src}
	return w.blocks(doc, "\n\n")
}

// mdWriter writes a parsed document back as normalised Markdown.
type mdWriter struct {
	src []byte
}

// blocks writes the block children of parent, separated by sep.
func (w *mdWriter) blocks(parent ast.Node, sep string) string {
	var parts []string
	for n := parent.FirstChild(); n != nil; n = n.NextSibling() {
		if s := w.block(n); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, sep)
}

func (w *mdWriter) block(n ast.Node) string {
	switch n := n.(type) {
	case *ast.Paragraph, *ast.TextBlock:
		return w.inlines(n)
	case *ast.Heading:
		if inner := strings.TrimSpace(w.inlines(n)); inner != "" {
			return "**" + inner + "**"
		}
		return ""
	case *ast.FencedCodeBlock, *ast.CodeBlock:
		return codeBlock(w.rawLines(n))
	case *ast.Blockquote:
		return prefixLines(w.blocks(n, "\n\n"), "> ", "> ")
	case *ast.List:
		return w.list(n)
	case *ast.ThematicBreak:
		return "────"
	case *ast.HTMLBlock:
		lines := w.rawLines(n)
		if n.HasClosure() {
			lines = append(lines, string(n.ClosureLine.Value(w.src)))
		}
		return literalLines(lines)
	}
	return literalLines(w.rawLines(n))
}

// list writes a list, keeping its marker so that adjacent lists stay apart.
func (w *mdWriter) list(l *ast.List) string {
	sep := "\n\n"
	if l.IsTight {
		sep = "\n"
	}
	num := l.Start
	var items []string
	for it := l.FirstChild(); it != nil; it = it.NextSibling() {
		marker := string(l.Marker)
		if l.IsOrdered() {
			marker = fmt.Sprintf("%d%c", num, l.Marker)
			num++
		}
		body := w.blocks(it, sep)
		if body == "" {
			items = append(items, marker)
			continue
		}
		items = append(items, prefixLines(body, marker+" ", strings.Repeat(" ", len(marker)+1)))
	}
	return strings.Join(items, sep)
}

// rawLines returns the source lines of a block without line endings.
func (w *mdWriter) rawLines(n ast.Node) []string {
	segs := n.Lines()
	out := make([]string, 0, segs.Len())
	for i := 0; i < segs.Len(); i++ {
		seg := segs.At(i)
		out = append(out, strings.TrimRight(string(seg.Value(w.src)), "\r\n"))
	}
	return out
}

// inlines writes the inline children of parent.
func (w *mdWriter) inlines(parent ast.Node) string {
	var b strings.Builder
	for n := parent.FirstChild(); n != nil; n = n.NextSibling() {
		w.inline(&b, n)
	}
	return strings.TrimSuffix(b.String(), "\\\n")
}

func (w *mdWriter) inline(b *strings.Builder, n ast.Node) {
	switch n := n.(type) {
	case *ast.Text:
		b.WriteString(escapeMarkdown(w.literal(n.Segment.Value(w.src))))
		if n.HardLineBreak() || n.SoftLineBreak() {
			b.WriteString("\\\n")
		}
	case *ast.String:
		b.WriteString(escapeMarkdown(w.literal(n.Value)))
	case *ast.CodeSpan:
		b.WriteString(codeSpan(strings.ReplaceAll(w.plain(n), "\n", " ")))
	case *ast.Emphasis:
		inner := w.inlines(n)
		if strings.TrimSpace(inner) == "" {
			b.WriteString(inner)
			return
		}
		delim := strings.Repeat("*", n.Level)
		b.WriteString(delim + inner + delim)
	case *ast.Link:
		label := w.inlines(n)
		b.WriteString(label)
		if dest := cleanLine(w.literal(n.Destination), 2048); dest != "" {
			if label != "" {
				b.WriteString(" ")
			}
			b.WriteString(escapeMarkdown("[" + dest + "]"))
		}
	case *ast.AutoLink:
		b.WriteString(escapeMarkdown(cleanLine(string(n.URL(w.src)), 2048)))
	case *ast.Image:
		alt := strings.TrimSpace(strings.ReplaceAll(w.plain(n), "\n", " "))
		if alt == "" {
			b.WriteString(escapeMarkdown("[image]"))
			return
		}
		b.WriteString(escapeMarkdown("[image: " + alt + "]"))
	case *ast.RawHTML:
		for i := 0; i < n.Segments.Len(); i++ {
			seg := n.Segments.At(i)
			b.WriteString(escapeMarkdown(strings.ReplaceAll(string(seg.Value(w.src)), "\n", " ")))
		}
	default:
		b.WriteString(escapeMarkdown(w.plain(n)))
	}
}

// literal resolves backslash escapes and character references in source
// text and sanitises the result again, because a reference such as "&#27;"
// can name a control character.
func (w *mdWriter) literal(raw []byte) string {
	v := util.UnescapePunctuations(raw)
	v = util.ResolveNumericReferences(v)
	v = util.ResolveEntityNames(v)
	return sanitizeText(string(v))
}

// plain returns the text content of n and its descendants, resolved.
func (w *mdWriter) plain(n ast.Node) string {
	var b strings.Builder
	var walk func(ast.Node)
	walk = func(n ast.Node) {
		switch n := n.(type) {
		case *ast.Text:
			if _, code := n.Parent().(*ast.CodeSpan); code {
				b.Write(n.Segment.Value(w.src))
			} else {
				b.WriteString(w.literal(n.Segment.Value(w.src)))
			}
			if n.SoftLineBreak() || n.HardLineBreak() {
				b.WriteByte('\n')
			}
			return
		case *ast.String:
			b.WriteString(w.literal(n.Value))
			return
		}
		for c := n.FirstChild(); c != nil; c = c.NextSibling() {
			walk(c)
		}
	}
	walk(n)
	return sanitizeText(b.String())
}

// escapeMarkdown escapes s so that Markdown reads it as literal text: every
// ASCII punctuation character becomes a numeric character reference.
// References, unlike backslash escapes, are what glamour turns back into
// the character when it draws text, and no Markdown syntax can start with
// one.
func escapeMarkdown(s string) string {
	var b strings.Builder
	b.Grow(len(s) + len(s)/2)
	for _, r := range s {
		if r < 0x80 && isASCIIPunct(byte(r)) {
			fmt.Fprintf(&b, "&#%d;", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isASCIIPunct(c byte) bool {
	return (c >= '!' && c <= '/') || (c >= ':' && c <= '@') || (c >= '[' && c <= '`') || (c >= '{' && c <= '~')
}

// literalLines writes lines as one paragraph of literal text with hard line
// breaks.
func literalLines(lines []string) string {
	var kept []string
	for _, l := range lines {
		if l = strings.TrimSpace(sanitizeText(l)); l != "" {
			kept = append(kept, escapeMarkdown(l))
		}
	}
	return strings.Join(kept, "\\\n")
}

// codeBlock writes a fenced code block whose fence is longer than any run
// of backticks in the code.
func codeBlock(lines []string) string {
	body := strings.Join(lines, "\n")
	fence := strings.Repeat("`", max(3, longestRun(body, '`')+1))
	if body == "" {
		return fence + "\n" + fence
	}
	return fence + "\n" + body + "\n" + fence
}

// codeSpan writes a code span whose delimiters are longer than any run of
// backticks in the code. Glamour resolves character references in code
// spans, so "&" is written as one.
func codeSpan(code string) string {
	code = strings.ReplaceAll(code, "&", "&amp;")
	if strings.TrimSpace(code) == "" {
		return escapeMarkdown(code)
	}
	fence := strings.Repeat("`", longestRun(code, '`')+1)
	pad := ""
	if strings.HasPrefix(code, "`") || strings.HasSuffix(code, "`") || (strings.HasPrefix(code, " ") && strings.HasSuffix(code, " ")) {
		pad = " "
	}
	return fence + pad + code + pad + fence
}

func longestRun(s string, c byte) int {
	best, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] != c {
			run = 0
			continue
		}
		run++
		best = max(best, run)
	}
	return best
}

// prefixLines prefixes the first line of s with first and the others with
// rest; blank lines get rest without trailing spaces.
func prefixLines(s, first, rest string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		p := rest
		if i == 0 {
			p = first
		}
		if l == "" {
			lines[i] = strings.TrimRight(p, " ")
			continue
		}
		lines[i] = p + l
	}
	return strings.Join(lines, "\n")
}

// cmdMarkdown runs /markdown on|off.
func (m *Model) cmdMarkdown(args []string) tea.Cmd {
	if len(args) == 0 {
		m.log(entrySystem, "Markdown is "+onOff(m.st.markdown)+". usage: /markdown on|off")
		return nil
	}
	on, ok := parseOnOff(resolveSub("/markdown", args[0], len(args) == 1, m.paletteSel))
	if !ok {
		m.log(entryError, "usage: /markdown on|off")
		return nil
	}
	m.setMarkdown(on)
	if on {
		m.log(entryGood, "Markdown on: emphasis, code, lists and quotes in messages are formatted. Links show their address and are not clickable.")
	} else {
		m.log(entryGood, "Markdown off: messages are shown exactly as typed.")
	}
	return m.saveSetting(SettingMarkdown, onOff(on))
}

// setMarkdown turns Markdown rendering of message bodies on or off.
func (m *Model) setMarkdown(on bool) {
	if m.st.markdown == on {
		return
	}
	m.st.markdown = on
	m.input.st = m.st
	m.refreshHistory()
}

// parseOnOff parses "on" or "off", ignoring case.
func parseOnOff(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on":
		return true, true
	case "off":
		return false, true
	}
	return false, false
}
