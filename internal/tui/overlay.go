package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"rsc.io/qr"
)

// overlayKind selects the full-pane overlay, if any.
type overlayKind uint8

const (
	overlayNone overlayKind = iota
	overlayVerify
	overlayWhoami
)

// safetyDigits is the length of a safety number.
const safetyDigits = 60

// overlay is the state of the /verify or /whoami screen. All text is
// sanitised when the overlay opens.
type overlay struct {
	kind       overlayKind
	contactID  string
	name       string
	shortID    string
	fullID     string
	digits     string
	verified   bool
	keyChanged bool
	code       *qr.Code
	busy       bool
	errText    string
}

// confirmation is a pending y/N question shown in place of the input.
type confirmation struct {
	active    bool
	contactID string
	name      string
}

// openVerify shows the safety number of a contact. It reports false if the
// number is malformed.
func (m *Model) openVerify(c *conversation, info VerificationInfo) bool {
	var digits strings.Builder
	for _, r := range info.SafetyNumber {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r == ' ':
		default:
			return false
		}
	}
	if digits.Len() != safetyDigits {
		return false
	}
	m.overlay = overlay{
		kind:       overlayVerify,
		contactID:  c.contact.ID,
		name:       c.contact.label(),
		shortID:    c.contact.ShortID,
		digits:     digits.String(),
		verified:   info.Verified,
		keyChanged: info.KeyChanged || c.contact.KeyChanged,
		code:       encodeQR(info.QRPayload, qr.L),
	}
	return true
}

// openWhoami shows the user's own ID.
func (m *Model) openWhoami() {
	m.overlay = overlay{
		kind:   overlayWhoami,
		name:   m.self.DisplayName,
		fullID: m.self.ID,
		code:   encodeQR(m.self.ID, qr.M),
	}
}

func (m *Model) handleOverlayKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "q":
		m.overlay = overlay{}
		return nil
	}
	b := m.cfg.Backend
	if m.overlay.kind != overlayVerify || m.overlay.busy || b == nil {
		return nil
	}
	switch msg.String() {
	case "v":
		m.overlay.busy = true
		return markVerifiedCmd(b, m.overlay.contactID, true)
	case "u":
		m.overlay.busy = true
		return markVerifiedCmd(b, m.overlay.contactID, false)
	}
	return nil
}

func (m *Model) handleConfirmKey(msg tea.KeyPressMsg) tea.Cmd {
	c := m.confirm
	m.confirm = confirmation{}
	if (msg.String() == "y" || msg.String() == "Y") && m.cfg.Backend != nil {
		return removeCmd(m.cfg.Backend, c.contactID, c.name)
	}
	m.log(entrySystem, "Kept "+c.name+".")
	return nil
}

// groupDigits splits a safety number into rows of perRow 5-digit groups.
func groupDigits(digits string, perRow int) []string {
	var groups []string
	for i := 0; i+5 <= len(digits); i += 5 {
		groups = append(groups, digits[i:i+5])
	}
	var rows []string
	for i := 0; i < len(groups); i += perRow {
		rows = append(rows, strings.Join(groups[i:min(i+perRow, len(groups))], " "))
	}
	return rows
}

// overlayText is the text column of an overlay at the given width.
func (m Model) overlayText(width int) []string {
	st := m.st
	o := m.overlay
	var lines []string
	add := func(style lipgloss.Style, text string) {
		for _, l := range wrapLines(text, width) {
			lines = append(lines, style.Render(l))
		}
	}
	if o.kind == overlayWhoami {
		lines = append(lines, st.muted.Render("Your ID"))
		add(st.text, groupID(o.fullID))
		lines = append(lines, "")
		add(st.faint, "Others need this ID to /add you. It is public and reveals nothing secret; share it with the people you want to hear from.")
		lines = append(lines, "")
		add(st.muted, "esc close")
		return lines
	}
	lines = append(lines, st.muted.Render("Safety number"))
	perRow := 4
	for _, n := range []int{4, 3, 2, 1} {
		perRow = n
		if n*6-1 <= width {
			break
		}
	}
	for _, r := range groupDigits(o.digits, perRow) {
		lines = append(lines, st.bold.Render(truncate(r, width)))
	}
	lines = append(lines, "")
	add(st.faint, "Compare these digits with "+o.name+" in person or over a call you trust, or scan each other's code. If every digit matches, press v.")
	lines = append(lines, "")
	switch {
	case o.keyChanged:
		add(st.danger.Bold(true), "⚠ safety number changed · compare again")
	case o.verified:
		add(st.ok, "✓ verified")
	default:
		add(st.warn, "not verified")
	}
	if o.errText != "" {
		add(st.danger, o.errText)
	}
	keys := "v verified · u not verified · esc close"
	if o.busy {
		keys = "saving…"
	}
	add(st.muted, keys)
	return lines
}

// renderOverlay draws the overlay as exactly height lines of width cells.
func (m Model) renderOverlay(width, height int) []string {
	st := m.st
	o := m.overlay
	boxW := min(width, 104)
	innerW, innerH := boxW-4, height-2

	title := st.bold.Render("Your qchat ID")
	if o.name != "" && o.kind == overlayWhoami {
		title += st.muted.Render(" · " + o.name)
	}
	if o.kind == overlayVerify {
		title = st.bold.Render("Verify "+o.name) + st.faint.Render("  "+o.shortID)
	}
	header := []string{truncateStyled(title, innerW), ""}
	content := m.overlayLayout(header, innerW, innerH)

	if len(content) > innerH {
		content = content[:innerH]
	}
	for len(content) < innerH {
		content = append(content, "")
	}
	for i, l := range content {
		content[i] = padRight(l, innerW, lipgloss.NewStyle())
	}
	box := st.overlayBox
	if o.keyChanged {
		box = box.BorderForeground(st.theme.Danger)
	}
	lines := strings.Split(box.Render(strings.Join(content, "\n")), "\n")
	left := strings.Repeat(" ", (width-boxW)/2)
	out := make([]string, height)
	for i := range out {
		if i < len(lines) {
			out[i] = padRight(left+lines[i], width, lipgloss.NewStyle())
			continue
		}
		out[i] = strings.Repeat(" ", width)
	}
	return out
}

// overlayLayout places the QR code beside or below the text when it fits,
// trying a smaller quiet zone before giving up on the code.
func (m Model) overlayLayout(header []string, innerW, innerH int) []string {
	const gap = 3
	const minText = 23
	code := m.overlay.code
	if code != nil {
		for _, quiet := range []int{4, 2} {
			qw, qh := qrSize(code, quiet)
			if textW := innerW - qw - gap; textW >= minText {
				text := m.overlayText(textW)
				if len(header)+max(qh, len(text)) <= innerH {
					return append(header, m.besideQR(qrLines(code, quiet), text, qw+gap)...)
				}
			}
			text := m.overlayText(innerW)
			if qw <= innerW && len(header)+len(text)+1+qh <= innerH {
				out := append(append(header, text...), "")
				pad := strings.Repeat(" ", (innerW-qw)/2)
				for _, l := range qrLines(code, quiet) {
					out = append(out, pad+m.st.qr.Render(l))
				}
				return out
			}
		}
	}
	text := m.overlayText(innerW)
	out := append(header, text...)
	if code != nil {
		out = append(out, "")
		for _, l := range wrapLines("The terminal is too small for the QR code; compare the digits instead, or enlarge the window.", innerW) {
			out = append(out, m.st.faint.Italic(true).Render(l))
		}
	}
	return out
}

func (m Model) besideQR(code, text []string, codeW int) []string {
	n := max(len(code), len(text))
	out := make([]string, n)
	for i := range out {
		left := strings.Repeat(" ", codeW)
		if i < len(code) {
			left = m.st.qr.Render(code[i]) + strings.Repeat(" ", codeW-lipgloss.Width(code[i]))
		}
		right := ""
		if i < len(text) {
			right = text[i]
		}
		out[i] = left + right
	}
	return out
}

// truncateStyled cuts styled text to width cells.
func truncateStyled(s string, width int) string {
	if lipgloss.Width(s) <= width {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(width).Render(s)
}
