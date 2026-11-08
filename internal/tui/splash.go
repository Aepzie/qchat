package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

// SplashFrames is the number of animation frames of the splash reveal; at
// AnimInterval per frame it lasts 1.2 s.
const SplashFrames = 15

// splashTagline is shown under the logo.
const splashTagline = "post-quantum · end-to-end · sealed"

// bigLogoGlyphs are the letters of the large logo, six rows each.
var bigLogoGlyphs = [][]string{
	{" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║▄▄ ██║", "╚██████╔╝", " ╚══▀▀═╝ "},
	{" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"},
	{"██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"},
	{" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"},
	{"████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "},
}

// smallLogo is the compact logo for narrow or short terminals.
var smallLogo = []string{
	"┏━┓┏━╸╻ ╻┏━┓╺┳╸",
	"┃┓┃┃  ┣━┫┣━┫ ┃ ",
	"┗┻┛┗━╸╹ ╹╹ ╹ ╹ ",
}

// bigLogo joins bigLogoGlyphs into rows of equal width.
func bigLogo() []string {
	rows := make([]string, len(bigLogoGlyphs[0]))
	for i := range rows {
		var b strings.Builder
		for _, g := range bigLogoGlyphs {
			b.WriteString(g[i])
		}
		rows[i] = b.String()
	}
	return rows
}

// splashLogo picks the largest logo that fits width×height together with
// the tagline, falling back to the plain word.
func splashLogo(width, height int) []string {
	for _, logo := range [][]string{bigLogo(), smallLogo} {
		if lipgloss.Width(logo[0]) <= width && len(logo)+2 <= height {
			return logo
		}
	}
	return []string{"qchat"}
}

// splashView draws the start screen at frame: the gradient logo revealed
// top to bottom by a bright scan line over SplashFrames frames, then the
// tagline fading in. Frames at or past SplashFrames show the final screen.
// The result fills width×height cells and no line is wider than width.
func splashView(width, height, frame int, th Theme) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	th = th.complete()
	logo := splashLogo(width, height)
	frame = max(0, min(frame, SplashFrames))
	logoW := lipgloss.Width(logo[0])

	reveal := SplashFrames - 4
	shown := len(logo) * min(frame, reveal) / reveal
	scan := lipgloss.NewStyle().Foreground(blend(th.Glow, splashWhite, 0.35)).Bold(true)

	var lines []string
	for i, row := range logo {
		row = truncate(row, width)
		switch {
		case i < shown:
			lines = append(lines, gradientText(row, th.Gradient))
		case i == shown && frame < SplashFrames:
			lines = append(lines, scan.Render(scanLine(row)))
		default:
			lines = append(lines, strings.Repeat(" ", lipgloss.Width(row)))
		}
	}

	if len(logo)+2 <= height {
		ruleW := min(logoW, width)
		rule := strings.Repeat(" ", ruleW)
		if frame >= reveal {
			rule = gradientRule(ruleW, "━", th.Gradient)
		}
		tag := truncate(splashTagline, width)
		tagColor := fade(splashGround(th), th.Muted, frame-reveal, SplashFrames-reveal)
		if frame < reveal {
			tag = strings.Repeat(" ", lipgloss.Width(tag))
		}
		lines = append(lines, rule, lipgloss.NewStyle().Foreground(tagColor).Render(tag))
	}

	block := lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, strings.Join(lines, "\n"))
	return clamp(block, width, height)
}

// splashWhite is pure white, the hot core of the scan line.
var splashWhite = lipgloss.Color("#FFFFFF")

// scanLine turns the visible cells of a logo row into the glyph of the
// scan line, keeping its width.
func scanLine(row string) string {
	var b strings.Builder
	for _, r := range row {
		if r == ' ' {
			b.WriteRune(' ')
			continue
		}
		b.WriteString(strings.Repeat("▀", lipgloss.Width(string(r))))
	}
	return b.String()
}

// splashGround is the background the tagline fades in from.
func splashGround(th Theme) color.Color {
	if th.Background == nil {
		return color.Black
	}
	return th.Background
}
