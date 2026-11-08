package tui

import (
	"hash/fnv"
	"image/color"
	"math"
	"strings"
	"time"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// AnimInterval is the frame interval of every animation, about 12 frames
// per second.
const AnimInterval = 80 * time.Millisecond

// pulseFrames is the length of one pulse brightness cycle, about 1.2 s.
const pulseFrames = 15

// animTickMsg advances the animations by one frame.
type animTickMsg struct{ at time.Time }

// animTick schedules the next animation frame. Only request it while
// something animates, so an idle interface costs no CPU.
func animTick() tea.Cmd {
	return tea.Tick(AnimInterval, func(t time.Time) tea.Msg { return animTickMsg{at: t} })
}

// parseAnimations interprets the stored ui.animations setting. Animations
// are on unless the value is a recognised "off".
func parseAnimations(s string) bool {
	on, ok := parseOnOff(s)
	return on || !ok
}

// spinnerGlyphs are the frames of the braille spinner.
var spinnerGlyphs = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinnerFrame returns the spinner glyph of a frame; any frame number,
// negative ones included, is valid.
func spinnerFrame(frame int) string {
	return spinnerGlyphs[mod(frame, len(spinnerGlyphs))]
}

func mod(a, n int) int {
	return ((a % n) + n) % n
}

// rgb8 returns the 8-bit channels of c; nil is black.
func rgb8(c color.Color) (r, g, b float64) {
	if c == nil {
		return 0, 0, 0
	}
	r16, g16, b16, _ := c.RGBA()
	return float64(r16 >> 8), float64(g16 >> 8), float64(b16 >> 8)
}

// blend linearly interpolates between a and b in RGB space: t = 0 gives a,
// t = 1 gives b. t is clamped to [0, 1]. A nil color yields the other one.
func blend(a, b color.Color, t float64) color.Color {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	t = math.Max(0, math.Min(1, t))
	ar, ag, ab := rgb8(a)
	br, bg, bb := rgb8(b)
	mix := func(x, y float64) uint8 { return uint8(math.Round(x + (y-x)*t)) }
	return color.RGBA{R: mix(ar, br), G: mix(ag, bg), B: mix(ab, bb), A: 0xff}
}

// fade returns the color step of steps on the way from from to to: step 0
// is from, step steps (or later) is to.
func fade(from, to color.Color, step, steps int) color.Color {
	if steps <= 0 {
		return blend(from, to, 1)
	}
	return blend(from, to, float64(step)/float64(steps))
}

// pulse cycles base between full brightness and a dimmed version blended
// towards the theme background, once every pulseFrames frames. Frame 0 is
// full brightness.
func pulse(th Theme, base color.Color, frame int) color.Color {
	bg := th.Background
	if bg == nil {
		bg = color.Black
	}
	phase := float64(mod(frame, pulseFrames)) / pulseFrames
	depth := (1 - math.Cos(2*math.Pi*phase)) / 2
	return blend(base, bg, 0.55*depth)
}

// gradientAt returns the color at position t in [0, 1] along stops.
func gradientAt(stops []color.Color, t float64) color.Color {
	switch len(stops) {
	case 0:
		return nil
	case 1:
		return stops[0]
	}
	pos := math.Max(0, math.Min(1, t)) * float64(len(stops)-1)
	i := min(int(pos), len(stops)-2)
	return blend(stops[i], stops[i+1], pos-float64(i))
}

// clusters splits plain text into display clusters: a rune together with
// the zero-width runes that follow it, and runs joined by U+200D. Control
// runes are dropped, so the result never carries terminal escapes.
func clusters(s string) []string {
	var out []string
	join := false
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			continue
		}
		zero := r == '‍' || lipgloss.Width(string(r)) == 0
		if len(out) > 0 && (zero || join) {
			out[len(out)-1] += string(r)
		} else {
			out = append(out, string(r))
		}
		join = r == '‍'
	}
	return out
}

// gradientText colors plain text with a horizontal gradient across stops,
// one color per character. Its width equals the input's width; wide runes
// keep their two cells. Without stops the text is returned unstyled.
func gradientText(s string, stops []color.Color) string {
	parts := clusters(s)
	if len(stops) == 0 || len(parts) == 0 {
		return strings.Join(parts, "")
	}
	var b strings.Builder
	last := max(len(parts)-1, 1)
	for i, p := range parts {
		if strings.TrimSpace(p) == "" {
			b.WriteString(p)
			continue
		}
		c := gradientAt(stops, float64(i)/float64(last))
		b.WriteString(lipgloss.NewStyle().Foreground(c).Render(p))
	}
	return b.String()
}

// gradientRule draws a horizontal rule of glyph, width cells wide, colored
// with a gradient across stops. An empty or zero-width glyph means "─"; a
// wide glyph that does not divide width is padded with spaces.
func gradientRule(width int, glyph string, stops []color.Color) string {
	if width <= 0 {
		return ""
	}
	gw := lipgloss.Width(glyph)
	if gw == 0 {
		glyph, gw = "─", 1
	}
	if gw > width {
		return strings.Repeat(" ", width)
	}
	n := width / gw
	return gradientText(strings.Repeat(glyph, n), stops) + strings.Repeat(" ", width-n*gw)
}

// avatarColor returns the stable avatar color of a contact or group member
// id: the same id always gets the same color of the theme's palette.
func avatarColor(th Theme, id string) color.Color {
	palette := th.AvatarPalette
	if len(palette) == 0 {
		palette = DefaultTheme().AvatarPalette
	}
	h := fnv.New32a()
	h.Write([]byte(id))
	return palette[h.Sum32()%uint32(len(palette))]
}

// avatarInitial returns the uppercase first letter or digit of name, or of
// id when name has none, or "?". Only single-cell characters qualify, so
// the badge always has width 3.
func avatarInitial(id, name string) string {
	for _, s := range []string{name, id} {
		for _, r := range s {
			if (unicode.IsLetter(r) || unicode.IsDigit(r)) && lipgloss.Width(string(r)) == 1 {
				up := unicode.ToUpper(r)
				if lipgloss.Width(string(up)) == 1 {
					return string(up)
				}
				return string(r)
			}
		}
	}
	return "?"
}

// avatar draws the "(B)" badge of a contact: its initial between
// parentheses in its avatar color, always 3 cells wide.
func avatar(th Theme, id, name string) string {
	return lipgloss.NewStyle().Foreground(avatarColor(th, id)).Bold(true).Render("(" + avatarInitial(id, name) + ")")
}
