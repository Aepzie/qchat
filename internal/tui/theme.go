package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// Theme is a named color palette. Every color the interface draws comes
// from a Theme field, so adding a theme means adding one constructor.
//
// The terminal's own background is left untouched; themes are designed for
// dark backgrounds.
type Theme struct {
	// Name identifies the theme.
	Name string

	// Text is the primary foreground color.
	Text color.Color
	// Muted is for secondary text such as timestamps and labels.
	Muted color.Color
	// Faint is for hints, placeholders and de-emphasised details.
	Faint color.Color
	// Border is for pane borders and separators.
	Border color.Color
	// Surface is the background of the status bar and footer.
	Surface color.Color
	// Highlight is the background of selected rows and badges.
	Highlight color.Color

	// Accent is the single accent color: brand, prompt, insert mode.
	Accent color.Color
	// OnAccent is text drawn on an Accent background.
	OnAccent color.Color

	// Success marks a healthy connection.
	Success color.Color
	// Warning marks transient trouble, such as reconnecting.
	Warning color.Color
	// Danger marks failures and security alerts.
	Danger color.Color

	// CodeLight and CodeDark are the light and dark modules of QR codes.
	// They default to white and black for the best scanning contrast.
	CodeLight color.Color
	CodeDark  color.Color
}

// DefaultTheme returns "dusk", a low-contrast dark theme with a soft blue
// accent.
func DefaultTheme() Theme {
	return Theme{
		Name:      "dusk",
		Text:      lipgloss.Color("#DADDE4"),
		Muted:     lipgloss.Color("#8C93A1"),
		Faint:     lipgloss.Color("#5B6170"),
		Border:    lipgloss.Color("#323743"),
		Surface:   lipgloss.Color("#1A1D24"),
		Highlight: lipgloss.Color("#262A35"),
		Accent:    lipgloss.Color("#8AADF4"),
		OnAccent:  lipgloss.Color("#141821"),
		Success:   lipgloss.Color("#A6D189"),
		Warning:   lipgloss.Color("#E5C890"),
		Danger:    lipgloss.Color("#E78284"),
		CodeLight: lipgloss.Color("#FFFFFF"),
		CodeDark:  lipgloss.Color("#000000"),
	}
}

// complete fills unset colors from DefaultTheme, so a partially specified
// theme still renders.
func (t Theme) complete() Theme {
	d := DefaultTheme()
	fill := func(c *color.Color, fallback color.Color) {
		if *c == nil {
			*c = fallback
		}
	}
	if t.Name == "" {
		t.Name = d.Name
	}
	fill(&t.Text, d.Text)
	fill(&t.Muted, d.Muted)
	fill(&t.Faint, d.Faint)
	fill(&t.Border, d.Border)
	fill(&t.Surface, d.Surface)
	fill(&t.Highlight, d.Highlight)
	fill(&t.Accent, d.Accent)
	fill(&t.OnAccent, d.OnAccent)
	fill(&t.Success, d.Success)
	fill(&t.Warning, d.Warning)
	fill(&t.Danger, d.Danger)
	fill(&t.CodeLight, d.CodeLight)
	fill(&t.CodeDark, d.CodeDark)
	return t
}

// styles holds the lipgloss styles derived from a Theme.
type styles struct {
	theme Theme

	text   lipgloss.Style
	muted  lipgloss.Style
	faint  lipgloss.Style
	accent lipgloss.Style
	ok     lipgloss.Style
	warn   lipgloss.Style
	danger lipgloss.Style
	bold   lipgloss.Style
	border lipgloss.Style

	bar        lipgloss.Style
	barBrand   lipgloss.Style
	barMuted   lipgloss.Style
	barFaint   lipgloss.Style
	barBadge   lipgloss.Style
	pillInsert lipgloss.Style
	pillNormal lipgloss.Style

	sidebarTitle lipgloss.Style
	rowSelected  lipgloss.Style
	rowMarker    lipgloss.Style
	unread       lipgloss.Style

	alertBox   lipgloss.Style
	alertTitle lipgloss.Style
	palette    lipgloss.Style
	paletteSel lipgloss.Style

	overlayBox lipgloss.Style
	qr         lipgloss.Style
	card       lipgloss.Style
}

func newStyles(t Theme) styles {
	t = t.complete()
	base := lipgloss.NewStyle()
	bar := base.Background(t.Surface).Foreground(t.Text)
	return styles{
		theme:  t,
		text:   base.Foreground(t.Text),
		muted:  base.Foreground(t.Muted),
		faint:  base.Foreground(t.Faint),
		accent: base.Foreground(t.Accent),
		ok:     base.Foreground(t.Success),
		warn:   base.Foreground(t.Warning),
		danger: base.Foreground(t.Danger),
		bold:   base.Foreground(t.Text).Bold(true),
		border: base.Foreground(t.Border),

		bar:        bar,
		barBrand:   bar.Foreground(t.Accent).Bold(true),
		barMuted:   bar.Foreground(t.Muted),
		barFaint:   bar.Foreground(t.Faint),
		barBadge:   base.Background(t.Highlight).Foreground(t.Warning),
		pillInsert: base.Background(t.Accent).Foreground(t.OnAccent).Bold(true),
		pillNormal: base.Background(t.Highlight).Foreground(t.Accent).Bold(true),

		sidebarTitle: base.Foreground(t.Faint).Bold(true),
		rowSelected:  base.Background(t.Highlight).Foreground(t.Text).Bold(true),
		rowMarker:    base.Background(t.Highlight).Foreground(t.Accent),
		unread:       base.Background(t.Highlight).Foreground(t.Accent).Bold(true),

		alertBox: base.
			Border(lipgloss.RoundedBorder()).
			BorderForeground(t.Danger).
			Padding(0, 1),
		alertTitle: base.Foreground(t.Danger).Bold(true),
		palette:    base.Foreground(t.Muted),
		paletteSel: base.Background(t.Highlight).Foreground(t.Text),

		overlayBox: base.
			Border(lipgloss.RoundedBorder()).
			BorderForeground(t.Accent).
			Padding(0, 1),
		qr: base.Foreground(t.CodeLight).Background(t.CodeDark),
		card: base.
			Border(lipgloss.RoundedBorder()).
			BorderForeground(t.Border).
			Padding(1, 2),
	}
}
