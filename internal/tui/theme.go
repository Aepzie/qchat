package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

// Theme is a named color palette. Every color the interface draws comes
// from a Theme field, so adding a theme means adding one constructor.
//
// A theme with a nil Background leaves the terminal's own background
// untouched and is designed for dark backgrounds. A theme with a Background
// asks the terminal to use that color while qchat runs; the terminal gets
// its own color back on exit.
type Theme struct {
	// Name identifies the theme. It is what /theme takes and what the
	// ui.theme setting stores.
	Name string
	// Description is a short summary shown by the /theme palette.
	Description string

	// Background, when set, replaces the terminal background.
	Background color.Color

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
	// They default to white and black for the best scanning contrast. Every
	// theme keeps dark modules on a light ground, which is what scanners
	// expect, the light theme included.
	CodeLight color.Color
	CodeDark  color.Color
}

// DefaultTheme returns "dusk", a low-contrast dark theme with a soft blue
// accent.
func DefaultTheme() Theme {
	return Theme{
		Name:        "dusk",
		Description: "soft blue on the terminal's own dark background",
		Text:        lipgloss.Color("#DADDE4"),
		Muted:       lipgloss.Color("#8C93A1"),
		Faint:       lipgloss.Color("#5B6170"),
		Border:      lipgloss.Color("#323743"),
		Surface:     lipgloss.Color("#1A1D24"),
		Highlight:   lipgloss.Color("#262A35"),
		Accent:      lipgloss.Color("#8AADF4"),
		OnAccent:    lipgloss.Color("#141821"),
		Success:     lipgloss.Color("#A6D189"),
		Warning:     lipgloss.Color("#E5C890"),
		Danger:      lipgloss.Color("#E78284"),
		CodeLight:   lipgloss.Color("#FFFFFF"),
		CodeDark:    lipgloss.Color("#000000"),
	}
}

// fjordTheme is a cool, frosty dark theme in the spirit of Nord.
func fjordTheme() Theme {
	return Theme{
		Name:        "fjord",
		Description: "frost blue on polar night",
		Background:  lipgloss.Color("#2E3440"),
		Text:        lipgloss.Color("#E5E9F0"),
		Muted:       lipgloss.Color("#A7B1C2"),
		Faint:       lipgloss.Color("#7A859A"),
		Border:      lipgloss.Color("#4C566A"),
		Surface:     lipgloss.Color("#3B4252"),
		Highlight:   lipgloss.Color("#434C5E"),
		Accent:      lipgloss.Color("#88C0D0"),
		OnAccent:    lipgloss.Color("#2E3440"),
		Success:     lipgloss.Color("#A3BE8C"),
		Warning:     lipgloss.Color("#EBCB8B"),
		Danger:      lipgloss.Color("#E08A92"),
		CodeLight:   lipgloss.Color("#ECEFF4"),
		CodeDark:    lipgloss.Color("#2E3440"),
	}
}

// emberTheme is a warm dark theme on the Solarized dark palette.
func emberTheme() Theme {
	return Theme{
		Name:        "ember",
		Description: "solarized dark with an orange glow",
		Background:  lipgloss.Color("#002B36"),
		Text:        lipgloss.Color("#A3B1B1"),
		Muted:       lipgloss.Color("#8A9B9D"),
		Faint:       lipgloss.Color("#647D84"),
		Border:      lipgloss.Color("#174652"),
		Surface:     lipgloss.Color("#073642"),
		Highlight:   lipgloss.Color("#0D4351"),
		Accent:      lipgloss.Color("#E07A3A"),
		OnAccent:    lipgloss.Color("#002B36"),
		Success:     lipgloss.Color("#9AAE1A"),
		Warning:     lipgloss.Color("#C9A227"),
		Danger:      lipgloss.Color("#F06A60"),
		CodeLight:   lipgloss.Color("#FDF6E3"),
		CodeDark:    lipgloss.Color("#002B36"),
	}
}

// contrastTheme maximises legibility: white text on black and saturated
// signal colors.
func contrastTheme() Theme {
	return Theme{
		Name:        "contrast",
		Description: "high contrast, white on black",
		Background:  lipgloss.Color("#000000"),
		Text:        lipgloss.Color("#FFFFFF"),
		Muted:       lipgloss.Color("#DADADA"),
		Faint:       lipgloss.Color("#B2B2B2"),
		Border:      lipgloss.Color("#9E9E9E"),
		Surface:     lipgloss.Color("#1C1C1C"),
		Highlight:   lipgloss.Color("#3A3A3A"),
		Accent:      lipgloss.Color("#FFD700"),
		OnAccent:    lipgloss.Color("#000000"),
		Success:     lipgloss.Color("#5FFF87"),
		Warning:     lipgloss.Color("#FFAF5F"),
		Danger:      lipgloss.Color("#FF7A7A"),
		CodeLight:   lipgloss.Color("#FFFFFF"),
		CodeDark:    lipgloss.Color("#000000"),
	}
}

// paperTheme is a light theme: ink on warm paper.
func paperTheme() Theme {
	return Theme{
		Name:        "paper",
		Description: "light, ink on warm paper",
		Background:  lipgloss.Color("#FAF8F2"),
		Text:        lipgloss.Color("#26251F"),
		Muted:       lipgloss.Color("#57544A"),
		Faint:       lipgloss.Color("#77736A"),
		Border:      lipgloss.Color("#CFCABA"),
		Surface:     lipgloss.Color("#ECE8DC"),
		Highlight:   lipgloss.Color("#E0DACA"),
		Accent:      lipgloss.Color("#245A8F"),
		OnAccent:    lipgloss.Color("#FFFFFF"),
		Success:     lipgloss.Color("#2F6B2F"),
		Warning:     lipgloss.Color("#805A00"),
		Danger:      lipgloss.Color("#A8231B"),
		CodeLight:   lipgloss.Color("#FFFFFF"),
		CodeDark:    lipgloss.Color("#000000"),
	}
}

// Themes returns every built-in theme, the default first.
func Themes() []Theme {
	return []Theme{DefaultTheme(), fjordTheme(), emberTheme(), contrastTheme(), paperTheme()}
}

// ThemeByName returns the built-in theme with the given name, ignoring case
// and surrounding spaces.
func ThemeByName(name string) (Theme, bool) {
	name = strings.TrimSpace(name)
	for _, t := range Themes() {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return Theme{}, false
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
