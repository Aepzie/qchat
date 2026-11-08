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

	// Gradient holds three to five color stops for horizontal gradients:
	// the logo, the tab bar underline and the header title.
	Gradient []color.Color
	// Glow is the bright halo color of focused and animated elements.
	Glow color.Color
	// PanelBorder is the dim border of unfocused panels.
	PanelBorder color.Color
	// PanelBorderFocus is the glowing border of the focused panel and of
	// the focused input.
	PanelBorderFocus color.Color
	// BubbleOwn is the fill of the user's own message bubbles and
	// BubbleOwnText the text drawn on it.
	BubbleOwn     color.Color
	BubbleOwnText color.Color
	// BubblePeer is the fill of peer message bubbles and BubblePeerText the
	// text drawn on it.
	BubblePeer     color.Color
	BubblePeerText color.Color
	// AvatarPalette holds at least eight distinct colors for contact
	// avatars and group sender names, all readable on the background.
	AvatarPalette []color.Color
}

// colors converts hex strings to colors.
func colors(hexes ...string) []color.Color {
	out := make([]color.Color, len(hexes))
	for i, h := range hexes {
		out[i] = lipgloss.Color(h)
	}
	return out
}

// DefaultTheme returns "phosphor": amber on warm black, in the style of an
// old CRT terminal. Accents are shades of the same amber rather than a
// multicolour gradient; only warnings and errors leave the palette.
func DefaultTheme() Theme {
	return phosphorTheme()
}

// phosphorTheme is the default theme: amber phosphor on warm black.
func phosphorTheme() Theme {
	return Theme{
		Name:             "phosphor",
		Description:      "amber phosphor on warm black",
		Background:       lipgloss.Color("#0B0906"),
		Text:             lipgloss.Color("#FFC24D"),
		Muted:            lipgloss.Color("#C98A1A"),
		Faint:            lipgloss.Color("#8A5E12"),
		Border:           lipgloss.Color("#3A2A0E"),
		Surface:          lipgloss.Color("#14100A"),
		Highlight:        lipgloss.Color("#2A1E08"),
		Accent:           lipgloss.Color("#FFB000"),
		OnAccent:         lipgloss.Color("#0B0906"),
		Success:          lipgloss.Color("#FFE08A"),
		Warning:          lipgloss.Color("#FF8A00"),
		Danger:           lipgloss.Color("#FF3B2F"),
		CodeLight:        lipgloss.Color("#FFFFFF"),
		CodeDark:         lipgloss.Color("#000000"),
		Gradient:         colors("#8A5E12", "#FFB000", "#FFD27A"),
		Glow:             lipgloss.Color("#FFD27A"),
		PanelBorder:      lipgloss.Color("#4A3510"),
		PanelBorderFocus: lipgloss.Color("#FFB000"),
		BubbleOwn:        lipgloss.Color("#3D2A00"),
		BubbleOwnText:    lipgloss.Color("#FFD58A"),
		BubblePeer:       lipgloss.Color("#1C160C"),
		BubblePeerText:   lipgloss.Color("#F2E3C6"),
		AvatarPalette: colors("#FFB000", "#FFD27A", "#E07B00", "#C9A227", "#FF8A5C",
			"#E6C68A", "#D4882B", "#FFE9B0", "#B8862B", "#F2A65A"),
	}
}

// neonTheme uses electric magenta, violet and cyan on a near-black ground.
func neonTheme() Theme {
	return Theme{
		Name:             "neon",
		Description:      "electric magenta and cyan on near black",
		Background:       lipgloss.Color("#0A0A12"),
		Text:             lipgloss.Color("#ECEAF7"),
		Muted:            lipgloss.Color("#A29EC2"),
		Faint:            lipgloss.Color("#6F6A92"),
		Border:           lipgloss.Color("#2C2645"),
		Surface:          lipgloss.Color("#13111F"),
		Highlight:        lipgloss.Color("#241D3D"),
		Accent:           lipgloss.Color("#FF2BD6"),
		OnAccent:         lipgloss.Color("#0A0A12"),
		Success:          lipgloss.Color("#B6FF3B"),
		Warning:          lipgloss.Color("#FFB020"),
		Danger:           lipgloss.Color("#FF3355"),
		CodeLight:        lipgloss.Color("#FFFFFF"),
		CodeDark:         lipgloss.Color("#000000"),
		Gradient:         colors("#FF2BD6", "#8A5CFF", "#00E5FF"),
		Glow:             lipgloss.Color("#00E5FF"),
		PanelBorder:      lipgloss.Color("#3A3358"),
		PanelBorderFocus: lipgloss.Color("#FF2BD6"),
		BubbleOwn:        lipgloss.Color("#5C1A6E"),
		BubbleOwnText:    lipgloss.Color("#FFFFFF"),
		BubblePeer:       lipgloss.Color("#10303D"),
		BubblePeerText:   lipgloss.Color("#E6FBFF"),
		AvatarPalette: colors("#FF2BD6", "#00E5FF", "#8A5CFF", "#B6FF3B", "#FFB020",
			"#FF5C8A", "#3DFFC5", "#5CA8FF", "#FFE45C", "#C77DFF"),
	}
}

// synthwaveTheme is an orange and pink sunset on deep purple.
func synthwaveTheme() Theme {
	return Theme{
		Name:             "synthwave",
		Description:      "orange and pink sunset on deep purple",
		Background:       lipgloss.Color("#1A1033"),
		Text:             lipgloss.Color("#F6ECFF"),
		Muted:            lipgloss.Color("#BBA6D8"),
		Faint:            lipgloss.Color("#8E79B0"),
		Border:           lipgloss.Color("#3D2A66"),
		Surface:          lipgloss.Color("#22153F"),
		Highlight:        lipgloss.Color("#33205C"),
		Accent:           lipgloss.Color("#FF8C42"),
		OnAccent:         lipgloss.Color("#1A1033"),
		Success:          lipgloss.Color("#72F1B8"),
		Warning:          lipgloss.Color("#FEDE5D"),
		Danger:           lipgloss.Color("#FF5566"),
		CodeLight:        lipgloss.Color("#FFFFFF"),
		CodeDark:         lipgloss.Color("#000000"),
		Gradient:         colors("#FEDE5D", "#FF8C42", "#FF4FA0", "#B65CFF"),
		Glow:             lipgloss.Color("#FF4FA0"),
		PanelBorder:      lipgloss.Color("#4A3378"),
		PanelBorderFocus: lipgloss.Color("#FF8C42"),
		BubbleOwn:        lipgloss.Color("#7A2E5C"),
		BubbleOwnText:    lipgloss.Color("#FFF4FA"),
		BubblePeer:       lipgloss.Color("#2E1F5A"),
		BubblePeerText:   lipgloss.Color("#F6ECFF"),
		AvatarPalette: colors("#FF8C42", "#FF4FA0", "#FEDE5D", "#72F1B8", "#36F9F6",
			"#C792EA", "#FF7EDB", "#F97E72", "#9DDCFF", "#E5FF7A"),
	}
}

// matrixTheme is green phosphor on black.
func matrixTheme() Theme {
	return Theme{
		Name:             "matrix",
		Description:      "green phosphor on black",
		Background:       lipgloss.Color("#020A04"),
		Text:             lipgloss.Color("#B8FFC4"),
		Muted:            lipgloss.Color("#5FCF78"),
		Faint:            lipgloss.Color("#34924B"),
		Border:           lipgloss.Color("#123D1D"),
		Surface:          lipgloss.Color("#06170B"),
		Highlight:        lipgloss.Color("#0D2C15"),
		Accent:           lipgloss.Color("#00FF41"),
		OnAccent:         lipgloss.Color("#001A08"),
		Success:          lipgloss.Color("#7CFF7C"),
		Warning:          lipgloss.Color("#E6FF4D"),
		Danger:           lipgloss.Color("#FF5050"),
		CodeLight:        lipgloss.Color("#FFFFFF"),
		CodeDark:         lipgloss.Color("#000000"),
		Gradient:         colors("#00B32C", "#00FF41", "#A6FFB8"),
		Glow:             lipgloss.Color("#00FF41"),
		PanelBorder:      lipgloss.Color("#1A5A2A"),
		PanelBorderFocus: lipgloss.Color("#00FF41"),
		BubbleOwn:        lipgloss.Color("#0F4D22"),
		BubbleOwnText:    lipgloss.Color("#E6FFEA"),
		BubblePeer:       lipgloss.Color("#0B2613"),
		BubblePeerText:   lipgloss.Color("#B8FFC4"),
		AvatarPalette: colors("#00FF41", "#7CFF7C", "#39D98A", "#B8FF5C", "#00E5A0",
			"#8FE3B0", "#D4FF8A", "#4DFFB8", "#2EE6D6", "#E6FF4D"),
	}
}

// iceTheme is frost blue and white on midnight.
func iceTheme() Theme {
	return Theme{
		Name:             "ice",
		Description:      "frost blue and white on midnight",
		Background:       lipgloss.Color("#0B1220"),
		Text:             lipgloss.Color("#EAF4FF"),
		Muted:            lipgloss.Color("#A9C0DA"),
		Faint:            lipgloss.Color("#7088A8"),
		Border:           lipgloss.Color("#24344F"),
		Surface:          lipgloss.Color("#111B2E"),
		Highlight:        lipgloss.Color("#1B2A45"),
		Accent:           lipgloss.Color("#7FD4FF"),
		OnAccent:         lipgloss.Color("#0B1220"),
		Success:          lipgloss.Color("#8EF0C8"),
		Warning:          lipgloss.Color("#FFD98A"),
		Danger:           lipgloss.Color("#FF7A8A"),
		CodeLight:        lipgloss.Color("#FFFFFF"),
		CodeDark:         lipgloss.Color("#000000"),
		Gradient:         colors("#FFFFFF", "#BFE8FF", "#7FD4FF", "#4A90FF"),
		Glow:             lipgloss.Color("#BFE8FF"),
		PanelBorder:      lipgloss.Color("#2E4466"),
		PanelBorderFocus: lipgloss.Color("#7FD4FF"),
		BubbleOwn:        lipgloss.Color("#1E4A78"),
		BubbleOwnText:    lipgloss.Color("#FFFFFF"),
		BubblePeer:       lipgloss.Color("#18263D"),
		BubblePeerText:   lipgloss.Color("#EAF4FF"),
		AvatarPalette: colors("#7FD4FF", "#BFE8FF", "#4A90FF", "#8EF0C8", "#FFD98A",
			"#FF9EB5", "#B9A7FF", "#5FE3E3", "#FFFFFF", "#9FB8FF"),
	}
}

// duskTheme is a low-contrast dark theme with a soft blue accent.
func duskTheme() Theme {
	return Theme{
		Name:             "dusk",
		Description:      "soft blue on the terminal's own dark background",
		Gradient:         colors("#8AADF4", "#C6A0F6", "#F5BDE6"),
		Glow:             lipgloss.Color("#8AADF4"),
		PanelBorder:      lipgloss.Color("#323743"),
		PanelBorderFocus: lipgloss.Color("#8AADF4"),
		BubbleOwn:        lipgloss.Color("#2E3A57"),
		BubbleOwnText:    lipgloss.Color("#E8ECF4"),
		BubblePeer:       lipgloss.Color("#23262F"),
		BubblePeerText:   lipgloss.Color("#DADDE4"),
		AvatarPalette: colors("#F5BDE6", "#C6A0F6", "#ED8796", "#F5A97F", "#EED49F",
			"#A6DA95", "#8BD5CA", "#91D7E3", "#7DC4E4", "#B7BDF8"),
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

// fjordTheme is a cool, frosty dark theme in the spirit of Nord.
func fjordTheme() Theme {
	return Theme{
		Name:             "fjord",
		Description:      "frost blue on polar night",
		Gradient:         colors("#8FBCBB", "#88C0D0", "#81A1C1", "#B48EAD"),
		Glow:             lipgloss.Color("#88C0D0"),
		PanelBorder:      lipgloss.Color("#4C566A"),
		PanelBorderFocus: lipgloss.Color("#88C0D0"),
		BubbleOwn:        lipgloss.Color("#3E5A70"),
		BubbleOwnText:    lipgloss.Color("#ECEFF4"),
		BubblePeer:       lipgloss.Color("#3B4252"),
		BubblePeerText:   lipgloss.Color("#E5E9F0"),
		AvatarPalette: colors("#E08A92", "#E9A37F", "#EBCB8B", "#A3BE8C", "#8FBCBB",
			"#88C0D0", "#9DB6D6", "#C7A3C2", "#D8DEE9", "#B9D7A0"),
		Background: lipgloss.Color("#2E3440"),
		Text:       lipgloss.Color("#E5E9F0"),
		Muted:      lipgloss.Color("#A7B1C2"),
		Faint:      lipgloss.Color("#7A859A"),
		Border:     lipgloss.Color("#4C566A"),
		Surface:    lipgloss.Color("#3B4252"),
		Highlight:  lipgloss.Color("#434C5E"),
		Accent:     lipgloss.Color("#88C0D0"),
		OnAccent:   lipgloss.Color("#2E3440"),
		Success:    lipgloss.Color("#A3BE8C"),
		Warning:    lipgloss.Color("#EBCB8B"),
		Danger:     lipgloss.Color("#E08A92"),
		CodeLight:  lipgloss.Color("#ECEFF4"),
		CodeDark:   lipgloss.Color("#2E3440"),
	}
}

// emberTheme is a warm dark theme on the Solarized dark palette.
func emberTheme() Theme {
	return Theme{
		Name:             "ember",
		Description:      "solarized dark with an orange glow",
		Gradient:         colors("#F06A60", "#E07A3A", "#C9A227"),
		Glow:             lipgloss.Color("#E07A3A"),
		PanelBorder:      lipgloss.Color("#174652"),
		PanelBorderFocus: lipgloss.Color("#E07A3A"),
		BubbleOwn:        lipgloss.Color("#5A3424"),
		BubbleOwnText:    lipgloss.Color("#FDF6E3"),
		BubblePeer:       lipgloss.Color("#073642"),
		BubblePeerText:   lipgloss.Color("#B4C2C2"),
		AvatarPalette: colors("#E07A3A", "#C9A227", "#9AAE1A", "#2AA198", "#3B9BE0",
			"#8A8FDB", "#E0559A", "#F06A60", "#93A1A1", "#5FC9B5"),
		Background: lipgloss.Color("#002B36"),
		Text:       lipgloss.Color("#A3B1B1"),
		Muted:      lipgloss.Color("#8A9B9D"),
		Faint:      lipgloss.Color("#647D84"),
		Border:     lipgloss.Color("#174652"),
		Surface:    lipgloss.Color("#073642"),
		Highlight:  lipgloss.Color("#0D4351"),
		Accent:     lipgloss.Color("#E07A3A"),
		OnAccent:   lipgloss.Color("#002B36"),
		Success:    lipgloss.Color("#9AAE1A"),
		Warning:    lipgloss.Color("#C9A227"),
		Danger:     lipgloss.Color("#F06A60"),
		CodeLight:  lipgloss.Color("#FDF6E3"),
		CodeDark:   lipgloss.Color("#002B36"),
	}
}

// contrastTheme maximises legibility: white text on black and saturated
// signal colors.
func contrastTheme() Theme {
	return Theme{
		Name:             "contrast",
		Description:      "high contrast, white on black",
		Gradient:         colors("#FFD700", "#FFFFFF", "#5FFF87"),
		Glow:             lipgloss.Color("#FFD700"),
		PanelBorder:      lipgloss.Color("#9E9E9E"),
		PanelBorderFocus: lipgloss.Color("#FFD700"),
		BubbleOwn:        lipgloss.Color("#3A3A3A"),
		BubbleOwnText:    lipgloss.Color("#FFFFFF"),
		BubblePeer:       lipgloss.Color("#1C1C1C"),
		BubblePeerText:   lipgloss.Color("#FFFFFF"),
		AvatarPalette: colors("#FFD700", "#5FFF87", "#FF7A7A", "#5FD7FF", "#FFAF5F",
			"#D787FF", "#FFFFFF", "#87FFFF", "#FF87D7", "#AFFF5F"),
		Background: lipgloss.Color("#000000"),
		Text:       lipgloss.Color("#FFFFFF"),
		Muted:      lipgloss.Color("#DADADA"),
		Faint:      lipgloss.Color("#B2B2B2"),
		Border:     lipgloss.Color("#9E9E9E"),
		Surface:    lipgloss.Color("#1C1C1C"),
		Highlight:  lipgloss.Color("#3A3A3A"),
		Accent:     lipgloss.Color("#FFD700"),
		OnAccent:   lipgloss.Color("#000000"),
		Success:    lipgloss.Color("#5FFF87"),
		Warning:    lipgloss.Color("#FFAF5F"),
		Danger:     lipgloss.Color("#FF7A7A"),
		CodeLight:  lipgloss.Color("#FFFFFF"),
		CodeDark:   lipgloss.Color("#000000"),
	}
}

// paperTheme is a light theme: ink on warm paper.
func paperTheme() Theme {
	return Theme{
		Name:             "paper",
		Description:      "light, ink on warm paper",
		Gradient:         colors("#245A8F", "#6B3FA0", "#A8231B"),
		Glow:             lipgloss.Color("#245A8F"),
		PanelBorder:      lipgloss.Color("#CFCABA"),
		PanelBorderFocus: lipgloss.Color("#245A8F"),
		BubbleOwn:        lipgloss.Color("#245A8F"),
		BubbleOwnText:    lipgloss.Color("#FFFFFF"),
		BubblePeer:       lipgloss.Color("#ECE8DC"),
		BubblePeerText:   lipgloss.Color("#26251F"),
		AvatarPalette: colors("#245A8F", "#A8231B", "#2F6B2F", "#805A00", "#6B3FA0",
			"#0F6E6E", "#A0306E", "#5A4A2A", "#3D4F9F", "#8A3A10"),
		Background: lipgloss.Color("#FAF8F2"),
		Text:       lipgloss.Color("#26251F"),
		Muted:      lipgloss.Color("#57544A"),
		Faint:      lipgloss.Color("#77736A"),
		Border:     lipgloss.Color("#CFCABA"),
		Surface:    lipgloss.Color("#ECE8DC"),
		Highlight:  lipgloss.Color("#E0DACA"),
		Accent:     lipgloss.Color("#245A8F"),
		OnAccent:   lipgloss.Color("#FFFFFF"),
		Success:    lipgloss.Color("#2F6B2F"),
		Warning:    lipgloss.Color("#805A00"),
		Danger:     lipgloss.Color("#A8231B"),
		CodeLight:  lipgloss.Color("#FFFFFF"),
		CodeDark:   lipgloss.Color("#000000"),
	}
}

// Themes returns every built-in theme, the default first.
func Themes() []Theme {
	return []Theme{
		DefaultTheme(), neonTheme(), synthwaveTheme(), matrixTheme(), iceTheme(),
		duskTheme(), fjordTheme(), emberTheme(), contrastTheme(), paperTheme(),
	}
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
	if t.Name == "" && t.Text == nil && t.Accent == nil && t.Background == nil && len(t.Gradient) == 0 {
		return d
	}
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
	fill(&t.Glow, t.Accent)
	fill(&t.PanelBorder, t.Border)
	fill(&t.PanelBorderFocus, t.Accent)
	fill(&t.BubbleOwn, t.Highlight)
	fill(&t.BubbleOwnText, t.Text)
	fill(&t.BubblePeer, t.Surface)
	fill(&t.BubblePeerText, t.Text)
	if len(t.Gradient) == 0 {
		t.Gradient = []color.Color{t.Accent, t.Glow}
	}
	if len(t.AvatarPalette) == 0 {
		t.AvatarPalette = d.AvatarPalette
	}
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
	match      lipgloss.Style

	// markdown reports whether message bodies are rendered as Markdown,
	// with md.
	markdown bool
	md       *markdownRenderer
}

// newStyles derives the styles of a theme, with Markdown rendering on.
func newStyles(t Theme) styles {
	t = t.complete()
	base := lipgloss.NewStyle()
	bar := base.Background(t.Surface).Foreground(t.Text)
	return styles{
		markdown: true,
		md:       newMarkdownRenderer(t),
		match:    base.Background(t.Accent).Foreground(t.OnAccent),
		theme:    t,
		text:     base.Foreground(t.Text),
		muted:    base.Foreground(t.Muted),
		faint:    base.Foreground(t.Faint),
		accent:   base.Foreground(t.Accent),
		ok:       base.Foreground(t.Success),
		warn:     base.Foreground(t.Warning),
		danger:   base.Foreground(t.Danger),
		bold:     base.Foreground(t.Text).Bold(true),
		border:   base.Foreground(t.Border),

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
