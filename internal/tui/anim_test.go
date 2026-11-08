package tui

import (
	"fmt"
	"image/color"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

func sameColor(a, b color.Color) bool {
	ar, ag, ab, _ := a.RGBA()
	br, bg, bb, _ := b.RGBA()
	return ar>>8 == br>>8 && ag>>8 == bg>>8 && ab>>8 == bb>>8
}

func TestGradientTextKeepsWidthAndText(t *testing.T) {
	stops := DefaultTheme().Gradient
	for _, s := range []string{
		"", "q", "qchat", "post-quantum · end-to-end · sealed", "日本語のテキスト", "a🔒b", "👩‍💻 dev", "éclair", "  spaced  ",
		"bad\x1b[31m\x07",
	} {
		got := gradientText(s, stops)
		want := strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, s)
		if lipgloss.Width(got) != lipgloss.Width(want) {
			t.Errorf("gradientText(%q) width %d, want %d", s, lipgloss.Width(got), lipgloss.Width(want))
		}
		if plain := stripANSI(got); plain != want {
			t.Errorf("gradientText(%q) text %q, want %q", s, plain, want)
		}
		if strings.ContainsRune(stripANSI(got), '\x1b') {
			t.Errorf("gradientText(%q) leaks an escape", s)
		}
	}
	if got := gradientText("plain", nil); got != "plain" {
		t.Errorf("no stops: %q", got)
	}
	one := gradientText("ab", []color.Color{lipgloss.Color("#FF0000")})
	if stripANSI(one) != "ab" {
		t.Errorf("single stop: %q", one)
	}
}

func TestGradientRuleWidth(t *testing.T) {
	stops := DefaultTheme().Gradient
	for _, w := range []int{-1, 0, 1, 2, 7, 80, 333} {
		for _, glyph := range []string{"━", "─", "", "═", "▓", "日"} {
			got := gradientRule(w, glyph, stops)
			if want := max(w, 0); lipgloss.Width(got) != want {
				t.Errorf("gradientRule(%d, %q) width %d", w, glyph, lipgloss.Width(got))
			}
		}
	}
}

func TestBlendAndFadeEndpoints(t *testing.T) {
	a, b := lipgloss.Color("#102030"), lipgloss.Color("#F0E0D0")
	if !sameColor(blend(a, b, 0), a) || !sameColor(blend(a, b, 1), b) {
		t.Error("blend endpoints")
	}
	if !sameColor(blend(a, b, -3), a) || !sameColor(blend(a, b, 9), b) {
		t.Error("blend does not clamp")
	}
	if mid := blend(lipgloss.Color("#000000"), lipgloss.Color("#FFFFFF"), 0.5); !sameColor(mid, lipgloss.Color("#808080")) {
		t.Errorf("blend midpoint %v", mid)
	}
	if !sameColor(blend(nil, b, 0.3), b) || !sameColor(blend(a, nil, 0.3), a) {
		t.Error("blend with nil")
	}
	if !sameColor(fade(a, b, 0, 5), a) || !sameColor(fade(a, b, 5, 5), b) || !sameColor(fade(a, b, 9, 5), b) || !sameColor(fade(a, b, 2, 0), b) {
		t.Error("fade endpoints")
	}
}

func TestPulseCycles(t *testing.T) {
	th := DefaultTheme()
	base := th.Accent
	if !sameColor(pulse(th, base, 0), base) || !sameColor(pulse(th, base, pulseFrames), base) {
		t.Error("pulse does not start and end at full brightness")
	}
	if sameColor(pulse(th, base, pulseFrames/2), base) {
		t.Error("pulse does not dim")
	}
	if luminance(pulse(th, base, pulseFrames/2)) >= luminance(base) {
		t.Error("pulse midpoint is not darker on a dark theme")
	}
	if !sameColor(pulse(th, base, -1), pulse(th, base, pulseFrames-1)) {
		t.Error("negative frames")
	}
	if AnimInterval*pulseFrames < 1e9 || AnimInterval*pulseFrames > 1.5e9 {
		t.Errorf("pulse period %v", AnimInterval*pulseFrames)
	}
}

func TestSpinnerFrames(t *testing.T) {
	seen := map[string]bool{}
	for i := -20; i < 20; i++ {
		f := spinnerFrame(i)
		if lipgloss.Width(f) != 1 {
			t.Fatalf("frame %d: %q", i, f)
		}
		seen[f] = true
	}
	if len(seen) != 10 || spinnerFrame(0) != "⠋" || spinnerFrame(10) != "⠋" {
		t.Errorf("spinner frames %v", seen)
	}
}

func TestAnimTick(t *testing.T) {
	if animTick() == nil {
		t.Fatal("animTick returns nil")
	}
}

func TestAvatarColorStableAndDistinct(t *testing.T) {
	for _, th := range Themes() {
		if avatarColor(th, "qc1-25ie-urlg") != avatarColor(th, "qc1-25ie-urlg") {
			t.Errorf("%s: avatar color not stable", th.Name)
		}
		used := map[string]bool{}
		for i := range 200 {
			r, g, b, _ := avatarColor(th, fmt.Sprintf("qc1-%04d", i)).RGBA()
			used[fmt.Sprint(r, g, b)] = true
		}
		if len(used) < len(th.AvatarPalette)*3/4 {
			t.Errorf("%s: only %d avatar colors used of %d", th.Name, len(used), len(th.AvatarPalette))
		}
	}
	th := DefaultTheme()
	if sameColor(avatarColor(th, "alice"), avatarColor(th, "bob")) && sameColor(avatarColor(th, "alice"), avatarColor(th, "carol")) {
		t.Error("different ids share one color")
	}
}

func TestAvatarBadge(t *testing.T) {
	th := DefaultTheme()
	for _, tc := range []struct{ id, name, want string }{
		{"qc1-x", "bob", "(B)"},
		{"qc1-x", "Élodie", "(É)"},
		{"qc1-x", "  ✦ zed", "(Z)"},
		{"qc1-x", "日本", "(Q)"},
		{"", "", "(?)"},
		{"", "\x07", "(?)"},
		{"", "\x07x", "(X)"},
		{"", "4you", "(4)"},
	} {
		got := avatar(th, tc.id, tc.name)
		if stripANSI(got) != tc.want || lipgloss.Width(got) != 3 {
			t.Errorf("avatar(%q, %q) = %q, want %q", tc.id, tc.name, stripANSI(got), tc.want)
		}
	}
}

func TestParseAnimations(t *testing.T) {
	for in, want := range map[string]bool{"": true, "on": true, "off": false, "garbage": true} {
		if got := parseAnimations(in); got != want {
			t.Errorf("parseAnimations(%q) = %v", in, got)
		}
	}
}

func TestThemesHaveRedesignFields(t *testing.T) {
	names := map[string]bool{}
	for _, th := range Themes() {
		names[th.Name] = true
		for name, c := range map[string]color.Color{
			"Glow": th.Glow, "PanelBorder": th.PanelBorder, "PanelBorderFocus": th.PanelBorderFocus,
			"BubbleOwn": th.BubbleOwn, "BubbleOwnText": th.BubbleOwnText, "BubblePeer": th.BubblePeer, "BubblePeerText": th.BubblePeerText,
		} {
			if c == nil {
				t.Errorf("%s: %s is unset", th.Name, name)
			}
		}
		if n := len(th.Gradient); n < 3 || n > 5 {
			t.Errorf("%s: %d gradient stops", th.Name, n)
		}
		for i, c := range th.Gradient {
			if c == nil {
				t.Errorf("%s: gradient stop %d is nil", th.Name, i)
			}
		}
		distinct := map[string]bool{}
		bg := th.Background
		if bg == nil {
			bg = color.Black
		}
		for _, c := range th.AvatarPalette {
			r, g, b, _ := c.RGBA()
			distinct[fmt.Sprint(r, g, b)] = true
			if contrast(c, bg) < 3 {
				t.Errorf("%s: avatar color %v has contrast %.1f", th.Name, c, contrast(c, bg))
			}
		}
		if len(distinct) < 8 {
			t.Errorf("%s: %d distinct avatar colors", th.Name, len(distinct))
		}
		if contrast(th.BubbleOwnText, th.BubbleOwn) < 4.5 || contrast(th.BubblePeerText, th.BubblePeer) < 4.5 {
			t.Errorf("%s: bubble text contrast own %.1f peer %.1f", th.Name,
				contrast(th.BubbleOwnText, th.BubbleOwn), contrast(th.BubblePeerText, th.BubblePeer))
		}
		if contrast(th.PanelBorderFocus, bg) < 3 {
			t.Errorf("%s: focused border contrast %.1f", th.Name, contrast(th.PanelBorderFocus, bg))
		}
		c := th.complete()
		if c.Glow == nil || len(c.Gradient) == 0 || len(c.AvatarPalette) == 0 {
			t.Errorf("%s: complete drops fields", th.Name)
		}
	}
	for _, want := range []string{"phosphor", "neon", "synthwave", "matrix", "ice", "dusk", "fjord", "ember", "contrast", "paper"} {
		if !names[want] {
			t.Errorf("theme %s missing", want)
		}
	}
	if DefaultTheme().Name != "phosphor" {
		t.Errorf("default theme %q", DefaultTheme().Name)
	}
	zero := Theme{}.complete()
	if zero.Name != "phosphor" || len(zero.Gradient) < 3 {
		t.Errorf("zero theme completes to %q with %d stops", zero.Name, len(zero.Gradient))
	}
	partial := Theme{Name: "custom", Accent: lipgloss.Color("#FF0000")}.complete()
	if partial.Glow == nil || partial.PanelBorderFocus == nil || len(partial.Gradient) == 0 || len(partial.AvatarPalette) < 8 || partial.BubbleOwn == nil {
		t.Error("partial theme not completed")
	}
}
