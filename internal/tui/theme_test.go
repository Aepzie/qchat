package tui

import (
	"errors"
	"image/color"
	"math"
	"strings"
	"sync"
	"testing"
)

// settingsBackend is a fakeBackend that also stores settings.
type settingsBackend struct {
	*fakeBackend
	mu     sync.Mutex
	values map[string]string
	writes []string
	getErr error
	setErr error
}

func newSettingsBackend() *settingsBackend {
	return &settingsBackend{fakeBackend: newFakeBackend(), values: map[string]string{}}
}

func (s *settingsBackend) GetSetting(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return "", s.getErr
	}
	return s.values[name], nil
}

func (s *settingsBackend) SetSetting(name, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, name+"="+value)
	if s.setErr != nil {
		return s.setErr
	}
	s.values[name] = value
	return nil
}

// luminance is the relative luminance of c as defined by WCAG.
func luminance(c color.Color) float64 {
	r, g, b, _ := c.RGBA()
	channel := func(v uint32) float64 {
		x := float64(v) / 0xffff
		if x <= 0.03928 {
			return x / 12.92
		}
		return math.Pow((x+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(r) + 0.7152*channel(g) + 0.0722*channel(b)
}

func contrast(a, b color.Color) float64 {
	la, lb := luminance(a), luminance(b)
	return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
}

func TestThemesAreCompleteAndReadable(t *testing.T) {
	seen := map[string]bool{}
	themes := Themes()
	if len(themes) < 5 || themes[0].Name != DefaultTheme().Name {
		t.Fatalf("got %d themes, default first: %v", len(themes), themes[0].Name)
	}
	for _, th := range themes {
		if th.Name == "" || seen[th.Name] || th.Description == "" || strings.ToLower(th.Name) != th.Name {
			t.Errorf("bad theme name or description: %q %q", th.Name, th.Description)
		}
		seen[th.Name] = true
		for name, c := range map[string]color.Color{
			"Text": th.Text, "Muted": th.Muted, "Faint": th.Faint, "Border": th.Border, "Surface": th.Surface,
			"Highlight": th.Highlight, "Accent": th.Accent, "OnAccent": th.OnAccent, "Success": th.Success,
			"Warning": th.Warning, "Danger": th.Danger, "CodeLight": th.CodeLight, "CodeDark": th.CodeDark,
		} {
			if c == nil {
				t.Errorf("%s: %s is unset", th.Name, name)
			}
		}
		if luminance(th.CodeLight) <= luminance(th.CodeDark) || contrast(th.CodeLight, th.CodeDark) < 10 {
			t.Errorf("%s: QR code must be dark modules on a light ground with high contrast (%.1f)", th.Name, contrast(th.CodeLight, th.CodeDark))
		}
		if contrast(th.OnAccent, th.Accent) < 4.5 {
			t.Errorf("%s: text on the accent is hard to read (%.1f)", th.Name, contrast(th.OnAccent, th.Accent))
		}
		bg := th.Background
		if bg == nil {
			bg = color.Black
		}
		for name, c := range map[string]color.Color{"Text": th.Text, "Muted": th.Muted, "Danger": th.Danger, "Accent": th.Accent} {
			if contrast(c, bg) < 4.5 {
				t.Errorf("%s: %s on the background has contrast %.1f", th.Name, name, contrast(c, bg))
			}
		}
		if contrast(th.Faint, bg) < 3 {
			t.Errorf("%s: Faint on the background has contrast %.1f", th.Name, contrast(th.Faint, bg))
		}
		got, ok := ThemeByName(" " + strings.ToUpper(th.Name) + " ")
		if !ok || got.Name != th.Name {
			t.Errorf("ThemeByName(%q) = %q, %v", th.Name, got.Name, ok)
		}
	}
	if _, ok := ThemeByName("nope"); ok {
		t.Error("unknown theme found")
	}
}

func TestThemeCommandSwitchesAndPersists(t *testing.T) {
	sb := newSettingsBackend()
	m := newChatModel(t, sb, 100, 30)

	m = say(t, m, "/theme")
	s := screen(m)
	for _, th := range Themes() {
		if !strings.Contains(s, th.Name) {
			t.Errorf("/theme does not list %s:\n%s", th.Name, s)
		}
	}
	if !strings.Contains(s, "dusk ✓") {
		t.Errorf("/theme does not mark the current theme:\n%s", s)
	}

	m = say(t, m, "/theme paper")
	if m.st.theme.Name != "paper" || m.input.st.theme.Name != "paper" {
		t.Fatalf("theme is %q", m.st.theme.Name)
	}
	if v := m.View(); v.BackgroundColor == nil || luminance(v.BackgroundColor) < 0.8 {
		t.Errorf("paper does not set a light background: %v", v.BackgroundColor)
	}
	if len(sb.writes) != 1 || sb.writes[0] != SettingTheme+"=paper" {
		t.Errorf("writes %v", sb.writes)
	}
	checkFits(t, m)

	m = say(t, m, "/theme dusk")
	if m.View().BackgroundColor != nil {
		t.Error("dusk changes the terminal background")
	}

	m = say(t, m, "/theme neon")
	if !strings.Contains(screen(m), "Unknown theme neon") || m.st.theme.Name != "dusk" {
		t.Errorf("unknown theme accepted:\n%s", screen(m))
	}

	sb.setErr = errors.New("disk full")
	m = say(t, m, "/theme fjord")
	if m.st.theme.Name != "fjord" || !strings.Contains(screen(m), "Cannot save the setting ui.theme: disk full") {
		t.Errorf("failed save not reported:\n%s", screen(m))
	}
}

func TestThemePaletteCompletion(t *testing.T) {
	m := newChatModel(t, newFakeBackend(), 100, 30)
	m = typeText(t, m, "/theme ")
	s := screen(m)
	for _, th := range Themes() {
		if !strings.Contains(s, "/theme "+th.Name) {
			t.Errorf("palette lacks %s:\n%s", th.Name, s)
		}
	}
	m.input.Reset()
	m.resetPalette()
	m = typeText(t, m, "/theme em")
	m = update(t, m, keyTab)
	if m.input.Value() != "/theme ember" {
		t.Fatalf("completion: %q", m.input.Value())
	}
	m.input.Reset()
	m.resetPalette()
	m = say(t, m, "/theme c")
	if m.st.theme.Name != "contrast" {
		t.Errorf("enter on a prefix chose %q", m.st.theme.Name)
	}
}

func TestStoredThemeIsApplied(t *testing.T) {
	sb := newSettingsBackend()
	sb.values[SettingTheme] = "ember"
	m := newChatModel(t, sb, 80, 24)
	if m.st.theme.Name != "ember" {
		t.Fatalf("stored theme not applied: %q", m.st.theme.Name)
	}

	sb = newSettingsBackend()
	sb.values[SettingTheme] = "\x1b[31mevil"
	m = newChatModel(t, sb, 80, 24)
	if m.st.theme.Name != "dusk" {
		t.Errorf("bogus stored theme applied: %q", m.st.theme.Name)
	}

	sb = newSettingsBackend()
	sb.getErr = errors.New("locked")
	m = newChatModel(t, sb, 80, 24)
	if m.st.theme.Name != "dusk" || !strings.Contains(strings.Join(entryTexts(m.convs[0].entries), "\n"), "Cannot load your interface settings: locked") {
		t.Errorf("settings error not reported")
	}
}

func TestEveryThemeFitsEverySize(t *testing.T) {
	for _, th := range Themes() {
		for _, size := range [][2]int{{40, 10}, {69, 17}, {100, 30}} {
			fb := newFakeBackend()
			m := newChatModel(t, fb, size[0], size[1])
			m.setTheme(th)
			m = do(t, m, keyCtrlN)
			m = say(t, m, "/whoami")
			checkFits(t, m)
			m = do(t, m, keyEsc)
			m = say(t, m, "/verify")
			checkFits(t, m)
		}
	}
}

func entryTexts(entries []entry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.text)
	}
	return out
}
