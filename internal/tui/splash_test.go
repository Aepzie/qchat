package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func TestSplashFitsEverySize(t *testing.T) {
	for _, th := range Themes() {
		for _, w := range []int{1, 3, 5, 10, 14, 15, 16, 30, 41, 42, 43, 80, 200} {
			for _, h := range []int{1, 2, 3, 4, 5, 7, 8, 9, 24, 60} {
				for _, frame := range []int{-3, 0, 1, 5, SplashFrames - 1, SplashFrames, SplashFrames + 40} {
					out := splashView(w, h, frame, th)
					lines := strings.Split(out, "\n")
					if len(lines) > h {
						t.Fatalf("%s %dx%d frame %d: %d lines", th.Name, w, h, frame, len(lines))
					}
					for i, l := range lines {
						if lipgloss.Width(l) > w {
							t.Fatalf("%s %dx%d frame %d: line %d is %d wide:\n%s", th.Name, w, h, frame, i, lipgloss.Width(l), stripANSI(out))
						}
					}
				}
			}
		}
	}
	if splashView(0, 10, 0, DefaultTheme()) != "" || splashView(10, 0, 0, DefaultTheme()) != "" {
		t.Error("empty size draws something")
	}
}

func TestSplashReveal(t *testing.T) {
	th := DefaultTheme()
	final := stripANSI(splashView(100, 30, SplashFrames, th))
	if !strings.Contains(final, splashTagline) || !strings.Contains(final, "██████╗") {
		t.Fatalf("final splash lacks logo or tagline:\n%s", final)
	}
	first := stripANSI(splashView(100, 30, 0, th))
	if strings.Contains(first, splashTagline) || strings.Contains(first, "╚██████╔╝") {
		t.Errorf("first frame already shows everything:\n%s", first)
	}
	if !strings.Contains(first, "▀") {
		t.Errorf("no scan line on the first frame:\n%s", first)
	}
	prev := -1
	for f := 0; f <= SplashFrames; f++ {
		n := strings.Count(stripANSI(splashView(100, 30, f, th)), "█")
		if n < prev {
			t.Errorf("frame %d reveals less than frame %d", f, f-1)
		}
		prev = n
	}
	small := stripANSI(splashView(30, 10, SplashFrames, th))
	if !strings.Contains(small, "┏━┓") || strings.Contains(small, "██") {
		t.Errorf("narrow splash does not use the small logo:\n%s", small)
	}
	tiny := stripANSI(splashView(12, 3, SplashFrames, th))
	if !strings.Contains(tiny, "qchat") {
		t.Errorf("tiny splash:\n%s", tiny)
	}
	if AnimInterval*SplashFrames > 1200*1e6 {
		t.Errorf("splash lasts %v", AnimInterval*SplashFrames)
	}
}

func TestBigLogoRowsAlign(t *testing.T) {
	rows := bigLogo()
	if len(rows) > 7 {
		t.Fatalf("%d rows", len(rows))
	}
	for i, r := range rows {
		if lipgloss.Width(r) != lipgloss.Width(rows[0]) {
			t.Errorf("row %d width %d, want %d", i, lipgloss.Width(r), lipgloss.Width(rows[0]))
		}
	}
	for i, r := range smallLogo {
		if lipgloss.Width(r) != lipgloss.Width(smallLogo[0]) {
			t.Errorf("small row %d width %d", i, lipgloss.Width(r))
		}
	}
}

func TestOnboardingCardsAnimateAndFit(t *testing.T) {
	cp := NewCreateProfile(CreateProfileConfig{})
	if cp.Init() == nil {
		t.Error("create profile does not start its animation")
	}
	if NewCreateProfile(CreateProfileConfig{NoAnimation: true}).Init() != nil {
		t.Error("NoAnimation ignored")
	}
	un := NewUnlock(UnlockConfig{})
	if un.Init() == nil || NewUnlock(UnlockConfig{NoAnimation: true}).Init() != nil {
		t.Error("unlock animation switch")
	}

	next, _ := cp.Update(tea.WindowSizeMsg{Width: 80, Height: 30})
	cp = next.(CreateProfileModel)
	next, cmd := cp.Update(onboardTickMsg{})
	cp = next.(CreateProfileModel)
	if cp.frame != 1 || cmd == nil {
		t.Errorf("tick: frame %d, cmd %v", cp.frame, cmd)
	}
	if cp.View().BackgroundColor == nil {
		t.Error("card does not use the theme background")
	}

	for _, th := range Themes() {
		for _, size := range [][2]int{{34, 16}, {40, 20}, {60, 26}, {80, 30}, {200, 60}} {
			for frame := range 20 {
				c := NewCreateProfile(CreateProfileConfig{Theme: th})
				c.frame = frame
				m, _ := c.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
				checkCardFits(t, th.Name+" create", m.(CreateProfileModel).View().Content, size[0], size[1])
				u := NewUnlock(UnlockConfig{Theme: th, Hint: strings.Repeat("profile path ", 9)})
				u.frame, u.busy = frame, frame%2 == 0
				m, _ = u.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
				checkCardFits(t, th.Name+" unlock", m.(UnlockModel).View().Content, size[0], size[1])
			}
		}
	}

	view := stripANSI(cp.View().Content)
	for _, want := range []string{"Create your qchat identity", "Display name", "Passphrase", "Confirm passphrase", "╭─"} {
		if !strings.Contains(view, want) {
			t.Errorf("create card lacks %q:\n%s", want, view)
		}
	}
}

func checkCardFits(t *testing.T, name, content string, w, h int) {
	t.Helper()
	lines := strings.Split(content, "\n")
	if len(lines) > h {
		t.Fatalf("%s %dx%d: %d lines", name, w, h, len(lines))
	}
	for i, l := range lines {
		if lipgloss.Width(l) > w {
			t.Fatalf("%s %dx%d: line %d is %d wide", name, w, h, i, lipgloss.Width(l))
		}
	}
}
