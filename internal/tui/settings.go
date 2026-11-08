package tui

import (
	tea "charm.land/bubbletea/v2"
)

// Results of settings calls.
type (
	settingsMsg struct {
		theme, markdown string
		err             error
	}
	settingSavedMsg struct {
		name string
		err  error
	}
)

// settingsBackend returns the Backend's SettingsBackend, or nil.
func (m *Model) settingsBackend() SettingsBackend {
	sb, _ := m.cfg.Backend.(SettingsBackend)
	return sb
}

// loadSettings reads the stored preferences.
func (m *Model) loadSettings() tea.Cmd {
	sb := m.settingsBackend()
	if sb == nil {
		return nil
	}
	return func() tea.Msg {
		theme, err := sb.GetSetting(SettingTheme)
		if err != nil {
			return settingsMsg{err: err}
		}
		markdown, err := sb.GetSetting(SettingMarkdown)
		return settingsMsg{theme: theme, markdown: markdown, err: err}
	}
}

// saveSetting stores one preference, or does nothing without a
// SettingsBackend.
func (m *Model) saveSetting(name, value string) tea.Cmd {
	sb := m.settingsBackend()
	if sb == nil {
		return nil
	}
	return func() tea.Msg { return settingSavedMsg{name: name, err: sb.SetSetting(name, value)} }
}

// applySettings applies stored preferences. Unknown values are ignored, so
// a damaged or newer setting cannot break the interface.
func (m *Model) applySettings(msg settingsMsg) {
	if msg.err != nil {
		m.sysLog(entryWarn, "Cannot load your interface settings: "+describeBackendError(msg.err)+". Using the defaults.")
		return
	}
	if t, ok := ThemeByName(msg.theme); ok {
		m.setTheme(t)
	}
	if on, ok := parseOnOff(msg.markdown); ok {
		m.setMarkdown(on)
	}
}

// setTheme switches to theme t and redraws everything with it.
func (m *Model) setTheme(t Theme) {
	markdown := m.st.markdown
	m.st = newStyles(t)
	m.st.markdown = markdown
	m.input.st = m.st
	m.refreshHistory()
}

// themeCommands are the /theme palette entries, one per theme.
func themeCommands() []command {
	themes := Themes()
	out := make([]command, 0, len(themes))
	for _, t := range themes {
		out = append(out, command{"/theme " + t.Name, t.Description})
	}
	return out
}

// cmdTheme runs /theme: without an argument it lists the themes, with one
// it switches and stores the choice.
func (m *Model) cmdTheme(args []string) tea.Cmd {
	if len(args) == 0 {
		var rows []row
		for _, t := range Themes() {
			name := t.Name
			if t.Name == m.st.theme.Name {
				name += " ✓"
			}
			rows = append(rows, row{name, t.Description})
		}
		m.addOutput("themes", rows, "Switch with /theme <name>; tab completes the name.")
		return nil
	}
	name := resolveSub("/theme", args[0], len(args) == 1, m.paletteSel)
	t, ok := ThemeByName(name)
	if !ok {
		m.log(entryError, "Unknown theme "+truncate(cleanLine(args[0], 32), 32)+". Type /theme to list them.")
		return nil
	}
	m.setTheme(t)
	m.log(entryGood, "Theme "+t.Name+".")
	return m.saveSetting(SettingTheme, t.Name)
}
