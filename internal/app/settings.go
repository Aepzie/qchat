package app

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Aepzie/qchat/internal/store/clientdb"
	"github.com/Aepzie/qchat/internal/tui"
)

// maxUISettingLen bounds the value of an interface setting.
const maxUISettingLen = 64

// uiSettings lists the settings the interface may read and write. Other
// settings in the database, such as the own display name, are not
// reachable through tui.SettingsBackend.
var uiSettings = map[string]bool{
	tui.SettingTheme:    true,
	tui.SettingMarkdown: true,
}

// GetSetting implements tui.SettingsBackend. Settings are stored in the
// encrypted client database; a setting that was never stored reads as "".
func (a *App) GetSetting(name string) (string, error) {
	if !uiSettings[name] {
		return "", fmt.Errorf("unknown setting %q", name)
	}
	value, err := a.prof.DB.GetSetting(context.Background(), name)
	if errors.Is(err, clientdb.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(value) > maxUISettingLen || !utf8.Valid(value) {
		return "", nil
	}
	return string(value), nil
}

// SetSetting implements tui.SettingsBackend.
func (a *App) SetSetting(name, value string) error {
	if !uiSettings[name] {
		return fmt.Errorf("unknown setting %q", name)
	}
	if len(value) > maxUISettingLen || !utf8.ValidString(value) {
		return errors.New("setting value too long")
	}
	return a.prof.DB.PutSetting(context.Background(), name, []byte(value))
}

var _ tui.SettingsBackend = (*App)(nil)
