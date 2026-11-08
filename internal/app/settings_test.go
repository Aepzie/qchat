package app

import (
	"context"
	"testing"

	"github.com/Aepzie/qchat/internal/store/clientdb"
	"github.com/Aepzie/qchat/internal/tui"
)

func TestUISettingsPersist(t *testing.T) {
	r := newFakeRelay()
	u := newFakeUser(t, r, "alice")

	if v, err := u.app.GetSetting(tui.SettingTheme); err != nil || v != "" {
		t.Fatalf("unset theme: %q, %v", v, err)
	}
	if err := u.app.SetSetting(tui.SettingTheme, "fjord"); err != nil {
		t.Fatal(err)
	}
	if err := u.app.SetSetting(tui.SettingMarkdown, "off"); err != nil {
		t.Fatal(err)
	}

	u.restart()
	if v, err := u.app.GetSetting(tui.SettingTheme); err != nil || v != "fjord" {
		t.Fatalf("theme after restart: %q, %v", v, err)
	}
	if v, err := u.app.GetSetting(tui.SettingMarkdown); err != nil || v != "off" {
		t.Fatalf("markdown after restart: %q, %v", v, err)
	}
}

func TestUISettingsAreRestricted(t *testing.T) {
	r := newFakeRelay()
	u := newFakeUser(t, r, "alice")

	if err := u.app.SetSetting(clientdb.SettingDisplayName, "mallory"); err == nil {
		t.Fatal("the interface could overwrite the display name")
	}
	if _, err := u.app.GetSetting(clientdb.SettingDisplayName); err == nil {
		t.Fatal("the interface could read an internal setting")
	}
	if err := u.app.SetSetting(tui.SettingTheme, string(make([]byte, 65))); err == nil {
		t.Fatal("oversized value accepted")
	}
	if err := u.app.SetSetting(tui.SettingTheme, "\xff"); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	if got := u.app.Self().DisplayName; got != "alice" {
		t.Fatalf("display name changed to %q", got)
	}
	if err := u.prof.DB.PutSetting(context.Background(), tui.SettingTheme, make([]byte, 200)); err != nil {
		t.Fatal(err)
	}
	if v, err := u.app.GetSetting(tui.SettingTheme); err != nil || v != "" {
		t.Fatalf("oversized stored value returned: %q, %v", v, err)
	}
}
