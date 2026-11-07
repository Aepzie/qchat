package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// appDirName is the name of the per-user qchat directory.
const appDirName = "qchat"

// DefaultDir returns the default profile directory of the current user:
//
//   - Windows: %AppData%\qchat (os.UserConfigDir, the roaming application
//     data folder, which is private to the user by default);
//   - macOS: ~/Library/Application Support/qchat (os.UserConfigDir);
//   - other systems: $XDG_DATA_HOME/qchat if XDG_DATA_HOME is set to an
//     absolute path, otherwise ~/.local/share/qchat, following the XDG Base
//     Directory specification (the profile is data, not configuration, so
//     XDG_CONFIG_HOME is not used; relative values of XDG_DATA_HOME are
//     ignored as the specification requires).
//
// DefaultDir only computes the path; [Create] creates the directory.
func DefaultDir() (string, error) {
	return defaultDir(runtime.GOOS, os.Getenv, os.UserHomeDir, os.UserConfigDir)
}

func defaultDir(goos string, getenv func(string) string, homeDir, configDir func() (string, error)) (string, error) {
	switch goos {
	case "windows", "darwin", "ios":
		base, err := configDir()
		if err != nil {
			return "", fmt.Errorf("profile: locating the application data directory: %w", err)
		}
		return filepath.Join(base, appDirName), nil
	}
	if xdg := getenv("XDG_DATA_HOME"); xdg != "" && filepath.IsAbs(xdg) {
		return filepath.Join(xdg, appDirName), nil
	}
	home, err := homeDir()
	if err != nil {
		return "", fmt.Errorf("profile: locating the home directory: %w", err)
	}
	if home == "" {
		return "", errors.New("profile: the home directory is unknown")
	}
	return filepath.Join(home, ".local", "share", appDirName), nil
}
