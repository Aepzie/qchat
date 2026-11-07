//go:build !unix && !windows

package profile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// makePrivateDir creates dir with mode 0700 on systems without Unix or
// Windows permissions, where nothing stronger is available.
func makePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("profile: creating directory: %w", err)
	}
	return nil
}

func syncDir(string) error { return nil }
