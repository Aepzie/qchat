//go:build !windows

package clientdb

import (
	"context"
	"os"
	"testing"
)

func TestFileModeIsPrivate(t *testing.T) {
	d, path, _ := openTemp(t)
	if err := d.PutSetting(context.Background(), "probe", []byte("x")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, mode)
		}
	}
}
