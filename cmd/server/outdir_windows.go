//go:build windows

package main

import (
	"fmt"
	"io/fs"

	"golang.org/x/sys/windows"
)

// checkOutDir refuses a build-client output directory that is a junction or
// symbolic link, whose creator could retarget it between building, hashing
// and publishing the binaries. Who may write to the directory is governed by
// its ACL, which the operator chooses together with the location.
func checkOutDir(dir string) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return &fs.PathError{Op: "stat", Path: dir, Err: err}
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("output directory %s is a junction or symbolic link; pass the real directory instead", dir)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("output directory %s exists and is not a directory", dir)
	}
	return nil
}
