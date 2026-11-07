//go:build windows

package profile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows ignores the Unix permission bits passed to os.Mkdir, and a new
// directory inherits the ACL of its parent. %AppData% is private to the user
// by default, but a profile directory given explicitly (say on another
// drive, or under C:\ProgramData) could inherit read access for every local
// user. makePrivateDir therefore gives the profile directory an explicit,
// protected DACL (the P flag stops inheritance from the parent) that grants
// full control to the current user and to SYSTEM only. The OI and CI flags
// make every file created inside (identity.qkey, qchat.db and its WAL files,
// temporary files) inherit exactly these two entries.
//
// The Administrators group is deliberately not granted access: an
// administrator can still take ownership, but no other account can read
// the encrypted key file or the database through normal access checks.
const privateDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%s)"

// makePrivateDir creates dir with the protected DACL. An existing directory
// is accepted only if it is a real directory (not a junction or symbolic
// link, whose creator could retarget it), and its DACL is then replaced by
// the protected one; this fails unless the current user may change it.
func makePrivateDir(dir string) error {
	sddl, err := privateDirDescriptor()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("profile: building security descriptor: %w", err)
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("profile: creating parent directory: %w", err)
		}
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	attributes := &windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	err = windows.CreateDirectory(name, attributes)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("profile: creating directory: %w", &fs.PathError{Op: "mkdir", Path: dir, Err: err})
	}

	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return fmt.Errorf("profile: %w", &fs.PathError{Op: "stat", Path: dir, Err: err})
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("profile: %s is a junction or symbolic link; use the real directory", dir)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("profile: %s exists and is not a directory", dir)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("profile: reading security descriptor: %w", err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("profile: restricting permissions of %s: %w", dir, err)
	}
	return nil
}

// privateDirDescriptor returns privateDirSDDL for the user running this
// process.
func privateDirDescriptor() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("profile: looking up the current user: %w", err)
	}
	return fmt.Sprintf(privateDirSDDL, user.User.Sid.String()), nil
}

// syncDir is a no-op on Windows: NTFS journals the rename itself, and a
// directory handle cannot be flushed through os.File.Sync.
func syncDir(string) error { return nil }
