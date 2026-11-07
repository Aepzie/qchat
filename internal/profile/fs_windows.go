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
// user. makePrivateDir therefore gives the profile directory the current
// user as owner and an explicit, protected DACL (the P flag stops
// inheritance from the parent) that grants full control to the current user
// and to SYSTEM only. The OI and CI flags make every file created inside
// (identity.qkey, qchat.db and its WAL files, temporary files) inherit these
// entries.
//
// The OWNER RIGHTS (OW) entry limits what the owner of an object gets from
// ownership alone. Without it, an owner implicitly holds READ_CONTROL and
// WRITE_DAC and can rewrite the DACL; with it, the owner of the directory
// or of any file inside receives only READ_CONTROL through ownership, so a
// file owned by another principal (for example the Administrators group,
// the default owner for elevated processes) cannot be opened up by that
// owner. The current user keeps full control through its own entry.
//
// The Administrators group is deliberately not granted access: an
// administrator can still take ownership, but no other account can read
// the encrypted key file or the database through normal access checks.
const privateDirSDDL = "O:%[1]sD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%[1]s)(A;OICI;RC;;;OW)"

// makePrivateDir creates dir with the current user as owner and the
// protected DACL. An existing directory is accepted only if it is a real
// directory (not a junction or symbolic link, whose creator could retarget
// it) owned by the current user, like the Unix version; a directory owned
// by another account (including the Administrators group) is refused,
// because its owner could change its permissions or swap the files inside
// at any time. The DACL of an accepted directory is then replaced by the
// protected one.
func makePrivateDir(dir string) error {
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf(privateDirSDDL, user.String()))
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
	if err := checkOwner(dir, user); err != nil {
		return err
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

// checkOwner returns an error unless dir is owned by user.
func checkOwner(dir string, user *windows.SID) error {
	current, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("profile: reading the owner of %s: %w", dir, err)
	}
	owner, _, err := current.Owner()
	if err != nil {
		return fmt.Errorf("profile: reading the owner of %s: %w", dir, err)
	}
	if owner == nil {
		return fmt.Errorf("profile: %s has no owner", dir)
	}
	if !owner.Equals(user) {
		return fmt.Errorf("profile: %s is owned by another account (%s)", dir, owner)
	}
	return nil
}

// currentUserSID returns the SID of the user running this process.
func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("profile: looking up the current user: %w", err)
	}
	sid, err := user.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("profile: looking up the current user: %w", err)
	}
	return sid, nil
}

// syncDir is a no-op on Windows: NTFS journals the rename itself, and a
// directory handle cannot be flushed through os.File.Sync.
func syncDir(string) error { return nil }
