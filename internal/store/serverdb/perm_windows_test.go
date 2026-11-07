//go:build windows

package serverdb

import (
	"context"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// markedDirSDDL is the ACL qchat-server init gives the data directory (full
// control for SYSTEM, Administrators and the owner, no inheritance from the
// parent) plus a read-only entry for LOCAL SERVICE, the way
// --service-account adds one. The extra entry marks the ACL, so the test can
// tell that the database files inherited it rather than some other ACL that
// grants the same well-known accounts.
const (
	localServiceSID = "S-1-5-19"
	ownerRightsSID  = "S-1-3-4"
	markedDirSDDL   = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;FRFX;;;" + localServiceSID + ")"
)

func createMarkedDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	sd, err := windows.SecurityDescriptorFromString(markedDirSDDL)
	if err != nil {
		t.Fatal(err)
	}
	attributes := &windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateDirectory(name, attributes); err != nil {
		t.Fatal(err)
	}
	return dir
}

// checkInheritedProtection fails unless every entry in the DACL of path was
// inherited, the marker entry is among them, and no entry grants access to
// anyone but SYSTEM, Administrators, OWNER RIGHTS, the current user or the
// marker account (read-only).
func checkInheritedProtection(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: no DACL (%v)", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(path)
	var marked bool
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			t.Errorf("%s: ACE for %s is not inherited from the data directory", base, sid)
		}
		switch {
		case sid.String() == localServiceSID:
			marked = true
			if ace.Mask&(windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.WRITE_DAC|windows.DELETE) != 0 {
				t.Errorf("%s: marker ACE grants write access (%#x)", base, ace.Mask)
			}
		case sid.IsWellKnown(windows.WinLocalSystemSid),
			sid.IsWellKnown(windows.WinBuiltinAdministratorsSid),
			sid.String() == ownerRightsSID,
			sid.Equals(user.User.Sid):
		default:
			t.Errorf("%s: ACE grants %#x to %s", base, ace.Mask, sid)
		}
	}
	if !marked {
		t.Errorf("%s: DACL lacks the entry of the data directory; it was not inherited", base)
	}
}

func TestDatabaseFilesInheritDataDirectoryACL(t *testing.T) {
	dir := createMarkedDir(t)
	path := filepath.Join(dir, "qchat.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.CreateInvite(context.Background(), time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		checkInheritedProtection(t, name)
	}
}
