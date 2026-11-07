//go:build windows

package profile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkPrivateACL verifies that path has a DACL granting access only to
// SYSTEM and the current user, and that for the directory itself the DACL
// is protected against inheritance from the parent.
func checkPrivateACL(t *testing.T, path string, wantProtected bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if wantProtected && control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s: DACL is not protected (%s)", path, sd)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: no DACL (%v)", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	var sawUser bool
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(user.User.Sid):
			sawUser = true
		case sid.IsWellKnown(windows.WinLocalSystemSid):
		default:
			t.Errorf("%s: ACE type %d grants %#x to %s", path, ace.Header.AceType, ace.Mask, sid)
		}
	}
	if !sawUser {
		t.Errorf("%s: current user has no access entry (%s)", path, sd)
	}
}

func TestPrivateDirACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profile")
	p := create(t, dir)
	p.Close()
	checkPrivateACL(t, dir, true)
	for _, name := range []string{KeyFileName, DBFileName} {
		checkPrivateACL(t, filepath.Join(dir, name), false)
	}
}

func TestPrivateDirACLExistingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "precreated")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	p := create(t, dir)
	p.Close()
	checkPrivateACL(t, dir, true)
	checkPrivateACL(t, filepath.Join(dir, KeyFileName), false)
}
