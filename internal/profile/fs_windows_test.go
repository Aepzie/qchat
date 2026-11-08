//go:build windows

package profile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Aepzie/qchat/internal/crypto/vault"
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
	var sawUser, sawOwnerRights bool
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
		case sid.IsWellKnown(windows.WinCreatorOwnerRightsSid):
			sawOwnerRights = true
			if ace.Mask != windows.READ_CONTROL {
				t.Errorf("%s: OWNER RIGHTS entry grants %#x, want READ_CONTROL only", path, ace.Mask)
			}
		default:
			t.Errorf("%s: ACE type %d grants %#x to %s", path, ace.Header.AceType, ace.Mask, sid)
		}
	}
	if !sawUser {
		t.Errorf("%s: current user has no access entry (%s)", path, sd)
	}
	if !sawOwnerRights {
		t.Errorf("%s: no OWNER RIGHTS entry (%s)", path, sd)
	}
}

// checkOwnedByUser verifies that path is owned by the current user.
func checkOwnedByUser(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil || !owner.Equals(user) {
		t.Errorf("%s: owner %v, want the current user %s", path, owner, user)
	}
}

func TestPrivateDirACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profile")
	p := create(t, dir)
	p.Close()
	checkPrivateACL(t, dir, true)
	checkOwnedByUser(t, dir)
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

func TestPrivateDirRefusesForeignOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil)
	if err != nil {
		t.Skipf("cannot hand the directory to another owner without privileges: %v", err)
	}
	if err := makePrivateDir(dir); err == nil {
		t.Fatal("makePrivateDir accepted a directory owned by Administrators")
	}
	if _, err := Create(dir, testPassphrase, "Alice", vault.TestParams()); err == nil {
		t.Fatal("Create accepted a directory owned by Administrators")
	}
	if Exists(dir) {
		t.Error("Create wrote a key file into a foreign directory")
	}
}
