//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// readSecurity returns the owner and DACL of path.
func readSecurity(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	if sd == nil {
		t.Fatalf("%s has no security descriptor", path)
	}
	return sd
}

// allowedACEs returns the access-allowed entries of the DACL of path.
func allowedACEs(t *testing.T, path string) []*windows.ACCESS_ALLOWED_ACE {
	t.Helper()
	sd := readSecurity(t, path)
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s: DACL is not protected against inheritance (%s)", path, sd)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: no DACL (%v)", path, err)
	}
	var aces []*windows.ACCESS_ALLOWED_ACE
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			t.Errorf("%s: inherited ACE for %s", path, aceSID(ace))
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			aces = append(aces, ace)
		}
	}
	return aces
}

func TestInitAppliesProtectedACL(t *testing.T) {
	dir, _ := initDataDir(t)
	for _, path := range []string{dir, filepath.Join(dir, keyFileName), filepath.Join(dir, certFileName), filepath.Join(dir, configFileName)} {
		for _, ace := range allowedACEs(t, path) {
			if label := broadSIDLabel(aceSID(ace)); label != "" {
				t.Errorf("%s: ACE grants %#x to %s", path, ace.Mask, label)
			}
		}
	}
	if exposure, err := keyFileExposure(filepath.Join(dir, keyFileName)); err != nil || exposure != "" {
		t.Errorf("keyFileExposure = %q, %v; want no exposure", exposure, err)
	}
}

func TestInitServiceAccountGetsReadAccess(t *testing.T) {
	const localService = "S-1-5-19"
	dir, _ := initDataDir(t, "--service-account", localService)
	for _, path := range []string{dir, filepath.Join(dir, keyFileName)} {
		var found bool
		for _, ace := range allowedACEs(t, path) {
			if aceSID(ace).String() != localService {
				continue
			}
			found = true
			if ace.Mask&windows.FILE_READ_DATA == 0 {
				t.Errorf("%s: service account lacks read access (mask %#x)", path, ace.Mask)
			}
			if ace.Mask&broadWriteRights != 0 {
				t.Errorf("%s: service account has write access (mask %#x)", path, ace.Mask)
			}
		}
		if !found {
			t.Errorf("%s: no ACE for the service account", path)
		}
	}
}

func TestInitRejectsBadServiceAccount(t *testing.T) {
	for _, account := range []string{"S-1-5-32-545", "S-1-1-0", `NT SERVICE\qchat-server-test-does-not-exist`, "S-1-bogus"} {
		dir := filepath.Join(t.TempDir(), "data")
		code, _, stderr := runCLI(t, "init", "--data-dir", dir, "--service-account", account)
		if code != 1 || !strings.Contains(stderr, "--service-account") {
			t.Errorf("--service-account %s: exit %d, stderr %q", account, code, stderr)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("--service-account %s: data directory created although init failed", account)
		}
	}
}

func TestInitRefusesBroadlyAccessibleDirectory(t *testing.T) {
	cases := []struct {
		name, sddl, want string
	}{
		{"users read", "D:P(A;OICI;FA;;;OW)(A;OICI;FRFX;;;BU)", "Users"},
		{"everyone write", "D:P(A;OICI;FA;;;OW)(A;OICI;FW;;;WD)", "Everyone"},
		{"authenticated users inherit-only", "D:P(A;OICI;FA;;;OW)(A;OICIIO;GA;;;AU)", "Authenticated Users"},
		{"programdata-like add file", "D:P(A;OICI;FA;;;OW)(A;CI;0x6;;;BU)", "Users"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			attributes, err := securityAttributes(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			name, err := windows.UTF16PtrFromString(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.CreateDirectory(name, attributes); err != nil {
				t.Fatal(err)
			}

			code, _, stderr := runCLI(t, "init", "--data-dir", dir)
			if code != 1 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("init into broad directory: exit %d, stderr %q", code, stderr)
			}
			if _, err := os.Stat(filepath.Join(dir, keyFileName)); err == nil {
				t.Fatal("key written into a broadly accessible directory")
			}
		})
	}
}

func TestInitAcceptsPrivateExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	attributes, err := securityAttributes(protectedDirSDDL)
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateDirectory(name, attributes); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "init", "--data-dir", dir); code != 0 {
		t.Fatalf("init into private existing directory: exit %d, stderr %q", code, stderr)
	}
	for _, ace := range allowedACEs(t, filepath.Join(dir, keyFileName)) {
		if label := broadSIDLabel(aceSID(ace)); label != "" {
			t.Errorf("key ACE grants %#x to %s", ace.Mask, label)
		}
	}
}

func TestKeyFileExposureReportsBroadACL(t *testing.T) {
	dir := t.TempDir()
	protection := &fileProtection{}
	attributes, err := securityAttributes("D:P(A;;FA;;;OW)(A;;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	protection.attributes = attributes
	keyPath := filepath.Join(dir, keyFileName)
	if err := writeFileAtomic(keyPath, []byte("not a key"), protection); err != nil {
		t.Fatal(err)
	}
	exposure, err := keyFileExposure(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exposure, "Users") {
		t.Errorf("keyFileExposure = %q, want a mention of Users", exposure)
	}
}

func TestInitRefusesJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create junction: %v: %s", err, out)
	}
	code, _, stderr := runCLI(t, "init", "--data-dir", link)
	if code != 1 || !strings.Contains(stderr, "junction") {
		t.Fatalf("init into junction: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(target, keyFileName)); err == nil {
		t.Fatal("key written through a junction")
	}
}
