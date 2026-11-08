//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/Aepzie/qchat/internal/server"
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
	for _, path := range []string{dir, filepath.Join(dir, keyFileName), filepath.Join(dir, certFileName), filepath.Join(dir, configFileName), filepath.Join(dir, server.DefaultDatabase), filepath.Dir(filepath.Join(dir, server.DefaultDatabase))} {
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

func TestInitServiceAccountGetsDatabaseWriteAccess(t *testing.T) {
	const localService = "S-1-5-19"
	dir, _ := initDataDir(t, "--service-account", localService)
	dbPath := filepath.Join(dir, server.DefaultDatabase)
	const modify = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.DELETE
	const forbidden = windows.WRITE_DAC | windows.WRITE_OWNER | fileDeleteChild | windows.GENERIC_ALL
	for _, path := range []string{filepath.Dir(dbPath), dbPath} {
		var found bool
		for _, ace := range allowedACEs(t, path) {
			if aceSID(ace).String() != localService {
				continue
			}
			found = true
			if ace.Mask&modify != modify {
				t.Errorf("%s: service account lacks modify access (mask %#x)", path, ace.Mask)
			}
			if ace.Mask&forbidden != 0 {
				t.Errorf("%s: service account may change permissions (mask %#x)", path, ace.Mask)
			}
			if path != dbPath && ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) == 0 {
				t.Errorf("%s: service account entry is not inheritable", path)
			}
		}
		if !found {
			t.Errorf("%s: no ACE for the service account", path)
		}
	}
	for _, path := range []string{dir, filepath.Join(dir, configFileName), filepath.Join(dir, certFileName)} {
		for _, ace := range allowedACEs(t, path) {
			if aceSID(ace).String() == localService && ace.Mask&broadWriteRights != 0 {
				t.Errorf("%s: service account has write access (mask %#x)", path, ace.Mask)
			}
		}
	}
}

func TestInitRefusesServiceAccountDatabaseInDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	code, _, stderr := runCLI(t, "init", "--data-dir", dir, "--service-account", "S-1-5-19", "--database", "qchat.db")
	if code != 2 || !strings.Contains(stderr, "--database") {
		t.Fatalf("init with database in data dir: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("data directory created although init failed")
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

// serviceAccountACEs returns the access-allowed entries of the DACL of path
// that name sid, inherited ones included.
func serviceAccountACEs(t *testing.T, path, sid string) []*windows.ACCESS_ALLOWED_ACE {
	t.Helper()
	dacl, _, err := readSecurity(t, path).DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: no DACL (%v)", path, err)
	}
	var aces []*windows.ACCESS_ALLOWED_ACE
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && aceSID(ace).String() == sid {
			aces = append(aces, ace)
		}
	}
	return aces
}

func TestInitForceAddsServiceAccountToExistingDatabase(t *testing.T) {
	const localService = "S-1-5-19"
	dir, _ := initDataDir(t)
	dbPath := filepath.Join(dir, server.DefaultDatabase)
	dbDir := filepath.Dir(dbPath)
	if aces := serviceAccountACEs(t, dbDir, localService); len(aces) != 0 {
		t.Fatalf("database directory has %d service account entries before --service-account", len(aces))
	}
	sidecar := filepath.Join(dbDir, "leftover")
	if err := os.WriteFile(sidecar, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for run := range 2 {
		if code, _, stderr := runCLI(t, "init", "--data-dir", dir, "--force", "--service-account", localService); code != 0 {
			t.Fatalf("run %d: init --force --service-account: exit %d, stderr %q", run, code, stderr)
		}
		for _, path := range []string{dbDir, dbPath} {
			aces := serviceAccountACEs(t, path, localService)
			if len(aces) != 1 {
				t.Fatalf("run %d: %s has %d service account entries, want 1", run, path, len(aces))
			}
			if aces[0].Mask != serviceAccountModify {
				t.Errorf("run %d: %s: service account mask %#x, want %#x", run, path, aces[0].Mask, serviceAccountModify)
			}
			if path == dbDir && aces[0].Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
				t.Errorf("run %d: %s: service account entry is not inheritable (flags %#x)", run, path, aces[0].Header.AceFlags)
			}
		}
		allowedACEs(t, dbDir)
		allowedACEs(t, dbPath)
	}
	inherited := serviceAccountACEs(t, sidecar, localService)
	if len(inherited) != 1 || inherited[0].Mask&serviceAccountModify != serviceAccountModify {
		t.Fatalf("existing file in the database directory did not inherit the service account entry: %d entries", len(inherited))
	}
	created := filepath.Join(dbDir, "qchat.db-shm")
	if err := os.WriteFile(created, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if aces := serviceAccountACEs(t, created, localService); len(aces) != 1 {
		t.Fatalf("new file in the database directory has %d service account entries, want 1", len(aces))
	}
}

func TestInitRefusesBroadlyAccessibleExistingDatabase(t *testing.T) {
	dir, _ := initDataDir(t)
	dbPath := filepath.Join(dir, server.DefaultDatabase)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)(A;;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dbPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "init", "--data-dir", dir, "--force", "--service-account", "S-1-5-19")
	if code != 1 || !strings.Contains(stderr, "Users") {
		t.Fatalf("init with a broadly readable database: exit %d, stderr %q", code, stderr)
	}
}

func TestClassifyACE(t *testing.T) {
	tests := []struct {
		aceType byte
		want    aceClass
	}{
		{windows.ACCESS_ALLOWED_ACE_TYPE, aceParsed},
		{accessAllowedCallbackACEType, aceParsed},
		{accessAllowedCompoundACEType, aceOpaqueAllow},
		{accessAllowedObjectACEType, aceOpaqueAllow},
		{accessAllowedCallbackObjectACEType, aceOpaqueAllow},
		{windows.ACCESS_DENIED_ACE_TYPE, aceIgnored},
		{systemAuditACEType, aceIgnored},
		{accessDeniedObjectACEType, aceIgnored},
		{accessDeniedCallbackACEType, aceIgnored},
		{systemMandatoryLabelACEType, aceIgnored},
		{systemAccessFilterACEType, aceIgnored},
		{0x16, aceUnknown},
		{0xff, aceUnknown},
	}
	for _, tt := range tests {
		if got := classifyACE(tt.aceType); got != tt.want {
			t.Errorf("classifyACE(0x%02x) = %d, want %d", tt.aceType, got, tt.want)
		}
	}
}

func TestBroadAccessGrantsFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		sddl string
		want string
	}{
		{"Plain", "D:P(A;;FA;;;OW)(A;;FR;;;BU)", "Users"},
		{"Callback", "D:P(A;;FA;;;OW)(XA;;FR;;;WD;(Member_of {SID(BA)}))", "Everyone"},
		{"Object", "D:P(A;;FA;;;OW)(OA;;FR;bf967aba-0de6-11d0-a285-00aa003049e2;;AU)", "ACE type 0x05"},
		{"CallbackObject", "D:P(A;;FA;;;OW)(ZA;;FR;bf967aba-0de6-11d0-a285-00aa003049e2;;AU;(Member_of {SID(BA)}))", "ACE type 0x0b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString(%q): %v", tt.sddl, err)
			}
			exposed, err := broadAccessGrants(sd, broadReadRights|broadWriteRights)
			if err != nil {
				t.Fatal(err)
			}
			if len(exposed) != 1 || !strings.Contains(exposed[0], tt.want) {
				t.Errorf("broadAccessGrants(%q) = %q, want one entry mentioning %q", tt.sddl, exposed, tt.want)
			}
		})
	}
}

func TestBroadAccessGrantsIgnoresHarmlessEntries(t *testing.T) {
	sddls := []string{
		"D:P(A;;FA;;;OW)(D;;FA;;;WD)",
		"D:P(A;;FA;;;OW)(XA;;FR;;;OW;(Member_of {SID(BA)}))",
	}
	for _, sddl := range sddls {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatalf("SecurityDescriptorFromString(%q): %v", sddl, err)
		}
		exposed, err := broadAccessGrants(sd, broadReadRights|broadWriteRights)
		if err != nil {
			t.Fatal(err)
		}
		if len(exposed) != 0 {
			t.Errorf("broadAccessGrants(%q) = %q, want none", sddl, exposed)
		}
	}
}
