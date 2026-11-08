//go:build windows

package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows ignores the Unix permission bits Go passes to os.Mkdir and
// os.OpenFile, and a new directory inherits the ACL of its parent: under
// C:\ProgramData that grants every local user read access. init therefore
// creates the data directory and every file in it with an explicit,
// protected ACL (the P flag stops inheritance from the parent) that grants
// full control to SYSTEM, the Administrators group and the owner only.
//
// The owner is not set explicitly: Windows assigns the default owner of the
// account running init, which is the Administrators group for an elevated
// administrator and the user itself otherwise. Forcing Administrators as
// owner would make init fail for an unprivileged user. The OWNER RIGHTS
// entry (OW) gives the owner full control and replaces the implicit
// READ_CONTROL and WRITE_DAC an owner otherwise has.
//
// The account that runs the service needs read access as well. A virtual
// service account such as "NT SERVICE\qchat-server" exists only once the
// service is registered, so init cannot add it by default; --service-account
// adds a read-only entry for it (see deploy/windows/README.md). The
// database directory (db\ by default) is created with the same protected
// ACL, except that the service account may modify it and every file in it:
// SQLite writes the database and creates and deletes its -wal and -shm
// files there.
//
// Running init again with --service-account on an existing database
// directory and file adds the service account's Modify entry to them, once
// they have passed the same checks as an existing data directory, so an
// installation first set up without --service-account can be fixed by
// re-running init --force.
const (
	protectedDirSDDL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
	protectedFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"

	// serviceAccountDirACE and serviceAccountFileACE grant read and
	// execute (list and traverse for the directory), never write, so a
	// compromised server process cannot alter its key or configuration.
	serviceAccountDirACE  = "(A;OICI;FRFX;;;%s)"
	serviceAccountFileACE = "(A;;FRFX;;;%s)"

	// serviceAccountDBDirACE and serviceAccountDBFileACE grant Modify
	// (0x1301bf: read, write, execute and delete, but neither WRITE_DAC,
	// WRITE_OWNER nor FILE_DELETE_CHILD), inherited by every file created
	// in the database directory.
	serviceAccountDBDirACE  = "(A;OICI;0x1301bf;;;%s)"
	serviceAccountDBFileACE = "(A;;0x1301bf;;;%s)"

	// serviceAccountModify is the access mask of serviceAccountDBDirACE
	// and serviceAccountDBFileACE.
	serviceAccountModify windows.ACCESS_MASK = 0x1301bf
)

// fileDeleteChild is FILE_DELETE_CHILD, which golang.org/x/sys/windows does
// not define: on a directory it allows deleting any file inside it.
const fileDeleteChild = 0x40

// Access rights that count as read or write access when checking an ACL.
// An entry granting any of them to a broad group exposes the key.
const (
	broadReadRights  windows.ACCESS_MASK = windows.FILE_READ_DATA | windows.GENERIC_READ | windows.GENERIC_ALL | windows.MAXIMUM_ALLOWED
	broadWriteRights windows.ACCESS_MASK = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | fileDeleteChild |
		windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.MAXIMUM_ALLOWED
)

// broadSIDs are the well-known groups that include every local user, or
// everyone at all. No data directory ACL entry may grant them access.
var broadSIDs = []struct {
	kind  windows.WELL_KNOWN_SID_TYPE
	label string
}{
	{windows.WinWorldSid, "Everyone (S-1-1-0)"},
	{windows.WinAuthenticatedUserSid, "Authenticated Users (S-1-5-11)"},
	{windows.WinInteractiveSid, "INTERACTIVE (S-1-5-4)"},
	{windows.WinBuiltinUsersSid, "Users (S-1-5-32-545)"},
}

// fileProtection holds the security attributes applied to every file init
// writes into the data directory, and to the database directory and file.
type fileProtection struct {
	attributes       *windows.SecurityAttributes
	dbDirAttributes  *windows.SecurityAttributes
	dbFileAttributes *windows.SecurityAttributes
	serviceAccount   *windows.SID
}

// prepareDataDir creates dir with a protected ACL, or verifies that an
// existing dir is safe to hold the key. serviceAccount, if not empty, is an
// account name or SID string that is granted read access to the directory
// and the files written into it.
func prepareDataDir(dir, serviceAccount string, _ io.Writer) (*fileProtection, error) {
	dirSDDL, fileSDDL := protectedDirSDDL, protectedFileSDDL
	dbDirSDDL, dbFileSDDL := protectedDirSDDL, protectedFileSDDL
	var protection fileProtection
	if serviceAccount != "" {
		sid, err := resolveServiceAccount(serviceAccount)
		if err != nil {
			return nil, err
		}
		protection.serviceAccount = sid
		dirSDDL += fmt.Sprintf(serviceAccountDirACE, sid)
		fileSDDL += fmt.Sprintf(serviceAccountFileACE, sid)
		dbDirSDDL += fmt.Sprintf(serviceAccountDBDirACE, sid)
		dbFileSDDL += fmt.Sprintf(serviceAccountDBFileACE, sid)
	}
	var dirAttributes *windows.SecurityAttributes
	for _, entry := range []struct {
		sddl   string
		target **windows.SecurityAttributes
	}{
		{dirSDDL, &dirAttributes},
		{fileSDDL, &protection.attributes},
		{dbDirSDDL, &protection.dbDirAttributes},
		{dbFileSDDL, &protection.dbFileAttributes},
	} {
		attributes, err := securityAttributes(entry.sddl)
		if err != nil {
			return nil, err
		}
		*entry.target = attributes
	}
	if _, err := createProtectedDir(dir, dirAttributes, "data directory"); err != nil {
		return nil, err
	}
	return &protection, nil
}

// prepareDatabaseDir creates the database directory with the protected ACL
// that lets the service account modify the database, or verifies an
// existing directory like the data directory and grants the service
// account, if any, Modify access to it and to the files created in it.
func (p *fileProtection) prepareDatabaseDir(dir string, _ io.Writer) error {
	existed, err := createProtectedDir(dir, p.dbDirAttributes, "database directory")
	if err != nil || !existed || p.serviceAccount == nil {
		return err
	}
	if err := grantModify(dir, p.serviceAccount, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
		return fmt.Errorf("grant the service account access to database directory %s: %w", dir, err)
	}
	return nil
}

// createProtectedDir creates the parents of dir and then dir itself with
// attributes, or verifies that an existing dir is safe to use. It reports
// whether dir already existed.
func createProtectedDir(dir string, attributes *windows.SecurityAttributes, what string) (bool, error) {
	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, dataDirMode); err != nil {
			return false, fmt.Errorf("create %s: %w", what, err)
		}
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return false, fmt.Errorf("create %s: %w", what, err)
	}
	err = windows.CreateDirectory(name, attributes)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return true, checkExistingDataDir(dir)
	default:
		return false, fmt.Errorf("create %s: %w", what, &fs.PathError{Op: "mkdir", Path: dir, Err: err})
	}
}

// grantModify merges an entry granting sid serviceAccountModify into the
// DACL of path, with the given inheritance. Running it again changes
// nothing. The DACL keeps its protection against inheritance from the
// parent, and new inheritable entries propagate to existing children that
// inherit from path.
func grantModify(path string, sid *windows.SID, inheritance uint32) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: serviceAccountModify,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, dacl)
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, merged, nil)
}

// resolveServiceAccount returns the SID of account, given either as a SID
// string such as "S-1-5-80-..." or as an account name. SID strings work on
// every Windows display language; names such as "NT AUTHORITY\LOCAL SERVICE"
// are localized, but "NT SERVICE\<name>" is not.
func resolveServiceAccount(account string) (*windows.SID, error) {
	var sid *windows.SID
	var err error
	if strings.HasPrefix(strings.ToUpper(account), "S-1-") {
		sid, err = windows.StringToSid(account)
	} else {
		sid, _, _, err = windows.LookupSID("", account)
	}
	if err != nil {
		return nil, fmt.Errorf("--service-account %q: %w (a virtual account such as \"NT SERVICE\\%s\" exists only after the service is registered with sc.exe create)", account, err, programName)
	}
	if label := broadSIDLabel(sid); label != "" {
		return nil, fmt.Errorf("--service-account %q is %s, which includes every user; name the account that runs the service", account, label)
	}
	return sid, nil
}

// securityAttributes converts an SDDL string into security attributes for
// CreateDirectory and CreateFile.
func securityAttributes(sddl string) (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, nil
}

// checkExistingDataDir refuses a directory that init did not just create
// unless its owner is SYSTEM, Administrators or the current user, and no
// ACL entry grants read or write access to a broad group. Anyone else who
// owns the directory can change its ACL at any time and read or replace
// the key. A junction or symbolic link is refused as well, because its
// creator can retarget it.
func checkExistingDataDir(dir string) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return &fs.PathError{Op: "stat", Path: dir, Err: err}
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("data directory %s is a junction or symbolic link; pass the real directory instead", dir)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("data directory %s exists and is not a directory", dir)
	}

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read permissions of data directory %s: %w", dir, err)
	}
	if sd == nil {
		return fmt.Errorf("data directory %s has no security descriptor; choose a directory on an NTFS volume", dir)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner of data directory %s: %w", dir, err)
	}
	trusted, err := isTrustedOwner(owner)
	if err != nil {
		return err
	}
	if !trusted {
		return fmt.Errorf("data directory %s is owned by %s, not by SYSTEM, Administrators or the current user, so that account can change its permissions and read or replace the key; delete the directory and run init again, or take ownership first (takeown /F %s /A)", dir, describeSID(owner), dir)
	}
	exposed, err := broadAccessGrants(sd, broadReadRights|broadWriteRights)
	if err != nil {
		return fmt.Errorf("read permissions of data directory %s: %w", dir, err)
	}
	if len(exposed) > 0 {
		return fmt.Errorf("data directory %s grants access to %s, so other users could read or replace the key; delete it and run init again to have it created with restricted permissions, or remove those entries (\"icacls %s\" lists them, including inherited ones)", dir, strings.Join(exposed, ", "), dir)
	}
	return nil
}

// isTrustedOwner reports whether owner is SYSTEM, the Administrators group
// or the user running this process.
func isTrustedOwner(owner *windows.SID) (bool, error) {
	if owner == nil {
		return false, nil
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true, nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("look up current user: %w", err)
	}
	return owner.Equals(user.User.Sid), nil
}

// broadAccessGrants returns the labels of the broad groups to which an
// access-allowed entry in the DACL of sd grants any of rights. Entries that
// apply only to objects created later (inherit-only) count as well. A
// missing or null DACL grants everyone full access.
func broadAccessGrants(sd *windows.SECURITY_DESCRIPTOR, rights windows.ACCESS_MASK) ([]string, error) {
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return []string{"everyone (the object has no access control list)"}, nil
	}
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		return []string{"everyone (the object has a null access control list)"}, nil
	}
	var labels []string
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&rights == 0 {
			continue
		}
		if label := broadSIDLabel(aceSID(ace)); label != "" && !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	return labels, nil
}

// broadSIDLabel returns the label of sid if it is one of broadSIDs, and ""
// otherwise.
func broadSIDLabel(sid *windows.SID) string {
	for _, broad := range broadSIDs {
		if sid.IsWellKnown(broad.kind) {
			return broad.label
		}
	}
	return ""
}

// describeSID returns the account name and SID string of sid, or just the
// SID string if the name cannot be looked up.
func describeSID(sid *windows.SID) string {
	if sid == nil {
		return "nobody"
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain != "" {
		account = domain + `\` + account
	}
	return fmt.Sprintf("%s (%s)", account, sid)
}

// aceSID returns the SID stored in ace, which starts at its SidStart
// field and extends past the end of the Go struct.
func aceSID(ace *windows.ACCESS_ALLOWED_ACE) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- the SID is stored inline in the ACE, starting at SidStart
}

// createTemp creates a new file in dir whose name starts with prefix,
// applying the protected ACL atomically at creation.
func (p *fileProtection) createTemp(dir, prefix string) (*os.File, error) {
	for range 10 {
		path := filepath.Join(dir, prefix+rand.Text())
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, p.attributes,
			windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, &fs.PathError{Op: "create", Path: path, Err: err}
		}
		return os.NewFile(uintptr(handle), path), nil
	}
	return nil, fmt.Errorf("create temporary file in %s: too many name collisions", dir)
}

// keyFileExposure describes how the private key at path is accessible to
// broad groups of users, or returns "" if it is not.
func keyFileExposure(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	if sd == nil {
		return "no access control list", nil
	}
	exposed, err := broadAccessGrants(sd, broadReadRights|broadWriteRights)
	if err != nil {
		return "", err
	}
	if len(exposed) == 0 {
		return "", nil
	}
	return "access control list grants " + strings.Join(exposed, ", "), nil
}

// createDatabaseFile creates an empty database file at path with the
// protected ACL of the database directory, atomically at creation. An
// existing file keeps its content; once it has passed the checks of
// checkExistingDatabaseFile, the service account, if any, is granted
// Modify access to it.
func (p *fileProtection) createDatabaseFile(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, p.dbFileAttributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return p.adoptDatabaseFile(path)
	}
	if err != nil {
		return &fs.PathError{Op: "create", Path: path, Err: err}
	}
	return windows.CloseHandle(handle)
}

// adoptDatabaseFile checks an existing database file and grants the service
// account, if any, Modify access to it.
func (p *fileProtection) adoptDatabaseFile(path string) error {
	if err := checkExistingDatabaseFile(path); err != nil {
		return err
	}
	if p.serviceAccount == nil {
		return nil
	}
	if err := grantModify(path, p.serviceAccount, windows.NO_INHERITANCE); err != nil {
		return fmt.Errorf("grant the service account access to database %s: %w", path, err)
	}
	return nil
}

// checkExistingDatabaseFile refuses an existing database file that is not
// a regular file, is a symbolic link, is owned by an untrusted account or
// grants access to a broad group, for the same reasons as
// checkExistingDataDir.
func checkExistingDatabaseFile(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("database %s is a symbolic link; pass the real file instead", path)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fmt.Errorf("database %s exists and is a directory", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read permissions of database %s: %w", path, err)
	}
	if sd == nil {
		return fmt.Errorf("database %s has no security descriptor; choose a file on an NTFS volume", path)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner of database %s: %w", path, err)
	}
	trusted, err := isTrustedOwner(owner)
	if err != nil {
		return err
	}
	if !trusted {
		return fmt.Errorf("database %s is owned by %s, not by SYSTEM, Administrators or the current user; take ownership first (takeown /F %s /A)", path, describeSID(owner), path)
	}
	exposed, err := broadAccessGrants(sd, broadReadRights|broadWriteRights)
	if err != nil {
		return fmt.Errorf("read permissions of database %s: %w", path, err)
	}
	if len(exposed) > 0 {
		return fmt.Errorf("database %s grants access to %s; remove those entries (\"icacls %s\" lists them, including inherited ones)", path, strings.Join(exposed, ", "), path)
	}
	return nil
}
