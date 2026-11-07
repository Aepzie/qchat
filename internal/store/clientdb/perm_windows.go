//go:build windows

package clientdb

// prepareFile does nothing on Windows. File modes do not map to ACLs there;
// the database file inherits the ACL of its directory, which the caller is
// responsible for restricting to the current user.
func prepareFile(string, bool) error { return nil }
