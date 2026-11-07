//go:build windows

package serverdb

// restrictFile does nothing on Windows: the database file and its -wal and
// -shm companions inherit the ACL of their directory, which the caller must
// have protected.
func restrictFile(string) error { return nil }
