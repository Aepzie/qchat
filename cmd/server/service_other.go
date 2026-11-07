//go:build !windows

package main

import "context"

// runAsService reports that the process is not running under a service
// manager that needs special handling. On Unix-like systems, service
// managers such as systemd stop the server with SIGTERM, which cmdRun
// handles directly.
func runAsService(func(context.Context) error) (bool, error) {
	return false, nil
}
