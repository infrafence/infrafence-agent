//go:build !linux

package audit

// LowerPriority does nothing outside Linux (the audit is for Linux
// servers; other systems only build it for the tests).
func LowerPriority() {}
