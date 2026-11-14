package scanner

// The read-only checks of Run that the one-shot server audit
// (internal/audit) maps to its stable check ids. Each reads files and
// runs query commands only (sshd -T); none starts a package manager.

// SSHChecks returns the SSH configuration checks (SSH_ROOT_LOGIN,
// SSH_PASSWORD_AUTH, SSH_DEFAULT_PORT, ...).
func SSHChecks() []Finding { return checkSSHConfig() }

// FilePermissionChecks returns the PERM_* checks.
func FilePermissionChecks() []Finding { return checkFilePermissions() }

// UserChecks returns USERS_UID0 and USERS_EMPTY_PW (counts only, in
// Details["count"]: never the account names).
func UserChecks() []Finding { return checkUsers() }

// OSVersionCheck returns VER_OS_EOL.
func OSVersionCheck() []Finding { return checkOSVersion() }

// OSEndOfLife reports whether the release version of the distribution id
// (os-release ID and VERSION_ID) no longer gets security updates.
func OSEndOfLife(id, version string) bool {
	for _, v := range eolVersions[id] {
		if version == v {
			return true
		}
	}
	return false
}
