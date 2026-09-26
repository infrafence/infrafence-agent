package preflight

import "strings"

// LiteSpeedRoot is where both LiteSpeed editions install.
const LiteSpeedRoot = "/usr/local/lsws"

// LiteSpeed describes a LiteSpeed installation.
type LiteSpeed struct {
	// Edition is "enterprise" (LiteSpeed Web Server, a drop-in Apache
	// replacement that reads Apache's configuration) or "openlitespeed"
	// (its own configuration format). Empty when not installed.
	Edition string
	Version string
	// Running: LiteSpeed is serving the sites. On cPanel/Plesk it can be
	// installed and switched off in favour of Apache.
	Running bool
}

// Installed reports whether LiteSpeed is installed.
func (l LiteSpeed) Installed() bool { return l.Edition != "" }

// Name is the web server name the agent reports: "litespeed" for the
// Enterprise edition, "openlitespeed" otherwise.
func (l LiteSpeed) Name() string {
	if l.Edition == "enterprise" {
		return "litespeed"
	}
	return l.Edition
}

// DetectLiteSpeed inspects the current host.
func DetectLiteSpeed() LiteSpeed { return detectLiteSpeed(hostEnv{}) }

func detectLiteSpeed(env Env) LiteSpeed {
	var l LiteSpeed
	switch {
	case env.Exists(LiteSpeedRoot + "/bin/openlitespeed"):
		l.Edition = "openlitespeed"
	case env.Exists(LiteSpeedRoot+"/bin/lshttpd") || env.Exists(LiteSpeedRoot+"/bin/litespeed"):
		l.Edition = "enterprise"
	default:
		return l
	}
	if v, err := env.ReadFile(LiteSpeedRoot + "/VERSION"); err == nil {
		l.Version = strings.TrimSpace(v)
	}
	if env.LookPath("pgrep") {
		for _, p := range []string{"litespeed", "lshttpd", "openlitespeed"} {
			if out, err := env.Run("pgrep", "-x", p); err == nil && out != "" {
				l.Running = true
				break
			}
		}
	}
	return l
}
