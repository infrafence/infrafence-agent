package audit

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

var (
	statusRank = map[string]int{StatusFail: 0, StatusWarn: 1, StatusInfo: 2, StatusPass: 3}
	sevRank    = map[string]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevInfo: 4}
)

// Sorted returns the checks worst first: failures, warnings, notes, then
// passes; by severity within each; then by id.
func Sorted(checks []Check) []Check {
	out := append([]Check(nil), checks...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if statusRank[a.Status] != statusRank[b.Status] {
			return statusRank[a.Status] < statusRank[b.Status]
		}
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		return a.ID < b.ID
	})
	return out
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func factsLine(f map[string]string) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+f[k])
	}
	return strings.Join(parts, " ")
}

func count(p *int) string {
	if p == nil {
		return "unknown"
	}
	return strconv.Itoa(*p)
}

// WriteSummary prints the short English summary of r. Every value it
// shows is in the report, and every field of the report is printed by
// the JSON that follows it before an upload.
func WriteSummary(w io.Writer, r *Report) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("InfraFence server audit (read-only: nothing on this server was changed)\n\n")
	p("  System       %s %s, kernel %s, %s\n", r.OS.ID, r.OS.Version, r.OS.Kernel, r.OS.Arch)
	p("  Environment  panel: %s, web server: %s, containers: %s\n", r.Environment.Panel, r.Environment.WebServer, yesNo(r.Environment.Containers))
	p("  Protection   firewall: %s, fail2ban: %s, CSF: %s, InfraFence: %s\n",
		r.Protection.Firewall, yesNo(r.Protection.Fail2ban), yesNo(r.Protection.CSF), yesNo(r.Protection.InfraFence))
	p("  Updates      security: %s, total: %s, reboot required: %s\n",
		count(r.Updates.Security), count(r.Updates.Total), yesNo(r.Updates.RebootRequired))
	a := r.Attacks
	p("\n  Attacks in the last %d hours\n", a.WindowHours)
	p("    SSH  %d failed logins from %d addresses\n", a.SSHFailedLogins, a.SSHUniqueIPs)
	p("    Web  %d suspicious requests from %d addresses\n", a.WebSuspiciousRequests, a.WebUniqueIPs)
	for _, t := range a.TopIPs {
		p("         %-39s %6d  %s\n", t.IP, t.Count, t.Kind)
	}
	var public []string
	for _, l := range r.Listening {
		if l.Public {
			name := strconv.Itoa(l.Port)
			if l.Process != "" {
				name += " (" + l.Process + ")"
			}
			public = append(public, name)
		}
	}
	if len(public) == 0 {
		public = []string{"none"}
	}
	p("\n  Ports open to the internet: %s\n", strings.Join(public, ", "))

	p("\n  Findings, worst first\n")
	passed := 0
	for _, c := range Sorted(r.Checks) {
		if c.Status == StatusPass {
			passed++
			continue
		}
		p("    %-4s  %-8s  %-32s %s\n", strings.ToUpper(c.Status), c.Severity, c.ID, factsLine(c.Facts))
	}
	p("    %d other checks passed.\n", passed)
}
