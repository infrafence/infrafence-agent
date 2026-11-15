package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Finding is a configuration weakness reported to the dashboard. IDs are
// stable: the dashboard translates them and keys its "fixed" state on them.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // critical, high, medium, low
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

// Firmware is the firmware status OPNsense keeps from its last update check.
type Firmware struct {
	Version     string `json:"version,omitempty"`
	Latest      string `json:"latest,omitempty"`
	Updates     int    `json:"updates"`
	Major       string `json:"major,omitempty"`
	LastCheck   string `json:"last_check,omitempty"`
	NeedsReboot bool   `json:"needs_reboot,omitempty"`
	Checked     bool   `json:"checked"`
}

// ParseFirmware reads the JSON of "configctl firmware product" (the local
// API behind System › Firmware › Status; product_check is the last update
// check, null until one ran).
func ParseFirmware(data []byte) (Firmware, error) {
	var p struct {
		Version string          `json:"product_version"`
		Latest  string          `json:"product_latest"`
		Check   json.RawMessage `json:"product_check"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return Firmware{}, err
	}
	fw := Firmware{Version: p.Version, Latest: p.Latest}
	if len(p.Check) == 0 || string(p.Check) == "null" {
		return fw, nil
	}
	var c struct {
		Upgrade     []json.RawMessage `json:"upgrade_packages"`
		New         []json.RawMessage `json:"new_packages"`
		Reinstall   []json.RawMessage `json:"reinstall_packages"`
		Major       string            `json:"upgrade_major_version"`
		LastCheck   string            `json:"last_check"`
		NeedsReboot string            `json:"needs_reboot"`
	}
	if err := json.Unmarshal(p.Check, &c); err != nil {
		return fw, err
	}
	fw.Checked = true
	fw.Updates = len(c.Upgrade) + len(c.New) + len(c.Reinstall)
	fw.Major = c.Major
	fw.LastCheck = c.LastCheck
	fw.NeedsReboot = c.NeedsReboot == "1"
	return fw, nil
}

// ReadFirmware asks configd for the firmware status (read-only: it reports
// the last check, it starts none).
func ReadFirmware(ctx context.Context) (Firmware, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/local/sbin/configctl", "firmware", "product").Output()
	if err != nil {
		// No fallback to /tmp/pkg_upgrade.json: /tmp is world-writable.
		return Firmware{}, fmt.Errorf("configctl firmware product: %v", err)
	}
	return ParseFirmware(out)
}

// Check returns the findings for the configuration and firmware status
// (fw nil: firmware unknown, not reported).
func Check(c *Config, fw *Firmware) []Finding {
	var out []Finding
	ext := map[string]bool{}
	for _, n := range c.ExternalNames() {
		ext[n] = true
	}

	if r, ok := wanAnyAny(c, ext); ok {
		out = append(out, Finding{ID: "wan_any_any_pass", Severity: "critical",
			Title:  "A WAN rule allows any traffic from the Internet",
			Detail: fmt.Sprintf("Rule %q passes any protocol from any source to any destination on %s.", r.Descr, strings.Join(r.Interface, ",")),
			Fix:    "Firewall › Rules › WAN: remove the rule or restrict its source, destination and port."})
	}
	if listensOn(c.WebGUI.Interfaces, ext) {
		if r, ok := wanPass(c, ext, "tcp", c.WebGUI.Port); ok {
			out = append(out, Finding{ID: "gui_wan_exposed", Severity: "high",
				Title:  "The web GUI is reachable from the Internet",
				Detail: fmt.Sprintf("The GUI listens on the WAN and rule %q passes TCP port %s from any source.", r.Descr, c.WebGUI.Port),
				Fix:    "System › Settings › Administration: listen on LAN only, or restrict the WAN rule to your management addresses (or use a VPN)."})
		}
	}
	if c.SSH.Enabled && listensOn(c.SSH.Interfaces, ext) {
		if r, ok := wanPass(c, ext, "tcp", c.SSH.Port); ok {
			sev := "medium"
			detail := fmt.Sprintf("SSH listens on the WAN and rule %q passes TCP port %s from any source.", r.Descr, c.SSH.Port)
			if c.SSH.PasswordAuth || c.SSH.PermitRoot {
				sev = "high"
				detail += " Password or root login is allowed."
			}
			out = append(out, Finding{ID: "ssh_wan_exposed", Severity: sev, Title: "SSH is reachable from the Internet", Detail: detail,
				Fix: "Restrict the WAN rule to your management addresses, use keys only and disable root login."})
		}
	}

	for _, u := range c.Users {
		if u.Disabled || !u.defaultPassword() {
			continue
		}
		out = append(out, Finding{ID: "default_root_password", Severity: "critical",
			Title:  "The factory default password is still set",
			Detail: fmt.Sprintf("User %q still has the default password.", u.Name),
			Fix:    "System › Access › Users: set a strong password."})
	}
	var admins, no2fa []string
	for _, u := range c.Users {
		if u.Disabled || !u.Admin {
			continue
		}
		admins = append(admins, u.Name)
		if !u.OTP {
			no2fa = append(no2fa, u.Name)
		}
	}
	sort.Strings(no2fa)
	totp := false
	for _, m := range c.WebGUI.AuthModes {
		for _, s := range c.TOTPServers {
			if m == s {
				totp = true
			}
		}
	}
	switch {
	case len(admins) > 0 && !totp:
		out = append(out, Finding{ID: "gui_2fa_off", Severity: "medium",
			Title:  "Logins to the web GUI do not require two-factor authentication",
			Detail: fmt.Sprintf("The GUI authenticates against %s only; %d administrator account(s).", strings.Join(orDefault(c.WebGUI.AuthModes, "Local Database"), ", "), len(admins)),
			Fix:    "System › Access › Servers: add a Local + Timebased One-time Password server, give administrators an OTP seed, then select it under System › Settings › Administration › Authentication."})
	case len(no2fa) > 0:
		out = append(out, Finding{ID: "admin_without_2fa", Severity: "medium",
			Title:  "Administrators without two-factor authentication",
			Detail: "No OTP seed for: " + strings.Join(no2fa, ", ") + ".",
			Fix:    "System › Access › Users: generate an OTP seed for each administrator."})
	}

	if len(c.Backups) == 0 {
		out = append(out, Finding{ID: "no_offbox_backup", Severity: "low",
			Title:  "No automatic off-box configuration backup",
			Detail: "Only the local configuration history is kept: a disk failure loses the firewall's configuration.",
			Fix:    "System › Configuration › Backups: set up Nextcloud, Git or Google Drive backups, or download a backup after each change."})
	}

	if fw != nil {
		switch {
		case !fw.Checked:
			out = append(out, Finding{ID: "firmware_not_checked", Severity: "low",
				Title: "No firmware update check on record", Fix: "System › Firmware › Status: check for updates (and enable the automatic check under Settings)."})
		case fw.Updates > 0:
			out = append(out, Finding{ID: "firmware_updates_pending", Severity: "medium",
				Title:  fmt.Sprintf("%d firmware update(s) pending", fw.Updates),
				Detail: strings.TrimSpace(fmt.Sprintf("Installed %s, latest %s. Last check %s.", fw.Version, fw.Latest, fw.LastCheck)),
				Fix:    "System › Firmware › Status: update (security fixes ship in minor releases)."})
		}
		if fw.Major != "" {
			out = append(out, Finding{ID: "firmware_major_available", Severity: "low",
				Title: "A new major OPNsense release is available", Detail: "Version " + fw.Major + ".",
				Fix: "Read the release notes, then upgrade from System › Firmware."})
		}
	}
	return out
}

func orDefault(v []string, d string) []string {
	if len(v) == 0 {
		return []string{d}
	}
	return v
}

// listensOn: a service bound to ifs (empty: all) is on an external one.
func listensOn(ifs []string, ext map[string]bool) bool {
	if len(ifs) == 0 {
		return true
	}
	for _, i := range ifs {
		if ext[i] {
			return true
		}
	}
	return false
}

// wanRule: an enabled pass rule matching inbound traffic on an external
// interface from any source.
func wanRule(r Rule, ext map[string]bool) bool {
	if !r.Enabled || (r.Action != "" && r.Action != "pass") {
		return false
	}
	if r.Direction != "" && r.Direction != "in" && r.Direction != "any" {
		return false
	}
	onExt := r.Floating && len(r.Interface) == 0
	for _, i := range r.Interface {
		if ext[i] {
			onExt = true
		}
	}
	return onExt && (r.Src == "" || r.Src == "any") && !r.SrcNot
}

func wanAnyAny(c *Config, ext map[string]bool) (Rule, bool) {
	for _, r := range c.Rules {
		if wanRule(r, ext) && (r.Dst == "" || r.Dst == "any") && !r.DstNot && (r.DstPort == "" || r.DstPort == "any") &&
			(r.Proto == "" || r.Proto == "any") {
			return r, true
		}
	}
	return Rule{}, false
}

// wanPass: a WAN rule passing proto/port to the firewall itself.
func wanPass(c *Config, ext map[string]bool, proto, port string) (Rule, bool) {
	for _, r := range c.Rules {
		if !wanRule(r, ext) || r.DstNot {
			continue
		}
		switch r.Dst {
		case "", "any", "(self)", "wanip":
		default:
			if !strings.HasSuffix(r.Dst, "ip") {
				continue
			}
		}
		p := strings.ToLower(r.Proto)
		if p != "" && p != "any" && !strings.Contains(p, proto) {
			continue
		}
		if portMatches(r.DstPort, port) {
			return r, true
		}
	}
	return Rule{}, false
}

func portMatches(spec, port string) bool {
	if spec == "" || spec == "any" {
		return true
	}
	want, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if p, ok := namedPorts[part]; ok {
			part = p
		}
		lo, hi, ok := strings.Cut(strings.ReplaceAll(part, "-", ":"), ":")
		a, err1 := strconv.Atoi(lo)
		if err1 != nil {
			continue // an alias: not resolved
		}
		b := a
		if ok {
			if v, err := strconv.Atoi(hi); err == nil {
				b = v
			}
		}
		if want >= a && want <= b {
			return true
		}
	}
	return false
}

var namedPorts = map[string]string{"http": "80", "https": "443", "ssh": "22", "www": "80"}
