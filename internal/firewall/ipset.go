package firewall

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// ipsetAvailable is true when the `ipset` binary is found on the system.
var ipsetAvailable bool
var ipsetOnce sync.Once

// checkIpset detects whether ipset is available on this system.
func checkIpset() bool {
	ipsetOnce.Do(func() {
		_, err := exec.LookPath("ipset")
		ipsetAvailable = err == nil
		if ipsetAvailable {
			log.Println("[firewall] ipset detected — using ipset for bans + country blocks")
		} else {
			log.Println("[firewall] ipset not found — falling back to iptables (limited capacity)")
		}
	})
	return ipsetAvailable
}

// HasIpset returns true if ipset is available on this system.
func HasIpset() bool {
	return checkIpset()
}

// ipsetSetName returns the ipset set name for a country code.
func ipsetSetName(countryCode string) string {
	return fmt.Sprintf("infrafence-geo-%s", strings.ToLower(countryCode))
}

// createIpsetHashNet creates an ipset hash:net set if it doesn't exist.
// maxelem is at least 131072; the United States alone is over 150000
// networks in the DB-IP country database (see netSetMax).
func createIpsetHashNet(name string, maxelem int) error {
	// -exist: no error when the set exists with the same parameters
	out, err := exec.Command("ipset", "create", name, "hash:net",
		"maxelem", strconv.Itoa(maxelem), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset create %s: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// netSetMax is the maxelem of a hash:net set for n entries: 131072, or the
// next power of two that holds them, at most 524288 (the country database
// refuses a country with more than 500,000 networks).
func netSetMax(n int) int {
	m := 131072
	for m < n && m < 524288 {
		m *= 2
	}
	return m
}

// ipsetExists reports whether the set exists.
func ipsetExists(name string) bool {
	return exec.Command("ipset", "list", "-n", name).Run() == nil
}

// flushIpset removes all entries from an ipset set.
func flushIpset(name string) error {
	out, err := exec.Command("ipset", "flush", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset flush %s: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// destroyIpset destroys an ipset set (must be flushed and unlinked from iptables first).
func destroyIpset(name string) error {
	out, err := exec.Command("ipset", "destroy", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset destroy %s: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// populateIpsetBatch adds CIDRs to an ipset using `ipset restore` for maximum speed.
// This is orders of magnitude faster than individual `ipset add` commands.
func populateIpsetBatch(setName string, cidrs []string) error {
	if len(cidrs) == 0 {
		return nil
	}

	var b strings.Builder
	for _, cidr := range cidrs {
		fmt.Fprintf(&b, "add %s %s -exist\n", setName, cidr)
	}

	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = strings.NewReader(b.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset restore for %s (%d CIDRs): %s (%w)",
			setName, len(cidrs), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// createIpsetHashIP creates an ipset hash:ip set for individual IP bans.
func createIpsetHashIP(name string) error {
	out, err := exec.Command("ipset", "create", name, "hash:ip",
		"maxelem", "65536", "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset create %s hash:ip: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetAdd adds a single IP to an ipset set.
func ipsetAdd(setName, ip string) error {
	out, err := exec.Command("ipset", "add", setName, ip, "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset add %s to %s: %s (%w)", ip, setName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetDel removes a single IP from an ipset set.
func ipsetDel(setName, ip string) error {
	out, err := exec.Command("ipset", "del", setName, ip, "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset del %s from %s: %s (%w)", ip, setName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetBatchAdd adds multiple IPs to an ipset using `ipset restore` for speed.
func ipsetBatchAdd(setName string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	var b strings.Builder
	for _, ip := range ips {
		fmt.Fprintf(&b, "add %s %s -exist\n", setName, ip)
	}
	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = strings.NewReader(b.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset batch add to %s (%d IPs): %s (%w)",
			setName, len(ips), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetBatchDel removes multiple IPs from an ipset in one `ipset restore`.
func ipsetBatchDel(setName string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	var b strings.Builder
	for _, ip := range ips {
		fmt.Fprintf(&b, "del %s %s -exist\n", setName, ip)
	}
	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = strings.NewReader(b.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset batch del from %s (%d IPs): %s (%w)",
			setName, len(ips), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetListMembers returns all IPs in an ipset set.
func ipsetListMembers(setName string) []string {
	out, err := exec.Command("ipset", "list", setName).CombinedOutput()
	if err != nil {
		return nil
	}
	var members []string
	inMembers := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "Members:" {
			inMembers = true
			continue
		}
		if inMembers && line != "" {
			members = append(members, line)
		}
	}
	return members
}

// ipsetEntryCount returns how many entries are in a set (for logging).
func ipsetEntryCount(setName string) int {
	out, err := exec.Command("ipset", "list", setName, "-t").CombinedOutput()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Number of entries:") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				var n int
				fmt.Sscanf(parts[3], "%d", &n)
				return n
			}
		}
	}
	return 0
}
