package firewall

import (
	"strings"
	"testing"
)

func TestFilterThreatNets(t *testing.T) {
	AddProtectedIPs("198.51.100.7")
	entries := []string{
		"203.0.113.0/24",  // kept
		"192.0.2.10",      // kept, single IP
		"198.51.100.0/24", // contains a protected IP
		"10.0.0.0/8",      // private
		"1.0.0.0/7",       // broader than /8
		"100.64.5.0/24",   // overlaps the whitelist below
		"2001:db8::/32",   // IPv6: not in the IPv4 set
		"not-an-ip",       // ignored
	}
	got, skipped := filterThreatNets(entries, []string{"100.64.5.9"})
	if strings.Join(got, ",") != "203.0.113.0/24,192.0.2.10/32" {
		t.Errorf("kept: %v", got)
	}
	if skipped != 4 {
		t.Errorf("skipped: got %d want 4", skipped)
	}
}
