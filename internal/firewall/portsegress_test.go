package firewall

import (
	"reflect"
	"strings"
	"testing"
)

func TestPortsEgressRules(t *testing.T) {
	s := &fwState{closedPorts: []int{6379, 9200}, egress: []string{"185.1.2.3", "198.51.100.8"}}

	ports, egress := s.portsEgressRules(true)
	if ports[0] != "-A INFRAFENCE-PORTS -i lo -j RETURN" {
		t.Fatalf("loopback must be exempt first: %v", ports)
	}
	joined := strings.Join(ports, "\n")
	for _, want := range []string{
		"-A INFRAFENCE-PORTS -s 10.0.0.0/8 -j RETURN",
		"-A INFRAFENCE-PORTS -s 172.16.0.0/12 -j RETURN",
		"-A INFRAFENCE-PORTS -p tcp -m conntrack --ctstate NEW --ctorigdstport 6379 -j DROP",
		"-A INFRAFENCE-PORTS -p tcp -m conntrack --ctstate NEW --ctorigdstport 9200 -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	if !reflect.DeepEqual(egress, []string{"-A INFRAFENCE-EGRESS -m set --match-set infrafence-egress dst -j DROP"}) {
		t.Errorf("ipset egress: %v", egress)
	}
	_, egress = s.portsEgressRules(false)
	if !reflect.DeepEqual(egress, []string{"-A INFRAFENCE-EGRESS -d 185.1.2.3/32 -j DROP", "-A INFRAFENCE-EGRESS -d 198.51.100.8/32 -j DROP"}) {
		t.Errorf("iptables egress: %v", egress)
	}

	empty := &fwState{}
	if p, e := empty.portsEgressRules(true); p != nil || e != nil {
		t.Errorf("empty state renders rules: %v %v", p, e)
	}
}

// The jumps to both chains come right after the allow-list RETURN, so
// allow-listed sources are never affected by a closed port.
func TestSubJumpsAfterAllowList(t *testing.T) {
	s := &fwState{allow: []string{"198.51.100.0/24"}, bans: map[string]bool{"203.0.113.5": true}}
	for _, ipset := range []bool{true, false} {
		main, _ := s.desiredRules(ipset)
		lastReturn, ports, egress, firstDrop := -1, -1, -1, -1
		for i, l := range main {
			switch {
			case strings.HasSuffix(l, "-j RETURN"):
				lastReturn = i
			case l == "-A INFRAFENCE -j INFRAFENCE-PORTS":
				ports = i
			case l == "-A INFRAFENCE -j INFRAFENCE-EGRESS":
				egress = i
			case strings.HasSuffix(l, "-j DROP") && firstDrop < 0:
				firstDrop = i
			}
		}
		if lastReturn < 0 || ports != lastReturn+1 || egress != ports+1 || firstDrop < egress {
			t.Errorf("ipset=%v: order wrong:\n%s", ipset, strings.Join(main, "\n"))
		}
	}
}

func TestEgressRefusal(t *testing.T) {
	AddProtectedIPs("203.0.113.200")
	t.Cleanup(func() {
		protMu.Lock()
		delete(protectedIPs, "203.0.113.200")
		protMu.Unlock()
	})
	s := &fwState{allow: []string{"198.51.100.0/24"}}
	for ip, want := range map[string]string{
		"185.1.2.3":     "",
		"nope":          "invalid",
		"2001:db8::1":   "ipv6_unsupported",
		"10.0.0.1":      "private_target",
		"192.168.1.1":   "private_target",
		"100.64.1.1":    "private_target",
		"127.0.0.1":     "private_target",
		"0.0.0.0":       "private_target",
		"224.0.0.1":     "private_target",
		"198.51.100.20": "allowlisted_target",
		"203.0.113.200": "allowlisted_target",
	} {
		if got := s.egressRefusal(ip); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
}

func TestMayAcceptOurChains(t *testing.T) {
	for _, l := range []string{
		"-A OUTPUT -m comment --comment infrafence-egress -j INFRAFENCE-EGRESS",
		"-A INFRAFENCE -j INFRAFENCE-PORTS",
	} {
		if mayAccept(l) {
			t.Errorf("%s: our chains never accept", l)
		}
	}
}
