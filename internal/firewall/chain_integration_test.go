//go:build integration

// Real-firewall tests. They change iptables/ipset, so they only run inside a
// disposable privileged container prepared by scripts/firewall-integration.sh:
// a network namespace "cl" (203.0.113.2) talks to this host (203.0.113.1).
package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	hostIP   = "203.0.113.1"
	clientIP = "203.0.113.2"
	custIP   = "198.51.100.77" // a rule the "customer" owns
)

func sh(t *testing.T, cmd string) string {
	t.Helper()
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", cmd, err, out)
	}
	return strings.TrimSpace(string(out))
}

// canConnect reports whether the client namespace can open a TCP connection
// to the host's test listener.
func canConnect() bool {
	return exec.Command("bash", "-c",
		fmt.Sprintf("ip netns exec cl timeout 2 bash -c 'exec 3<>/dev/tcp/%s/8080'", hostIP)).Run() == nil
}

func mustEnsure(t *testing.T) EnsureResult {
	t.Helper()
	res, err := Ensure()
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	return res
}

func inputRules(t *testing.T) []string {
	lines, _ := currentRules("INPUT")
	return lines
}

func TestFirewallIntegration(t *testing.T) {
	if os.Getenv("INFRAFENCE_FW_IT") != "1" {
		t.Skip("run via scripts/firewall-integration.sh")
	}
	ipset := HasIpset()
	t.Logf("backend: %s, ipset: %v", sh(t, "iptables -V"), ipset)

	ln, err := net.Listen("tcp", hostIP+":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// Pre-existing host state: a customer DROP rule, and an ufw-style chain
	// that ACCEPTs the service port, jumped to from INPUT.
	sh(t, "iptables -A INPUT -s "+custIP+" -j DROP")
	sh(t, "iptables -N ufw-user-input && iptables -A ufw-user-input -p tcp --dport 8080 -j ACCEPT && iptables -A INPUT -j ufw-user-input")
	sh(t, "iptables -N DOCKER-USER && iptables -A DOCKER-USER -j RETURN")
	// Legacy state from an older agent version.
	if ipset {
		sh(t, "ipset create infrafence-bans hash:ip -exist && iptables -A INPUT -m set --match-set infrafence-bans src -j DROP")
	}
	if !canConnect() {
		t.Fatal("baseline: client should connect")
	}
	sh(t, "iptables -A INPUT -s "+clientIP+" -j DROP") // legacy per-IP ban of an agent ban

	Init()
	ApplyBans([]string{clientIP})

	t.Run("legacy INPUT rules migrated, customer rule kept", func(t *testing.T) {
		all := strings.Join(inputRules(t), "\n")
		if strings.Contains(all, "--match-set infrafence-") {
			t.Errorf("legacy set rule still in INPUT:\n%s", all)
		}
		if strings.Contains(all, "-s "+clientIP+"/32 -j DROP") {
			t.Errorf("legacy per-IP agent ban still in INPUT:\n%s", all)
		}
		if !strings.Contains(all, "-s "+custIP+"/32 -j DROP") {
			t.Errorf("customer rule was removed:\n%s", all)
		}
	})

	t.Run("jump sits before the ufw ACCEPT and blocks the banned client", func(t *testing.T) {
		lines := inputRules(t)
		if len(lines) == 0 || lines[0] != jumpLine("INPUT", jumpComment, chainName) {
			t.Fatalf("INFRAFENCE jump is not first:\n%s", strings.Join(lines, "\n"))
		}
		if canConnect() {
			t.Fatal("banned client could connect")
		}
	})

	t.Run("cleanup never touches the customer rule", func(t *testing.T) {
		CleanupStaleBans(map[string]bool{}, map[string]bool{})
		if !strings.Contains(strings.Join(inputRules(t), "\n"), "-s "+custIP+"/32 -j DROP") {
			t.Fatal("customer rule was removed by cleanup")
		}
		if !canConnect() {
			t.Fatal("client should connect after its ban expired")
		}
		if added, err := BanIPOnce(clientIP); err != nil || !added {
			t.Fatalf("re-ban after expiry: added=%v err=%v", added, err)
		}
		if canConnect() {
			t.Fatal("re-banned client could connect")
		}
		// A second detection of a banned IP is not a new ban (no duplicate
		// report), and the ban stays in force.
		if added, err := BanIPOnce(clientIP); err != nil || added {
			t.Fatalf("second ban of the same IP: added=%v err=%v", added, err)
		}
		if canConnect() {
			t.Fatal("client could connect after a repeated ban")
		}
	})

	t.Run("self-heals after INPUT is flushed (ufw/firewalld reload)", func(t *testing.T) {
		// A reload restores the host's own persisted rules, not ours.
		sh(t, "iptables -F INPUT && iptables -A INPUT -s "+custIP+" -j DROP && iptables -A INPUT -j ufw-user-input")
		if !canConnect() {
			t.Fatal("setup: after the flush the client should get through ufw's ACCEPT")
		}
		res := mustEnsure(t)
		if len(res.Repairs) == 0 {
			t.Fatal("Ensure reported no repair")
		}
		if canConnect() {
			t.Fatal("banned client could connect after repair")
		}
	})

	t.Run("self-heals after the chain itself is flushed", func(t *testing.T) {
		sh(t, "iptables -F "+chainName)
		if !canConnect() {
			t.Fatal("setup: client should get through an empty chain")
		}
		res := mustEnsure(t)
		if strings.Join(res.Repairs, ",") != "chain-contents" {
			t.Errorf("repairs = %v, want [chain-contents]", res.Repairs)
		}
		if canConnect() {
			t.Fatal("banned client could connect after repair")
		}
		if res := mustEnsure(t); len(res.Repairs) != 0 {
			t.Errorf("a clean Ensure should repair nothing, got %v", res.Repairs)
		}
	})

	t.Run("DOCKER-USER gets the jump and keeps it", func(t *testing.T) {
		lines, _ := currentRules(dockerChain)
		if len(lines) == 0 || lines[0] != jumpLine(dockerChain, jumpComment, chainName) {
			t.Fatalf("DOCKER-USER jump missing:\n%s", strings.Join(lines, "\n"))
		}
		sh(t, "iptables -F DOCKER-USER && iptables -A DOCKER-USER -j RETURN")
		if res := mustEnsure(t); !strings.Contains(strings.Join(res.Repairs, ","), "jump:"+dockerChain) {
			t.Errorf("DOCKER-USER jump not restored: %v", res.Repairs)
		}
	})

	t.Run("whitelist exempts from bans without opening anything", func(t *testing.T) {
		SetAllowList([]string{clientIP})
		if !canConnect() {
			t.Fatal("whitelisted client should connect")
		}
		for _, l := range inputRules(t) {
			if strings.Contains(l, clientIP) && strings.Contains(l, "ACCEPT") {
				t.Errorf("whitelist added an ACCEPT to INPUT: %s", l)
			}
		}
		SetAllowList(nil)
		if canConnect() {
			t.Fatal("client should be blocked again once removed from the whitelist")
		}
	})

	if ipset {
		t.Run("threat feed blocks, and clears", func(t *testing.T) {
			_ = UnbanIP(clientIP)
			if !canConnect() {
				t.Fatal("setup: unbanned client should connect")
			}
			if _, _, err := ApplyThreatSet([]string{clientIP + "/32"}, nil); err != nil {
				t.Fatal(err)
			}
			if canConnect() {
				t.Fatal("client in the threat feed could connect")
			}
			ClearThreatSet()
			if !canConnect() {
				t.Fatal("client should connect after the feed is cleared")
			}
			sh(t, "ipset destroy "+banSetName+" 2>/dev/null || (iptables -F "+chainName+" && ipset destroy "+banSetName+")")
			if res := mustEnsure(t); !strings.Contains(strings.Join(res.Repairs, ","), "set:"+banSetName) {
				t.Errorf("destroyed ban set not recreated: %v", res.Repairs)
			}
		})
	}

	t.Run("uninstall removes everything InfraFence created, only that", func(t *testing.T) {
		RemoveAll()
		all := sh(t, "iptables -S")
		if strings.Contains(all, chainName) || strings.Contains(all, "infrafence") {
			t.Errorf("leftovers after RemoveAll:\n%s", all)
		}
		if !strings.Contains(all, "-s "+custIP+"/32 -j DROP") || !strings.Contains(all, "ufw-user-input") {
			t.Errorf("RemoveAll touched rules it doesn't own (need %s DROP and ufw-user-input):\n%s", custIP, all)
		}
		if ipset {
			if sets := sh(t, "ipset list -n"); strings.Contains(sets, "infrafence-") {
				t.Errorf("sets left: %s", sets)
			}
		}
	})
}
