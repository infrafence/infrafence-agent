package preflight

import (
	"reflect"
	"testing"
)

func tool(c Coexistence, id string) *Tool {
	for i := range c.Tools {
		if c.Tools[i].ID == id {
			return &c.Tools[i]
		}
	}
	return nil
}

// withSystemctl: the host has /usr/bin/systemctl.
func withSystemctl(env fakeEnv) fakeEnv {
	env.files["/usr/bin/systemctl"] = ""
	return env
}

func TestCoexistencePlainHost(t *testing.T) {
	c := DetectCoexistenceEnv(ubuntu())
	if c.Mode != ModePrimary || len(c.Tools) != 0 || c.Tools == nil {
		t.Errorf("plain host: %+v", c)
	}
}

func TestCoexistenceCPanelStack(t *testing.T) {
	env := withSystemctl(ubuntu())
	env.files["/usr/local/cpanel"] = ""
	env.files["/etc/csf/csf.conf"] = "TESTING = \"0\"\nTCP_IN = \"22,80,443\"\n"
	env.files["/etc/csf/version.txt"] = "14.20\n"
	env.files["/usr/sbin/lfd"] = ""
	env.files["/var/cpanel/hulkd"] = ""
	env.files["/var/cpanel/hulkd/enabled"] = ""
	env.files["/usr/bin/imunify360-agent"] = ""
	env.files["/etc/apache2/conf.d/modsec_vendor_configs/OWASP3"] = ""
	env.files["/etc/apache2/conf.d/modsec_vendor_configs/imunify360-full-apache"] = ""
	env.files["/var/cpanel/modsec_vendors/meta_comodo_apache.yaml"] = ""
	env.runs["/usr/bin/systemctl is-active lfd"] = "active"
	env.runs["/usr/bin/systemctl is-active imunify360"] = "active"

	c := DetectCoexistenceEnv(env)
	if c.Mode != ModeCoexist {
		t.Errorf("mode %q, want coexist", c.Mode)
	}
	csf := tool(c, "csf")
	if csf == nil || !csf.Active || csf.Version != "14.20" || !csf.Firewall || csf.Action == "" || csf.ActionID != "coexist_csf" {
		t.Errorf("csf: %+v", csf)
	}
	if l := tool(c, "lfd"); l == nil || !l.Active {
		t.Errorf("lfd: %+v", l)
	}
	if h := tool(c, "cphulk"); h == nil || !h.Active {
		t.Errorf("cphulk: %+v", h)
	}
	if im := tool(c, "imunify"); im == nil || !im.Active || !im.Firewall {
		t.Errorf("imunify: %+v", im)
	}
	ms := tool(c, "modsecurity")
	if ms == nil || !reflect.DeepEqual(ms.Rulesets, []string{"Comodo WAF", "Imunify360 WAF", "OWASP CRS"}) {
		t.Errorf("modsecurity: %+v", ms)
	}
	for _, tl := range c.Tools {
		if tl.Action == "" {
			t.Errorf("%s has no action text", tl.ID)
		}
	}
}

func TestCoexistencePleskStack(t *testing.T) {
	env := withSystemctl(ubuntu())
	env.files["/usr/local/psa"] = ""
	env.files["/usr/local/psa/var/modules/firewall"] = ""
	env.files["/etc/apache2/modsecurity.d/rules/tortix"] = ""
	env.files["/etc/fail2ban/jail.conf"] = ""
	env.files["/opt/bitninja"] = ""
	env.files["/etc/monarx-agent.conf"] = ""
	env.runs["/usr/bin/systemctl is-active fail2ban"] = "active"
	env.runs["/usr/bin/systemctl is-active psa-firewall"] = "active"
	env.runs["/usr/bin/systemctl is-active monarx-agent"] = "active"

	c := DetectCoexistenceEnv(env)
	if c.Mode != ModeCoexist {
		t.Errorf("mode %q", c.Mode)
	}
	for _, id := range []string{"plesk_firewall", "fail2ban", "bitninja", "monarx"} {
		if tool(c, id) == nil {
			t.Errorf("%s not found", id)
		}
	}
	if b := tool(c, "bitninja"); b.Active {
		t.Errorf("bitninja reported active without its service: %+v", b)
	}
	if m := tool(c, "monarx"); m.Firewall || m.Kind != "malware" || !m.Active {
		t.Errorf("monarx: %+v", m)
	}
	if ms := tool(c, "modsecurity"); ms == nil || !reflect.DeepEqual(ms.Rulesets, []string{"Atomicorp"}) {
		t.Errorf("modsecurity: %+v", ms)
	}
}

func TestCoexistenceInactiveFirewallStaysPrimary(t *testing.T) {
	env := withSystemctl(ubuntu())
	// Installed but not running, and CSF in testing mode: nothing manages
	// the firewall besides InfraFence.
	env.files["/etc/fail2ban/jail.conf"] = ""
	env.files["/etc/csf/csf.conf"] = "TESTING = \"1\"\n"
	c := DetectCoexistenceEnv(env)
	if c.Mode != ModePrimary {
		t.Errorf("mode %q, tools %+v", c.Mode, c.Tools)
	}
	if f := tool(c, "fail2ban"); f == nil || f.Active {
		t.Errorf("fail2ban: %+v", f)
	}
}

func TestCoexistenceModSecurityWithoutVendors(t *testing.T) {
	env := withSystemctl(ubuntu())
	env.files["/etc/modsecurity/modsecurity.conf"] = ""
	c := DetectCoexistenceEnv(env)
	ms := tool(c, "modsecurity")
	if ms == nil || len(ms.Rulesets) != 0 || c.Mode != ModePrimary {
		t.Errorf("modsecurity: %+v mode %s", ms, c.Mode)
	}
}
