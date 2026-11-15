package uci

import "testing"

func TestParse(t *testing.T) {
	m := Parse([]byte("dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].confdir='/tmp/dnsmasq.d'\ndhcp.lan=dhcp\ndhcp.lan.dhcp_option='6,1.1.1.1' '3,192.168.1.1'\ninfrafence.main.server_url='https://example.com/it'\\''s'\n"))
	if v, ok := First(m, "dhcp", "dnsmasq", "confdir"); !ok || v != "/tmp/dnsmasq.d" {
		t.Errorf("confdir = %q %v", v, ok)
	}
	if m["dhcp.lan.dhcp_option"] != "6,1.1.1.1 3,192.168.1.1" {
		t.Errorf("list = %q", m["dhcp.lan.dhcp_option"])
	}
	if m["infrafence.main.server_url"] != "https://example.com/it's" {
		t.Errorf("escaped = %q", m["infrafence.main.server_url"])
	}
	m = Parse([]byte("firewall.cfg01e63d=defaults\nfirewall.cfg01e63d.flow_offloading='1'\n"))
	if v, _ := First(m, "firewall", "defaults", "flow_offloading"); v != "1" {
		t.Errorf("named = %q", v)
	}
}
