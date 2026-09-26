package preflight

import (
	"strings"
	"testing"
)

func TestEveryPanelIsDetectedByItsMarkers(t *testing.T) {
	for _, d := range panelDefs {
		for _, m := range d.markers {
			e := ubuntu()
			e.files[m] = ""
			if got := detectPanel(e); got.ID != d.id {
				t.Errorf("marker %s: detected %q, want %q", m, got.ID, d.id)
			}
		}
	}
	if p := detectPanel(ubuntu()); p.Found() {
		t.Errorf("plain host detected %+v", p)
	}
}

func TestVirtualminBeforeWebmin(t *testing.T) {
	e := ubuntu()
	e.files["/etc/webmin/miniserv.conf"] = ""
	e.files["/etc/webmin/virtual-server"] = ""
	e.files["/etc/webmin/version"] = "2.202\n"
	if p := detectPanel(e); p.ID != "virtualmin" || p.Version != "2.202" {
		t.Errorf("got %+v", p)
	}
	delete(e.files, "/etc/webmin/virtual-server")
	if p := detectPanel(e); p.ID != "webmin" {
		t.Errorf("plain Webmin: got %+v", p)
	}
}

func TestPanelVersions(t *testing.T) {
	cases := []struct {
		files map[string]string
		runs  map[string]string
		id    string
		want  string
	}{
		{map[string]string{"/usr/local/cpanel": "", "/usr/local/cpanel/version": "11.122.0.28\n"}, nil, "cpanel", "11.122.0.28"},
		{map[string]string{"/usr/local/psa": "", "/usr/local/psa/version": "18.0.65 Ubuntu 22.04 1800241015.10"}, nil, "plesk", "18.0.65"},
		{map[string]string{"/usr/local/hestia": "", "/usr/local/hestia/conf/hestia.conf": "BACKEND_PORT='8083'\nVERSION='1.8.11'\n"}, nil, "hestiacp", "1.8.11"},
		{map[string]string{"/usr/local/directadmin": ""}, map[string]string{"/usr/local/directadmin/directadmin v": "DirectAdmin v.1.662 55ab8d0e"}, "directadmin", "1.662"},
		// Unreadable or odd content: no version rather than garbage.
		{map[string]string{"/usr/local/cpanel": "", "/usr/local/cpanel/version": "<html>error</html>"}, nil, "cpanel", ""},
		{map[string]string{"/etc/easypanel": ""}, nil, "easypanel", ""},
	}
	for _, c := range cases {
		e := ubuntu()
		for k, v := range c.files {
			e.files[k] = v
		}
		for k, v := range c.runs {
			e.runs[k] = v
		}
		if p := detectPanel(e); p.ID != c.id || p.Version != c.want {
			t.Errorf("%s: got %+v, want version %q", c.id, p, c.want)
		}
	}
}

func TestNewPanelsVetoWebserverChanges(t *testing.T) {
	e := ubuntu()
	e.files["/etc/easypanel"] = ""
	r := ScanEnv(e)
	if r.Decisions.WebserverChangesSafe || !strings.Contains(r.Decisions.WebserverChangesReason, "Easypanel") {
		t.Errorf("Easypanel must veto web server changes: %+v", r.Decisions)
	}
	if r.Facts["panel"] != "Easypanel" {
		t.Errorf("fact panel = %q", r.Facts["panel"])
	}
}
