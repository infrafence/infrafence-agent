package preflight

import (
	"reflect"
	"testing"
)

func TestSitesNoPanel(t *testing.T) {
	if s := DetectSitesEnv(ubuntu(), ""); s == nil || len(s) != 0 {
		t.Errorf("no panel: %+v", s)
	}
	// A panel whose files are missing breaks nothing either.
	if s := DetectSitesEnv(ubuntu(), "cpanel"); len(s) != 0 {
		t.Errorf("empty cPanel: %+v", s)
	}
}

func TestSitesCPanel(t *testing.T) {
	env := ubuntu()
	env.files["/var/cpanel/users/alice"] = ""
	env.files["/var/cpanel/users/system"] = ""
	env.files["/var/cpanel/users/bob"] = ""
	env.files["/var/cpanel/userdata/alice/main"] = `---
addon_domains:
  shop.com: shop.alice.com
cp_php_magic_include_path.conf: 0
main_domain: alice.com
parked_domains:
  - alice.net
sub_domains:
  - shop.alice.com
  - blog.alice.com
`
	env.files["/var/cpanel/userdata/alice/alice.com"] = "---\ndocumentroot: /home/alice/public_html\nservername: alice.com\n"
	env.files["/var/cpanel/userdata/alice/shop.alice.com"] = "documentroot: /home/alice/shop.com\n"
	env.files["/var/cpanel/userdata/alice/blog.alice.com"] = "documentroot: /home/alice/public_html/blog\n"
	// bob has no userdata: /etc/trueuserdomains is used.
	env.files["/etc/trueuserdomains"] = "alice.com: alice\nbob.org: bob\nbad domain: bob\n../x: ../x\n"
	env.files["/home/bob/public_html"] = ""

	got := DetectSitesEnv(env, "cpanel")
	want := []Site{
		{Account: "alice", Domain: "alice.com", Kind: "main", DocumentRoot: "/home/alice/public_html"},
		{Account: "alice", Domain: "alice.net", Kind: "parked", DocumentRoot: "/home/alice/public_html"},
		{Account: "alice", Domain: "blog.alice.com", Kind: "sub", DocumentRoot: "/home/alice/public_html/blog"},
		{Account: "alice", Domain: "shop.com", Kind: "addon", DocumentRoot: "/home/alice/shop.com"},
		{Account: "bob", Domain: "bob.org", Kind: "main", DocumentRoot: "/home/bob/public_html"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestSitesPleskDatabase(t *testing.T) {
	env := ubuntu()
	env.files["/usr/local/psa/bin/plesk"] = ""
	env.runs["/usr/local/psa/bin/plesk db -Ne "+pleskQuery] = "example.com\t/var/www/vhosts/example.com/httpdocs\texuser\n" +
		"shop.example.com\t/var/www/vhosts/example.com/shop\texuser\n" +
		"other.org\t\t\n" +
		"garbage line\n" +
		"evil.com\t../../etc\troot;x\n"
	got := DetectSitesEnv(env, "plesk")
	want := []Site{
		{Domain: "evil.com", Kind: "site"},
		{Domain: "other.org", Kind: "site"},
		{Account: "exuser", Domain: "example.com", Kind: "site", DocumentRoot: "/var/www/vhosts/example.com/httpdocs"},
		{Account: "exuser", Domain: "shop.example.com", Kind: "site", DocumentRoot: "/var/www/vhosts/example.com/shop"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestSitesPleskFallback(t *testing.T) {
	env := ubuntu()
	env.files["/opt/psa/bin/plesk"] = ""
	env.runs["/opt/psa/bin/plesk bin site --list"] = "example.com\nsecond.org\n"
	env.files["/var/www/vhosts/example.com/httpdocs"] = ""
	got := DetectSitesEnv(env, "plesk")
	want := []Site{
		{Domain: "example.com", Kind: "site", DocumentRoot: "/var/www/vhosts/example.com/httpdocs"},
		{Domain: "second.org", Kind: "site"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestSitesDirectAdmin(t *testing.T) {
	env := ubuntu()
	env.files["/usr/local/directadmin/data/users/carol/domains.list"] = "carol.io\n\n"
	env.files["/home/carol/domains/carol.io/public_html"] = ""
	got := DetectSitesEnv(env, "directadmin")
	want := []Site{{Account: "carol", Domain: "carol.io", Kind: "site", DocumentRoot: "/home/carol/domains/carol.io/public_html"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
}
