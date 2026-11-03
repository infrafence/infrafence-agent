package phpconf

import (
	"strconv"
	"strings"
	"testing"
)

func docRootMap(roots []DocRoot) map[string]DocRoot {
	m := map[string]DocRoot{}
	for _, r := range roots {
		m[r.Root] = r
	}
	return m
}

func TestDocRootsApacheDebian(t *testing.T) {
	env := RootedEnv(writeTree(t, map[string]string{
		"/etc/apache2/apache2.conf": "ServerRoot \"/etc/apache2\"\nIncludeOptional mods-enabled/*.load\n" +
			"IncludeOptional conf-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n",
		"/etc/apache2/conf-enabled/extra.conf":        "Include /etc/apache2/custom/\n",
		"/etc/apache2/custom/legacy.conf":             "<VirtualHost *:8080>\n  ServerName legacy.example\n  DocumentRoot /srv/legacy\n</VirtualHost>\n",
		"/etc/apache2/sites-enabled/000-default.conf": "<VirtualHost *:80>\n  DocumentRoot /var/www/html\n</VirtualHost>\n",
		"/etc/apache2/sites-enabled/shop.conf": "<VirtualHost *:80>\n  ServerName shop.example\n  ServerAlias www.shop.example\n" +
			"  DocumentRoot \"/var/www/shop/public/\"\n</VirtualHost>\n" +
			"<VirtualHost *:443>\n  ServerName shop.example\n  DocumentRoot /var/www/shop/public\n  SSLEngine on\n</VirtualHost>\n",
		// Not enabled: never read.
		"/etc/apache2/sites-available/off.conf": "<VirtualHost *:80>\n  DocumentRoot /var/www/off\n</VirtualHost>\n",
		// A variable the agent can't resolve.
		"/etc/apache2/sites-enabled/var.conf":       "<VirtualHost *:80>\n  DocumentRoot ${APACHE_ROOT}/x\n</VirtualHost>\n",
		"/etc/apache2/sites-enabled/commented.conf": "#<VirtualHost *:80>\n#  DocumentRoot /var/www/commented\n#</VirtualHost>\n",
	}))
	got := docRootMap(DocRoots(env))
	for _, want := range []string{"/var/www/html", "/var/www/shop/public", "/srv/legacy"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %+v", want, got)
		}
	}
	for _, not := range []string{"/var/www/off", "/var/www/commented"} {
		if _, ok := got[not]; ok {
			t.Errorf("%s should not be listed", not)
		}
	}
	if len(got) != 3 {
		t.Errorf("roots = %+v", got)
	}
	if n := got["/var/www/shop/public"].Names; len(n) == 0 || n[0] != "shop.example" {
		t.Errorf("shop names = %v", n)
	}
}

func TestDocRootsApacheRHELAndCPanel(t *testing.T) {
	env := RootedEnv(writeTree(t, map[string]string{
		"/etc/httpd/conf/httpd.conf":  "ServerRoot \"/etc/httpd\"\nDocumentRoot \"/var/www/html\"\nIncludeOptional conf.d/*.conf\n",
		"/etc/httpd/conf.d/site.conf": "<VirtualHost *:80>\n  ServerName two.example\n  DocumentRoot /var/www/two\n</VirtualHost>\n",
		// cPanel EA4: one file with every account's virtual hosts.
		"/etc/apache2/conf/httpd.conf": "Include \"/etc/apache2/conf.d/*.conf\"\n" +
			"<VirtualHost 10.0.0.1:80>\n  ServerName alice.example\n  DocumentRoot /home/alice/public_html\n</VirtualHost>\n" +
			"<VirtualHost 10.0.0.1:80>\n  ServerName blog.alice.example\n  DocumentRoot /home/alice/blog.alice.example\n</VirtualHost>\n",
		"/etc/apache2/conf.d/includes.conf": "# nothing\n",
	}))
	got := docRootMap(DocRoots(env))
	for _, want := range []string{"/var/www/html", "/var/www/two", "/home/alice/public_html", "/home/alice/blog.alice.example"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %+v", want, got)
		}
	}
}

func TestDocRootsNginx(t *testing.T) {
	env := RootedEnv(writeTree(t, map[string]string{
		"/etc/nginx/nginx.conf":          "http {\n  include /etc/nginx/conf.d/*.conf;\n  include /etc/nginx/sites-enabled/*;\n}\n",
		"/etc/nginx/conf.d/default.conf": "server {\n  listen 80 default_server;\n  root /usr/share/nginx/html;\n}\n",
		"/etc/nginx/sites-enabled/a": "server {\n  server_name a.example www.a.example;\n  root /var/www/a;\n" +
			"  location /static/ { root /var/www/a-static; }\n  location ~ \\.php$ { fastcgi_pass unix:/run/php.sock; }\n}\n" +
			"server { server_name b.example; root \"/var/www/b\"; }\n",
		"/etc/nginx/sites-enabled/c": "server {\n  server_name c.example;\n  set $base /var/www/c;\n  root $base/public;\n}\n",
	}))
	got := docRootMap(DocRoots(env))
	for _, want := range []string{"/usr/share/nginx/html", "/var/www/a", "/var/www/a-static", "/var/www/b"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %+v", want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("roots = %+v", got)
	}
	if n := got["/var/www/b"].Names; len(n) != 1 || n[0] != "b.example" {
		t.Errorf("b names = %v", n)
	}
}

func TestDocRootsOpenLiteSpeed(t *testing.T) {
	env := RootedEnv(writeTree(t, map[string]string{
		"/usr/local/lsws/conf/httpd_config.conf": "serverName lsws\n" +
			"virtualhost Example {\n  vhRoot                  Example/\n  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhconf.conf\n  allowSymbolLink 1\n}\n" +
			"virtualhost shop.example {\n  vhRoot /home/shop.example\n  configFile $SERVER_ROOT/conf/vhosts/shop.example/vhost.conf\n}\n" +
			"listener Default {\n  address *:8088\n  map Example *\n}\n",
		"/usr/local/lsws/conf/vhosts/Example/vhconf.conf":     "docRoot                   $VH_ROOT/html/\nindex  {\n  indexFiles index.html\n}\n",
		"/usr/local/lsws/conf/vhosts/shop.example/vhost.conf": "docRoot $VH_ROOT/public_html\nvhDomain shop.example\nvhAliases www.shop.example\n",
		// CyberPanel layout, not in the main file.
		"/usr/local/lsws/conf/vhosts/blog.example/vhost.conf": "docRoot /home/blog.example/public_html\n",
	}))
	got := docRootMap(DocRoots(env))
	// "Example/" is relative to the server root.
	for _, want := range []string{"/usr/local/lsws/Example/html", "/home/shop.example/public_html", "/home/blog.example/public_html"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %+v", want, got)
		}
	}
	if n := got["/home/shop.example/public_html"].Names; len(n) != 2 || n[0] != "shop.example" {
		t.Errorf("shop names = %v", n)
	}
}

func TestDocRootsLiteSpeedXML(t *testing.T) {
	env := RootedEnv(writeTree(t, map[string]string{
		"/usr/local/lsws/conf/httpd_config.xml": "<httpServerConfig>\n<virtualHostList>\n<virtualHost>\n  <name>one</name>\n" +
			"  <vhRoot>/srv/one/</vhRoot>\n  <configFile>$VH_ROOT/conf/vhconf.xml</configFile>\n</virtualHost>\n</virtualHostList>\n</httpServerConfig>\n",
		"/srv/one/conf/vhconf.xml": "<virtualHostConfig>\n  <docRoot>$VH_ROOT/html/</docRoot>\n</virtualHostConfig>\n",
	}))
	if _, ok := docRootMap(DocRoots(env))["/srv/one/html"]; !ok {
		t.Errorf("roots = %+v", DocRoots(env))
	}
}

func TestDocRootsPlesk(t *testing.T) {
	env := RootedEnv(writeTree(t, map[string]string{
		"/var/www/vhosts/example.com/httpdocs/index.php":                  "<?php",
		"/var/www/vhosts/example.com/shop.example.com/index.php":          "<?php",
		"/var/www/vhosts/example.com/logs.old/access_log":                 "",
		"/var/www/vhosts/old.example/subdomains/blog/httpdocs/index.html": "",
		"/var/www/vhosts/system/example.com/conf/httpd.conf": "<VirtualHost 10.0.0.1:80>\n  ServerName \"example.com\"\n" +
			"  DocumentRoot \"/var/www/vhosts/example.com/httpdocs\"\n</VirtualHost>\n",
		"/var/www/vhosts/system/example.com/conf/nginx.conf": "server {\n  server_name example.com;\n  root \"/var/www/vhosts/example.com/httpdocs\";\n}\n",
	}))
	got := docRootMap(DocRoots(env))
	for _, want := range []string{"/var/www/vhosts/example.com/httpdocs", "/var/www/vhosts/example.com/shop.example.com", "/var/www/vhosts/old.example/subdomains/blog/httpdocs"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %+v", want, got)
		}
	}
	if _, ok := got["/var/www/vhosts/example.com/logs.old"]; ok {
		t.Error("a directory with no site in it is not a document root")
	}
	if n := got["/var/www/vhosts/old.example/subdomains/blog/httpdocs"].Names; len(n) != 1 || n[0] != "blog.old.example" {
		t.Errorf("subdomain names = %v", n)
	}
}

func TestDocRootsBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < docRootMax+50; i++ {
		b.WriteString("server { root /var/www/s" + strconv.Itoa(i) + "; }\n")
	}
	env := RootedEnv(writeTree(t, map[string]string{
		"/etc/nginx/nginx.conf":         "include /etc/nginx/sites-enabled/*;\n",
		"/etc/nginx/sites-enabled/many": b.String(),
	}))
	if n := len(DocRoots(env)); n != docRootMax {
		t.Errorf("roots = %d, want the cap %d", n, docRootMax)
	}
}
