package watcher

import (
	"reflect"
	"testing"
)

func TestNginxSiteRoots(t *testing.T) {
	dump := `# configuration file /etc/nginx/nginx.conf:
http {
    server {
        listen 80 default_server;
        server_name _;
        root /var/www/html;
    }
    server {
        listen 80;
        server_name example.com www.example.com;
        root /var/www/example/public;
        location /static/ {
            root /srv/static;
        }
    }
    server {
        listen 443 ssl;
        server_name "shop.example.org";
        root "/var/www/vhosts/shop.example.org/httpdocs";
    }
    server {
        server_name redirect.example.com;
        return 301 https://example.com$request_uri;
    }
    server {
        server_name dyn.example.com;
        root /var/www/$host;
    }
    server {
        server_name rel.example.com;
        root html;
    }
}
`
	got := nginxSiteRoots(parseNginxBlocks(dump))
	want := []SiteRoot{
		{Names: []string{"example.com", "www.example.com"}, Root: "/var/www/example/public"},
		{Names: []string{"shop.example.org"}, Root: "/var/www/vhosts/shop.example.org/httpdocs"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestApacheDocumentRoot(t *testing.T) {
	conf := `<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot "/var/www/example"
</VirtualHost>
<VirtualHost *:80>
    ServerName env.example.com
    DocumentRoot ${APACHE_ROOT}/env
</VirtualHost>
<VirtualHost _default_:80>
    documentroot /var/www/html
</VirtualHost>
`
	vh := parseApacheVhosts(conf)
	if len(vh) != 3 {
		t.Fatalf("got %d vhosts", len(vh))
	}
	if vh[0].docRoot != "/var/www/example" || !reflect.DeepEqual(vh[0].serverNames, []string{"example.com", "www.example.com"}) {
		t.Errorf("vhost 0: %+v", vh[0])
	}
	if vh[1].docRoot != "" {
		t.Errorf("a root with a variable is not a literal path: %q", vh[1].docRoot)
	}
	if vh[2].docRoot != "/var/www/html" || len(vh[2].serverNames) != 0 {
		t.Errorf("vhost 2: %+v", vh[2])
	}
}
