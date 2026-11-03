package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/phpconf"
)

func TestCollectPHPRuntimes(t *testing.T) {
	root := t.TempDir()
	for p, c := range map[string]string{
		"/etc/php/8.3/fpm/php.ini":          "[PHP]\n",
		"/etc/php/8.3/fpm/php-fpm.conf":     "[global]\ninclude=/etc/php/8.3/fpm/pool.d/*.conf\n",
		"/etc/php/8.3/fpm/pool.d/www.conf":  "[www]\nuser = www-data\nlisten = /run/php/php8.3-fpm.sock\n",
		"/etc/php/8.3/fpm/pool.d/shop.conf": "[shop]\nuser = shop\nlisten = 127.0.0.1:9001\n",
		"/etc/php/8.1/fpm/php.ini":          "[PHP]\n",
		"/etc/php/8.1/fpm/php-fpm.conf":     "[global]\ninclude=/etc/php/8.1/fpm/pool.d/*.conf\n",
		"/etc/php/8.1/fpm/pool.d/old.conf":  "[old]\nuser = old\nlisten = /run/php/php8.1-fpm.sock\n",
		"/etc/php/8.3/cli/php.ini":          "",
		"/etc/nginx/nginx.conf":             "http {\n include /etc/nginx/sites-enabled/*;\n}\n",
		"/etc/nginx/sites-enabled/a": "server {\n server_name a.example;\n root /var/www/a;\n location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.3-fpm.sock; }\n}\n" +
			"server {\n server_name legacy.example;\n root /var/www/legacy;\n location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.1-fpm.sock; }\n}\n",
		"/etc/nginx/sites-enabled/shop": "server {\n server_name shop.example;\n root /var/www/shop;\n location ~ \\.php$ { fastcgi_pass 127.0.0.1:9001; }\n}\n",
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := collectPHPRuntimes(phpconf.RootedEnv(root))
	byID := map[string]PHPRuntime{}
	for _, r := range got {
		byID[r.ID] = r
	}
	r83, ok := byID["debian-8.3-fpm"]
	if !ok || r83.Version != "8.3" || r83.Status != "up_to_date" || len(r83.Pools) != 2 {
		t.Fatalf("8.3 = %+v (all %+v)", r83, got)
	}
	pools := map[string]PHPPool{}
	for _, p := range r83.Pools {
		pools[p.Name] = p
	}
	if s := pools["www"].Sites; len(s) != 1 || s[0] != "a.example" {
		t.Errorf("www sites = %v", s)
	}
	if s := pools["shop"].Roots; len(s) != 1 || s[0] != "/var/www/shop" {
		t.Errorf("shop roots = %v", s)
	}
	r81 := byID["debian-8.1-fpm"]
	if r81.Status != "eol" || len(r81.Pools) != 1 || len(r81.Pools[0].Sites) != 1 || r81.Pools[0].Sites[0] != "legacy.example" {
		t.Errorf("8.1 = %+v", r81)
	}
	if _, ok := byID["debian-8.3-cli"]; ok {
		t.Error("the CLI is not a web runtime")
	}
}

func TestPHPStatus(t *testing.T) {
	for v, want := range map[string]string{"7.4.33": "eol", "8.1.2": "eol", "8.2": "outdated", "8.3.14": "up_to_date", "8.4": "up_to_date", "": "unknown"} {
		if got := phpStatus(v); got != want {
			t.Errorf("%q: %s, want %s", v, got, want)
		}
	}
}
