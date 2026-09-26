package watcher

import (
	"errors"
	"reflect"
	"testing"
)

// Layouts as written by CyberPanel and by the OpenLiteSpeed one-click images.
const olsServerConf = `
serverName
user                      nobody
errorlog $SERVER_ROOT/logs/error.log {
  logLevel                WARN
  rollingSize             10M
}

accesslog $SERVER_ROOT/logs/access.log {
  rollingSize             10M
  keepDays                30
}

virtualhost example.com {
  vhRoot                  /home/example.com
  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhconf.conf
  allowSymbolLink         1
}

virtualhost wordpress {
  vhRoot                  /var/www/html/
  configFile              conf/vhosts/wordpress/vhconf.conf
}

virtualhost Example {
  vhRoot                  Example/
  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhconf.conf
}

listener Default {
  address                 *:80
  map                     example.com example.com, www.example.com
  map                     wordpress *
}

listener SSL {
  address                 *:443
  secure                  1
  map                     example.com example.com, www.example.com
}
`

const cyberPanelVhost = `
docRoot                   $VH_ROOT/public_html
errorlog $VH_ROOT/logs/$VH_NAME.error_log {
  useServer               0
  logLevel                WARN
}
accesslog $VH_ROOT/logs/$VH_NAME.access_log {
  useServer               0
  logFormat               "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
  logHeaders              5
}
`

const serverLogVhost = `
docRoot $VH_ROOT
accessLog $VH_ROOT/logs/access.log {
  useServer 1
}
`

const exampleVhost = `
docRoot $VH_ROOT/html/
accesslog $VH_ROOT/logs/access.log {
  useServer 0
}
`

func TestParseOpenLiteSpeedLogs(t *testing.T) {
	files := map[string]string{
		"/usr/local/lsws/conf/httpd_config.conf":              olsServerConf,
		"/usr/local/lsws/conf/vhosts/example.com/vhconf.conf": cyberPanelVhost,
		"/usr/local/lsws/conf/vhosts/wordpress/vhconf.conf":   serverLogVhost,
		"/usr/local/lsws/conf/vhosts/Example/vhconf.conf":     exampleVhost,
	}
	read := func(p string) (string, error) {
		if s, ok := files[p]; ok {
			return s, nil
		}
		return "", errors.New("not found")
	}
	got := parseOpenLiteSpeedLogs("/usr/local/lsws", read)
	want := []LogPathInfo{
		{Path: "/home/example.com/logs/example.com.access_log", Domains: []string{"example.com", "www.example.com"}},
		{Path: "/usr/local/lsws/Example/logs/access.log"},
		{Path: "/usr/local/lsws/logs/access.log"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestParseOpenLiteSpeedMissingConfig(t *testing.T) {
	if got := parseOpenLiteSpeedLogs("/usr/local/lsws", func(string) (string, error) {
		return "", errors.New("not found")
	}); got != nil {
		t.Errorf("got %+v", got)
	}
}

func TestCyberPanelDomainFromLogPath(t *testing.T) {
	if d := extractDomainFromLogPath("/home/example.com/logs/example.com.access_log"); d != "example.com" {
		t.Errorf("domain = %q", d)
	}
}
