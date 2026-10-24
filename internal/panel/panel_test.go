package panel

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func TestParseIP(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":           "203.0.113.7",
		"2001:db8::1":           "2001:db8::1",
		"2001:DB8:0:0:0:0:0:1":  "2001:db8::1",
		"::ffff:203.0.113.7":    "203.0.113.7",
		"203.0.113.0/24":        "",
		"203.0.113.7:22":        "",
		" 203.0.113.7":          "",
		"fe80::1%eth0":          "",
		"203.0.113.7; rm -rf /": "",
		"":                      "",
		"localhost":             "",
		"0203.0.113.7":          "",
	} {
		got, ok := ParseIP(in)
		if got != want || ok != (want != "") {
			t.Errorf("ParseIP(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestValidActorAndNote(t *testing.T) {
	for in, want := range map[string]bool{
		"root": true, "admin": true, "reseller.one": true, "a@b.example": true,
		"": false, "a b": false, "x;id": false, "$(id)": false, strings.Repeat("a", 65): false,
	} {
		if ValidActor(in) != want {
			t.Errorf("ValidActor(%q) != %v", in, want)
		}
	}
	if n, ok := CleanNote("  office VPN  "); !ok || n != "office VPN" {
		t.Errorf("note: %q %v", n, ok)
	}
	if _, ok := CleanNote("line\nbreak"); ok {
		t.Error("control characters accepted in a note")
	}
	if _, ok := CleanNote(strings.Repeat("x", 201)); ok {
		t.Error("long note accepted")
	}
}

func TestValidPath(t *testing.T) {
	for in, want := range map[string]bool{
		"/home/alice/public_html":              true,
		"/var/www/vhosts/example.com/httpdocs": true,
		"relative/path":                        false,
		"/home/alice/../bob":                   false,
		"/home/alice/":                         false,
		"/":                                    false,
		"/home/a\nb":                           false,
		"":                                     false,
	} {
		if ValidPath(in) != want {
			t.Errorf("ValidPath(%q) != %v", in, want)
		}
	}
}

func TestParseSince(t *testing.T) {
	if s, ok := ParseSince("24h", now); !ok || s != "2026-10-15T12:00:00Z" {
		t.Errorf("24h: %q %v", s, ok)
	}
	if s, ok := ParseSince("2026-10-16T10:00:00+02:00", now); !ok || s != "2026-10-16T08:00:00Z" {
		t.Errorf("rfc3339: %q %v", s, ok)
	}
	for _, bad := range []string{"-1h", "yesterday", "2400h"} {
		if _, ok := ParseSince(bad, now); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseArgs(t *testing.T) {
	cases := []struct {
		args     []string
		want     Request
		json     bool
		errCode  string
		errMatch string
	}{
		{args: []string{"status", "--json"}, want: Request{Command: "status"}, json: true},
		{args: []string{"bans", "--limit", "10", "--json"}, want: Request{Command: "bans", Limit: 10}, json: true},
		{args: []string{"bans"}, want: Request{Command: "bans", Limit: DefaultLimit}},
		{args: []string{"unban", "203.0.113.7", "--actor", "root", "--json"}, want: Request{Command: "unban", IP: "203.0.113.7", Actor: "root"}, json: true},
		{args: []string{"--json", "allow", "--actor=admin", "--note", "office", "2001:db8::1"}, want: Request{Command: "allow", IP: "2001:db8::1", Actor: "admin", Note: "office"}, json: true},
		{args: []string{"events", "--since", "1h", "--limit", "5"}, want: Request{Command: "events", Limit: 5, Since: "2026-10-16T11:00:00Z"}},
		{args: []string{"scan", "/home/alice/public_html", "--actor", "root"}, want: Request{Command: "scan", Path: "/home/alice/public_html", Actor: "root"}},
		{args: []string{"map", "--json"}, want: Request{Command: "map", Hours: 24}, json: true},
		{args: []string{"map", "--hours", "168", "--json"}, want: Request{Command: "map", Hours: 168}, json: true},
		{args: []string{"map", "--hours=24"}, want: Request{Command: "map", Hours: 24}},
		{args: []string{"score", "--json"}, want: Request{Command: "score"}, json: true},
		{args: []string{"map", "--hours", "48"}, errCode: ErrBadRequest, errMatch: "24 or 168"},
		{args: []string{"map", "--hours", "abc"}, errCode: ErrBadRequest},
		{args: []string{"map", "--limit", "5"}, errCode: ErrBadRequest},
		{args: []string{"score", "--hours", "24"}, errCode: ErrBadRequest},
		{args: []string{"bans", "--hours", "24"}, errCode: ErrBadRequest},
		{args: nil, errCode: ErrBadRequest},
		{args: []string{"reboot"}, errCode: ErrUnknownCommand},
		{args: []string{"unban", "203.0.113.7"}, errCode: ErrInvalidActor},
		{args: []string{"unban", "203.0.113.0/24", "--actor", "root"}, errCode: ErrInvalidIP},
		{args: []string{"unban", "--actor", "root"}, errCode: ErrBadRequest, errMatch: "exactly one"},
		{args: []string{"status", "extra"}, errCode: ErrBadRequest},
		{args: []string{"status", "--actor", "root"}, errCode: ErrBadRequest},
		{args: []string{"bans", "--limit", "0"}, errCode: ErrBadRequest},
		{args: []string{"bans", "--limit", "9999"}, errCode: ErrBadRequest},
		{args: []string{"bans", "--limit"}, errCode: ErrBadRequest},
		{args: []string{"bans", "--force"}, errCode: ErrBadRequest},
		{args: []string{"allow", "203.0.113.7", "--actor", "root", "--actor", "x"}, errCode: ErrBadRequest},
		{args: []string{"scan", "../etc", "--actor", "root"}, errCode: ErrInvalidPath},
		{args: []string{"unban", "203.0.113.7", "--actor", "a;b"}, errCode: ErrInvalidActor},
	}
	for _, c := range cases {
		req, jsonOut, fail := ParseArgs(c.args, now)
		if c.errCode != "" {
			if fail == nil || fail["error"] != c.errCode {
				t.Errorf("%v: want %s, got %v", c.args, c.errCode, fail)
			} else if c.errMatch != "" && !strings.Contains(fail["message"].(string), c.errMatch) {
				t.Errorf("%v: message %q", c.args, fail["message"])
			}
			continue
		}
		if fail != nil {
			t.Errorf("%v: %v", c.args, fail)
			continue
		}
		if req != c.want || jsonOut != c.json {
			t.Errorf("%v: got %+v json=%v, want %+v json=%v", c.args, req, jsonOut, c.want, c.json)
		}
	}
}

func TestValidateOnTheAgentSide(t *testing.T) {
	for _, c := range []struct {
		req  Request
		code string
	}{
		{Request{Command: "status"}, ""},
		{Request{Command: "nope"}, ErrUnknownCommand},
		{Request{Command: "unban", IP: "203.0.113.7"}, ErrInvalidActor},
		{Request{Command: "unban", IP: "not-an-ip", Actor: "root"}, ErrInvalidIP},
		{Request{Command: "scan", Path: "/a/../b", Actor: "root"}, ErrInvalidPath},
		{Request{Command: "bans", Limit: 100000}, ErrBadRequest},
		{Request{Command: "events", Since: "yesterday"}, ErrBadRequest},
		{Request{Command: "allow", IP: "203.0.113.7", Actor: "root", Note: "a\x00b"}, ErrBadRequest},
		{Request{Command: "map", Hours: 168}, ""},
		{Request{Command: "map", Hours: 48}, ErrBadRequest},
		{Request{Command: "score", Hours: 24}, ErrBadRequest},
		{Request{Command: "status", Hours: 24}, ErrBadRequest},
	} {
		req := c.req
		resp := Validate(&req)
		got := ""
		if resp != nil {
			got = resp["error"].(string)
		}
		if got != c.code {
			t.Errorf("%+v: got %q, want %q", c.req, got, c.code)
		}
	}
	m := Request{Command: "map"}
	if Validate(&m) != nil || m.Hours != DefaultMapHours {
		t.Errorf("map hours not defaulted: %+v", m)
	}
	req := Request{Command: "unban", IP: "::ffff:203.0.113.7", Actor: "root"}
	if Validate(&req) != nil || req.IP != "203.0.113.7" || req.Limit != DefaultLimit {
		t.Errorf("not normalized: %+v", req)
	}
}

func TestResponses(t *testing.T) {
	ok := OK(map[string]any{"x": 1})
	if !ok.Succeeded() || ok["x"] != 1 {
		t.Errorf("ok: %v", ok)
	}
	f := Fail(ErrNotBanned, "%s is not banned", "203.0.113.7")
	if f.Succeeded() || f["error"] != ErrNotBanned || f["message"] != "203.0.113.7 is not banned" {
		t.Errorf("fail: %v", f)
	}
}

func TestParseIPRejectsSpecialAddresses(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255"} {
		if _, ok := ParseIP(s); ok {
			t.Errorf("%s accepted", s)
		}
	}
}
