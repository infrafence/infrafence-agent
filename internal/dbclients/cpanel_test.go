package dbclients

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// As WHM writes /var/cpanel/mysqlaccesshosts (SQL Services > Additional
// MySQL Access Hosts): one host per line.
const accessHosts = `localhost
127.0.0.1
203.0.113.25
198.51.100.%
192.0.%.%
10.1.2.%
%
db-backup.example.com
%.example.net
203.0.113.0/255.255.255.192
2001:db8:1::10
198.18.0.0/15
  203.0.113.25  
# a comment
bad host name
`

func TestParseAccessHosts(t *testing.T) {
	old := Resolver
	t.Cleanup(func() { Resolver = old })
	asked := []string{}
	Resolver = func(_ context.Context, host string) []string {
		asked = append(asked, host)
		if host == "db-backup.example.com" {
			return []string{"198.51.200.4", "10.0.0.4"}
		}
		return nil
	}
	got := ParseAccessHosts(accessHosts, "cpanel_access_hosts")
	var entries []string
	for _, d := range got {
		entries = append(entries, d.Entry)
		if d.Source != "cpanel_access_hosts" {
			t.Fatalf("source: %+v", d)
		}
	}
	want := []string{"192.0.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "198.51.200.4", "2001:db8:1::10", "203.0.113.0/26", "203.0.113.25"}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("got %v, want %v", entries, want)
	}
	if !reflect.DeepEqual(asked, []string{"db-backup.example.com"}) {
		t.Fatalf("resolved %v", asked)
	}
	for _, d := range got {
		if d.Entry == "198.51.200.4" && d.Host != "db-backup.example.com" {
			t.Fatalf("host: %+v", d)
		}
	}
}

func TestReadCPanelAccessHosts(t *testing.T) {
	old := AccessHostsFile
	t.Cleanup(func() { AccessHostsFile = old })
	AccessHostsFile = filepath.Join(t.TempDir(), "mysqlaccesshosts")
	if _, ok := ReadCPanelAccessHosts(); ok {
		t.Fatal("no file: not ok")
	}
	_ = os.WriteFile(AccessHostsFile, []byte("203.0.113.25\n"), 0o644)
	got, ok := ReadCPanelAccessHosts()
	if !ok || len(got) != 1 || got[0].Entry != "203.0.113.25" {
		t.Fatalf("got %+v %v", got, ok)
	}
}

// A host name that fails to resolve keeps its last good addresses.
func TestResolveFailureKeepsLastAnswer(t *testing.T) {
	old := Resolver
	t.Cleanup(func() { Resolver = old })
	Resolver = func(context.Context, string) []string { return []string{"198.51.200.9"} }
	if got := ParseAccessHosts("replica.example.org\n", "x"); len(got) != 1 {
		t.Fatalf("first: %+v", got)
	}
	Resolver = func(context.Context, string) []string { return nil }
	if got := ParseAccessHosts("replica.example.org\n", "x"); len(got) != 1 || got[0].Entry != "198.51.200.9" {
		t.Fatalf("after failure: %+v", got)
	}
}
