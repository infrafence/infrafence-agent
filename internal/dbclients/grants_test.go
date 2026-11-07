package dbclients

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func entries(d []Declared) []string {
	out := []string{}
	for _, x := range d {
		out = append(out, x.Entry)
	}
	return out
}

func TestParseGrantHosts(t *testing.T) {
	data := strings.Join([]string{
		"%", "localhost", "127.0.0.1", "::1", "10.0.0.5", "192.168.1.%",
		"203.0.113.7", "198.51.100.%", "192.0.2.0/255.255.255.0",
		"db.example.com", "%.example.com", "203.0.113._", "", "server1",
	}, "\n")
	got, names := ParseGrantHosts(data)
	if want := []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.7"}; !reflect.DeepEqual(entries(got), want) {
		t.Fatalf("entries: %v", entries(got))
	}
	for _, d := range got {
		if d.Source != SourceMySQLGrants || d.ClientPort() != 3306 || d.Host == "" {
			t.Errorf("declared: %+v", d)
		}
	}
	if want := []string{"%.example.com", "db.example.com", "server1"}; !reflect.DeepEqual(names, want) {
		t.Errorf("names: %v", names)
	}
}

func TestParsePGHBA(t *testing.T) {
	data := `# TYPE  DATABASE  USER  ADDRESS  METHOD
local   all       all                       peer
host    all       all   127.0.0.1/32        scram-sha-256
host    all       all   ::1/128             scram-sha-256
host    all       all   0.0.0.0/0           md5
host    all       all   ::/0                md5
host    all       all   all                 md5
host    all       all   samehost            md5
host    all       all   samenet             md5
host    all       all   db.example.com      md5
host    all       all   .example.com        md5
host    all       all   10.0.0.0/8          md5
host    all       all   203.0.113.9/32      reject
hostssl shop      app   203.0.113.7/32      scram-sha-256
hostnossl all     all   198.51.100.0 255.255.255.0 md5
host    all       all   192.0.2.0/24        md5   # office
include_dir conf.d
hostssl all all 203.0.113.10/32
`
	got := ParsePGHBA(data)
	if want := []string{"203.0.113.7", "198.51.100.0/24", "192.0.2.0/24"}; !reflect.DeepEqual(entries(got), want) {
		t.Fatalf("entries: %v", entries(got))
	}
	for _, d := range got {
		if d.Source != SourcePGHBA || d.ClientPort() != 5432 {
			t.Errorf("declared: %+v", d)
		}
	}
}

// The real query path, with a fake client on PATH: no client, an
// authentication failure, and an answer read with root's option file.
func TestReadMySQLGrants(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	if _, _, err := ReadMySQLGrants(); err == nil {
		t.Fatal("no client: no error")
	}

	script := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "mysql"), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script(`echo "ERROR 1045 (28000): Access denied for user 'root'@'localhost'" >&2; exit 1`)
	if _, _, err := ReadMySQLGrants(); err == nil {
		t.Fatal("auth failure: no error")
	}

	old := rootMyCnf
	rootMyCnf = filepath.Join(dir, "my.cnf")
	t.Cleanup(func() { rootMyCnf = old })
	_ = os.WriteFile(rootMyCnf, []byte("[client]\n"), 0o600)
	args := filepath.Join(dir, "args")
	script(`echo "$@" > ` + args + `; printf '%%\nlocalhost\n203.0.113.7\napp.example.com\n'`)
	got, names, err := ReadMySQLGrants()
	if err != nil || !reflect.DeepEqual(entries(got), []string{"203.0.113.7"}) || !reflect.DeepEqual(names, []string{"app.example.com"}) {
		t.Fatalf("got %v %v %v", got, names, err)
	}
	b, _ := os.ReadFile(args)
	if a := string(b); !strings.HasPrefix(a, "--defaults-file="+rootMyCnf+" ") || !strings.Contains(a, "--protocol=socket") || !strings.Contains(a, grantHostsQuery) {
		t.Errorf("args: %q", a)
	}
}

func TestReadPGHBA(t *testing.T) {
	dir := t.TempDir()
	oldFile, oldPaths := PGHBAFile, PGHBAPaths
	t.Cleanup(func() { PGHBAFile, PGHBAPaths = oldFile, oldPaths })

	// No PostgreSQL to ask, no file.
	PGHBAFile = func() string { return "" }
	PGHBAPaths = []string{filepath.Join(dir, "*/main/pg_hba.conf")}
	if got, ok := ReadPGHBA(); ok || len(got) != 0 {
		t.Fatalf("no file: %v %v", got, ok)
	}

	// The usual place.
	p := filepath.Join(dir, "16/main/pg_hba.conf")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte("host all all 203.0.113.7/32 md5\n"), 0o644)
	if got, ok := ReadPGHBA(); !ok || !reflect.DeepEqual(entries(got), []string{"203.0.113.7"}) {
		t.Fatalf("usual path: %v %v", got, ok)
	}

	// The file PostgreSQL names wins.
	named := filepath.Join(dir, "custom_hba.conf")
	_ = os.WriteFile(named, []byte("host all all 198.51.100.0/24 md5\n"), 0o644)
	PGHBAFile = func() string { return named }
	if got, ok := ReadPGHBA(); !ok || !reflect.DeepEqual(entries(got), []string{"198.51.100.0/24"}) {
		t.Fatalf("named: %v %v", got, ok)
	}
	// A named file that cannot be read.
	PGHBAFile = func() string { return filepath.Join(dir, "missing") }
	if _, ok := ReadPGHBA(); ok {
		t.Error("missing named file read")
	}

}
