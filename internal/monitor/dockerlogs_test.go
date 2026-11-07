package monitor

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func frame(stream byte, payload string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(payload)))
	return append(h, payload...)
}

func TestDemuxSplitLines(t *testing.T) {
	var b bytes.Buffer
	// A line split across frames, stdout and stderr mixed, an empty frame.
	b.Write(frame(1, `{"ClientHost":"203.0.113.5","RequestPath":"/a"}`+"\n"+`{"ClientHost":"203.0`))
	b.Write(frame(1, ""))
	b.Write(frame(1, `.113.6","RequestPath":"/b"}`+"\r\n"))
	b.Write(frame(2, "level=info msg=started\n"))
	b.Write(frame(1, strings.Repeat("x", MaxLogLine+10)+"\nlast\n"))
	var got []string
	if err := splitLines(&demuxReader{r: bufio.NewReader(&b)}, func(l string) { got = append(got, l) }); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"ClientHost":"203.0.113.5","RequestPath":"/a"}`,
		`{"ClientHost":"203.0.113.6","RequestPath":"/b"}`,
		"level=info msg=started",
		"last",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestParseInspect(t *testing.T) {
	body := `{"Id":"abc","Name":"/coolify-proxy","Path":"/entrypoint.sh","Args":["--ping=true","--accesslog=true"],
	"Config":{"Image":"traefik:v3.1","Env":["PATH=/usr/bin"],"Tty":false},
	"Mounts":[{"Type":"bind","Source":"/data/coolify/proxy","Destination":"/traefik"},
	          {"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock"},
	          {"Type":"volume","Source":"/var/lib/docker/volumes/x/_data","Destination":"/logs"},
	          {"Type":"tmpfs","Source":"","Destination":"/tmp"}]}`
	d, err := parseInspect([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "coolify-proxy" || d.Image != "traefik:v3.1" || d.Tty ||
		!reflect.DeepEqual(d.Args, []string{"/entrypoint.sh", "--ping=true", "--accesslog=true"}) || len(d.Mounts) != 3 {
		t.Fatalf("got %+v", d)
	}
}
