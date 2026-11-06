package monitor

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ContainerDetails is what the web watcher needs from a container's
// inspect: how its process was started (a reverse proxy's access log is
// configured on its command line or in its environment), its mounts (to
// find a log file it writes on the host) and whether it has a TTY (how its
// output is framed).
type ContainerDetails struct {
	Name   string
	Image  string
	Args   []string // the process and its arguments
	Env    []string
	Tty    bool
	Mounts []DockerMount // bind mounts and volumes
}

// maxInspect bounds one inspect reply (a container with a huge environment
// is not worth more).
const maxInspect = 4 << 20

// InspectContainer returns a running container's details through the
// Docker (or Podman) API. Read only.
func InspectContainer(idOrName string) (*ContainerDetails, error) {
	sock := findDockerSocket()
	if sock == "" {
		return nil, fmt.Errorf("no docker socket found")
	}
	resp, err := dockerHTTPClient(sock).Get("http://localhost/containers/" + url.PathEscape(idOrName) + "/json")
	if err != nil {
		return nil, fmt.Errorf("docker API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker API: inspect %s: %s", idOrName, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInspect))
	if err != nil {
		return nil, fmt.Errorf("docker API read: %w", err)
	}
	return parseInspect(body)
}

func parseInspect(body []byte) (*ContainerDetails, error) {
	var r struct {
		Name   string   `json:"Name"`
		Path   string   `json:"Path"`
		Args   []string `json:"Args"`
		Config struct {
			Image string   `json:"Image"`
			Env   []string `json:"Env"`
			Tty   bool     `json:"Tty"`
		} `json:"Config"`
		Mounts []DockerMount `json:"Mounts"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("docker API parse: %w", err)
	}
	d := &ContainerDetails{
		Name:  strings.TrimPrefix(r.Name, "/"),
		Image: r.Config.Image,
		Env:   r.Config.Env,
		Tty:   r.Config.Tty,
	}
	if r.Path != "" {
		d.Args = append(d.Args, r.Path)
	}
	d.Args = append(d.Args, r.Args...)
	for _, m := range r.Mounts {
		if (m.Type == "bind" || m.Type == "volume") && m.Source != "" && m.Destination != "" {
			d.Mounts = append(d.Mounts, m)
		}
	}
	return d, nil
}

// MaxLogLine is the longest container output line passed on; a longer one
// is dropped (no access log line is that long).
const MaxLogLine = 64 << 10

// FollowContainerLogs streams a running container's output (stdout and
// stderr) from now on, one line at a time, until ctx ends or the stream
// does (the container stopped). Read only: the same as `docker logs -f
// --since now`. tty: the container has a TTY, so its output is not framed.
func FollowContainerLogs(ctx context.Context, idOrName string, tty bool, onLine func(string)) error {
	sock := findDockerSocket()
	if sock == "" {
		return fmt.Errorf("no docker socket found")
	}
	// No client timeout: the stream stays open; ctx ends it.
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     true,
	}}
	q := url.Values{}
	q.Set("follow", "1")
	q.Set("stdout", "1")
	q.Set("stderr", "1")
	// Whole seconds: Podman's API takes no fraction. A reconnect may see
	// the lines of its first second again.
	q.Set("since", strconv.FormatInt(time.Now().Unix(), 10))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://localhost/containers/"+url.PathEscape(idOrName)+"/logs?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("docker API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker API: logs %s: %s", idOrName, resp.Status)
	}
	var r io.Reader = resp.Body
	if !tty {
		r = &demuxReader{r: bufio.NewReader(resp.Body)}
	}
	return splitLines(r, onLine)
}

// demuxReader strips the 8-byte frame headers of a non-TTY container's
// output stream (stream type, 3 zero bytes, big-endian payload length).
type demuxReader struct {
	r    *bufio.Reader
	left uint32 // payload bytes left in the current frame
}

func (d *demuxReader) Read(p []byte) (int, error) {
	for d.left == 0 {
		var h [8]byte
		if _, err := io.ReadFull(d.r, h[:]); err != nil {
			return 0, err
		}
		d.left = binary.BigEndian.Uint32(h[4:])
	}
	if uint32(len(p)) > d.left {
		p = p[:d.left]
	}
	n, err := d.r.Read(p)
	d.left -= uint32(n)
	return n, err
}

// splitLines calls onLine for every complete line of r, dropping lines
// longer than MaxLogLine.
func splitLines(r io.Reader, onLine func(string)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var long bool
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 && !long {
			if len(buf)+len(chunk) > MaxLogLine {
				long, buf = true, buf[:0]
			} else {
				buf = append(buf, chunk...)
			}
		}
		switch err {
		case nil:
			if !long {
				onLine(strings.TrimRight(string(buf), "\r\n"))
			}
			long, buf = false, buf[:0]
		case bufio.ErrBufferFull:
			// the line goes on
		default:
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
