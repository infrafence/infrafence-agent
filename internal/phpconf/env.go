package phpconf

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// Env is the host as discovery sees it; tests root it in a fixture
// directory.
type Env interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) []string
	Exists(path string) bool
	Run(name string, args ...string) (string, error)
}

// hostEnv reads the real host. Root, when set, is prepended to every path
// (fixtures); paths returned by Glob are given back without it.
type hostEnv struct{ root string }

// System is the real host.
var System Env = hostEnv{}

// RootedEnv reads files under root as if it were "/" and runs no commands.
func RootedEnv(root string) Env { return hostEnv{root: root} }

// ReadFile reads a regular file of at most maxFileSize bytes. Symlinks are
// followed (Debian's conf.d is made of them), but a device or a FIFO a
// site owner put in place of a .user.ini is refused, never read or waited
// on.
func (e hostEnv) ReadFile(p string) ([]byte, error) {
	f, err := os.OpenFile(e.root+p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileSize {
		return nil, errTooLarge
	}
	return b, nil
}

var (
	errNotRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("file too large")
)

func (e hostEnv) Exists(p string) bool {
	_, err := os.Stat(e.root + p)
	return err == nil
}
func (e hostEnv) Glob(pattern string) []string {
	m, _ := filepath.Glob(e.root + pattern)
	out := make([]string, 0, len(m))
	for _, p := range m {
		out = append(out, p[len(e.root):])
	}
	sort.Strings(out)
	return out
}
func (e hostEnv) Run(name string, args ...string) (string, error) {
	if e.root != "" {
		return "", exec.ErrNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	return string(out), err
}

// maxFileSize bounds what is read from one configuration file.
const maxFileSize = 1 << 20

func readSmall(env Env, p string) (string, bool) {
	b, err := env.ReadFile(p)
	if err != nil || len(b) > maxFileSize {
		return "", false
	}
	return string(b), true
}
