package phpconf

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Bounds of the function search, so a host with huge docroots isn't
// slowed down by a check.
const (
	usageMaxFiles   = 20000
	usageMaxSize    = 1 << 20
	usageMaxResults = 20
	usageTimeout    = 30 * time.Second
)

// FindUsage lists (as "file:line", at most 20) the PHP files under roots
// that call one of funcs as a plain function. Read only; symlinks are not
// followed.
func FindUsage(roots []string, funcs []string) []string {
	if len(roots) == 0 || len(funcs) == 0 {
		return nil
	}
	quoted := make([]string, len(funcs))
	for i, f := range funcs {
		quoted[i] = regexp.QuoteMeta(f)
	}
	// A call, not a method (->exec, ::exec), a definition or a variable.
	re := regexp.MustCompile(`(?i)(^|[^\w$>:\\])(` + strings.Join(quoted, "|") + `)\s*\(`)
	defRe := regexp.MustCompile(`(?i)function\s+&?\s*(` + strings.Join(quoted, "|") + `)\s*\(`)
	deadline := time.Now().Add(usageTimeout)
	var out []string
	files := 0
	for _, root := range roots {
		if root == "/" || !filepath.IsAbs(root) {
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || len(out) >= usageMaxResults || files >= usageMaxFiles || time.Now().After(deadline) {
				if d != nil && d.IsDir() && err == nil {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".php" && ext != ".phtml" && ext != ".inc" {
				return nil
			}
			if info, err := d.Info(); err != nil || info.Size() > usageMaxSize {
				return nil
			}
			files++
			if line := firstCall(p, re, defRe); line > 0 {
				out = append(out, fmt.Sprintf("%s:%d", p, line))
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

func firstCall(p string, re, defRe *regexp.Regexp) int {
	// Non-blocking and no symlink: a FIFO named x.php can't hang the scan.
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return 0
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), usageMaxSize)
	for n := 1; sc.Scan(); n++ {
		l := sc.Text()
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "*") {
			continue
		}
		if re.MatchString(l) && !defRe.MatchString(l) {
			return n
		}
	}
	return 0
}
