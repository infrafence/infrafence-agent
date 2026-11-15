// Command owrtpkg builds the OpenWrt opkg packages and feed of the router
// agent without the OpenWrt SDK: .ipk files (gzip'd tar of debian-binary,
// control.tar.gz, data.tar.gz, as ipkg-build makes them), the Packages
// index, and usign (ed25519, signify format) keys and signatures, which
// opkg checks against /etc/opkg/keys.
//
//	owrtpkg ipk -root DIR -control DIR -out FILE [-epoch N]
//	owrtpkg index -dir FEEDDIR            writes Packages and Packages.gz
//	owrtpkg keygen -sec FILE -pub FILE     usign key pair (the secret is not encrypted: keep it in a CI secret)
//	owrtpkg sign -sec FILE -m FILE         writes FILE.sig
//	owrtpkg verify -pub FILE -m FILE       checks FILE.sig
//	owrtpkg fingerprint -pub FILE          the key's name in /etc/opkg/keys
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "ipk":
		err = cmdIPK(args)
	case "index":
		err = cmdIndex(args)
	case "keygen":
		err = cmdKeygen(args)
	case "sign":
		err = cmdSign(args)
	case "verify":
		err = cmdVerify(args)
	case "fingerprint":
		err = cmdFingerprint(args)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "owrtpkg:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: owrtpkg ipk|index|keygen|sign|verify|fingerprint [flags]")
	os.Exit(2)
}

// ---- ipk ----

func cmdIPK(args []string) error {
	fl := flag.NewFlagSet("ipk", flag.ExitOnError)
	root := fl.String("root", "", "data root (installed under /)")
	ctl := fl.String("control", "", "control directory (control, conffiles, postinst, prerm, postrm)")
	out := fl.String("out", "", "output .ipk")
	epoch := fl.Int64("epoch", 0, "file times (SOURCE_DATE_EPOCH); 0: from the environment or now")
	_ = fl.Parse(args)
	if *root == "" || *ctl == "" || *out == "" {
		return errors.New("-root, -control and -out are required")
	}
	mtime := sourceDate(*epoch)
	size, err := treeSize(*root)
	if err != nil {
		return err
	}
	control, err := os.ReadFile(filepath.Join(*ctl, "control"))
	if err != nil {
		return err
	}
	control = setField(control, "Installed-Size", strconv.FormatInt(size, 10))
	data, err := tarGz(*root, nil, mtime)
	if err != nil {
		return err
	}
	ctrl, err := tarGz(*ctl, map[string][]byte{"control": control}, mtime)
	if err != nil {
		return err
	}
	var outer bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&outer, gzip.BestCompression)
	gz.ModTime = mtime
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{{"./debian-binary", []byte("2.0\n")}, {"./data.tar.gz", data}, {"./control.tar.gz", ctrl}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), ModTime: mtime, Typeflag: tar.TypeReg, Format: tar.FormatGNU}); err != nil {
			return err
		}
		if _, err := tw.Write(f.body); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return os.WriteFile(*out, outer.Bytes(), 0o644)
}

func sourceDate(epoch int64) time.Time {
	if epoch == 0 {
		if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
			epoch, _ = strconv.ParseInt(s, 10, 64)
		}
	}
	if epoch == 0 {
		epoch = time.Now().Unix()
	}
	return time.Unix(epoch, 0).UTC()
}

func treeSize(root string) (int64, error) {
	var n int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			st, err := d.Info()
			if err != nil {
				return err
			}
			n += st.Size()
		}
		return nil
	})
	return n, err
}

// setField replaces or appends a "Key: value" line of a control file.
func setField(control []byte, key, value string) []byte {
	lines := strings.Split(strings.TrimRight(string(control), "\n"), "\n")
	done := false
	for i, l := range lines {
		if strings.HasPrefix(l, key+":") {
			lines[i] = key + ": " + value
			done = true
		}
	}
	if !done {
		// Before Description (which may continue on further lines).
		at := len(lines)
		for i, l := range lines {
			if strings.HasPrefix(l, "Description:") {
				at = i
				break
			}
		}
		lines = append(lines[:at], append([]string{key + ": " + value}, lines[at:]...)...)
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// tarGz archives dir as ./..., root-owned, sorted, with fixed times;
// override replaces the content of top-level files.
func tarGz(dir string, override map[string][]byte, mtime time.Time) ([]byte, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != dir {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	gz.ModTime = mtime
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "./", Mode: 0o755, ModTime: mtime, Typeflag: tar.TypeDir, Format: tar.FormatGNU}); err != nil {
		return nil, err
	}
	for _, p := range paths {
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		st, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		h := &tar.Header{Name: "./" + rel, ModTime: mtime, Uname: "root", Gname: "root", Format: tar.FormatGNU}
		switch {
		case st.IsDir():
			h.Typeflag, h.Name, h.Mode = tar.TypeDir, h.Name+"/", 0o755
			if err := tw.WriteHeader(h); err != nil {
				return nil, err
			}
		case st.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return nil, err
			}
			h.Typeflag, h.Linkname, h.Mode = tar.TypeSymlink, target, 0o777
			if err := tw.WriteHeader(h); err != nil {
				return nil, err
			}
		case st.Mode().IsRegular():
			body, ok := override[rel]
			if !ok {
				if body, err = os.ReadFile(p); err != nil {
					return nil, err
				}
			}
			h.Typeflag, h.Size = tar.TypeReg, int64(len(body))
			h.Mode = 0o644
			if st.Mode().Perm()&0o100 != 0 {
				h.Mode = 0o755
			}
			if st.Mode().Perm()&0o077 == 0 {
				h.Mode &= 0o700 // keep 0600 files private
			}
			if err := tw.WriteHeader(h); err != nil {
				return nil, err
			}
			if _, err := tw.Write(body); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- index ----

// cmdIndex writes the opkg Packages index of every .ipk in dir: each
// package's control fields plus Filename, Size and SHA256sum.
func cmdIndex(args []string) error {
	fl := flag.NewFlagSet("index", flag.ExitOnError)
	dir := fl.String("dir", "", "feed directory")
	_ = fl.Parse(args)
	files, err := filepath.Glob(filepath.Join(*dir, "*.ipk"))
	if err != nil || len(files) == 0 {
		return fmt.Errorf("no .ipk in %q", *dir)
	}
	sort.Strings(files)
	var idx bytes.Buffer
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		control, err := ipkControl(body)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		sum := sha256.Sum256(body)
		idx.WriteString(strings.TrimRight(string(control), "\n") + "\n")
		fmt.Fprintf(&idx, "Filename: %s\nSize: %d\nSHA256sum: %s\n\n", filepath.Base(f), len(body), hex.EncodeToString(sum[:]))
	}
	if err := os.WriteFile(filepath.Join(*dir, "Packages"), idx.Bytes(), 0o644); err != nil {
		return err
	}
	var gzb bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&gzb, gzip.BestCompression)
	gz.ModTime = sourceDate(0)
	gz.Write(idx.Bytes())
	gz.Close()
	return os.WriteFile(filepath.Join(*dir, "Packages.gz"), gzb.Bytes(), 0o644)
}

func ipkControl(ipk []byte) ([]byte, error) {
	inner, err := tarMember(bytes.NewReader(ipk), "./control.tar.gz")
	if err != nil {
		return nil, err
	}
	return tarMember(bytes.NewReader(inner), "./control")
}

func tarMember(r io.Reader, name string) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("%s not found: %w", name, err)
		}
		if h.Name == name || "./"+strings.TrimPrefix(h.Name, "./") == name {
			return io.ReadAll(io.LimitReader(tr, 64<<20))
		}
	}
}

// ---- usign ----

// usign (OpenWrt's signify) formats, all base64 after an "untrusted
// comment:" line:
//
//	public key: "Ed" | fingerprint[8] | pubkey[32]
//	secret key: "Ed" | "BK" | kdfrounds[4] | salt[16] | checksum[8] | fingerprint[8] | seckey[64]
//	signature:  "Ed" | fingerprint[8] | sig[64]
func writeB64(path, comment string, body []byte, perm os.FileMode) error {
	return os.WriteFile(path, []byte("untrusted comment: "+comment+"\n"+base64.StdEncoding.EncodeToString(body)+"\n"), perm)
}

func readB64(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "untrusted comment:") {
		return nil, fmt.Errorf("%s: not a usign file", path)
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
}

func cmdKeygen(args []string) error {
	fl := flag.NewFlagSet("keygen", flag.ExitOnError)
	sec := fl.String("sec", "", "secret key file")
	pub := fl.String("pub", "", "public key file")
	comment := fl.String("c", "InfraFence OpenWrt feed", "comment")
	_ = fl.Parse(args)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var fp [8]byte
	if _, err := rand.Read(fp[:]); err != nil {
		return err
	}
	sum := sha512.Sum512(sk)
	s := []byte("EdBK")
	s = binary.BigEndian.AppendUint32(s, 0)
	s = append(s, make([]byte, 16)...)
	s = append(s, sum[:8]...)
	s = append(s, fp[:]...)
	s = append(s, sk...)
	if err := writeB64(*sec, *comment+" secret key", s, 0o600); err != nil {
		return err
	}
	p := append(append([]byte("Ed"), fp[:]...), pk...)
	return writeB64(*pub, "public key "+hex.EncodeToString(fp[:]), p, 0o644)
}

func readSecret(path string) (ed25519.PrivateKey, []byte, error) {
	s, err := readB64(path)
	if err != nil {
		return nil, nil, err
	}
	if len(s) != 2+2+4+16+8+8+64 || string(s[:4]) != "EdBK" || binary.BigEndian.Uint32(s[4:8]) != 0 {
		return nil, nil, errors.New("unsupported secret key (encrypted or not usign)")
	}
	sk := ed25519.PrivateKey(s[40:104])
	if sum := sha512.Sum512(sk); !bytes.Equal(sum[:8], s[24:32]) {
		return nil, nil, errors.New("secret key checksum mismatch")
	}
	return sk, s[32:40], nil
}

func cmdSign(args []string) error {
	fl := flag.NewFlagSet("sign", flag.ExitOnError)
	sec := fl.String("sec", "", "secret key file")
	msg := fl.String("m", "", "file to sign")
	_ = fl.Parse(args)
	sk, fp, err := readSecret(*sec)
	if err != nil {
		return err
	}
	m, err := os.ReadFile(*msg)
	if err != nil {
		return err
	}
	sig := append(append([]byte("Ed"), fp...), ed25519.Sign(sk, m)...)
	return writeB64(*msg+".sig", "signed by key "+hex.EncodeToString(fp), sig, 0o644)
}

func cmdVerify(args []string) error {
	fl := flag.NewFlagSet("verify", flag.ExitOnError)
	pub := fl.String("pub", "", "public key file")
	msg := fl.String("m", "", "signed file")
	_ = fl.Parse(args)
	p, err := readB64(*pub)
	if err != nil {
		return err
	}
	s, err := readB64(*msg + ".sig")
	if err != nil {
		return err
	}
	m, err := os.ReadFile(*msg)
	if err != nil {
		return err
	}
	if len(p) != 42 || len(s) != 74 || !bytes.Equal(p[2:10], s[2:10]) {
		return errors.New("key and signature do not match")
	}
	if !ed25519.Verify(ed25519.PublicKey(p[10:]), m, s[10:]) {
		return errors.New("bad signature")
	}
	fmt.Println("OK")
	return nil
}

func cmdFingerprint(args []string) error {
	fl := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	pub := fl.String("pub", "", "public key file")
	_ = fl.Parse(args)
	p, err := readB64(*pub)
	if err != nil {
		return err
	}
	if len(p) != 42 {
		return errors.New("not a usign public key")
	}
	fmt.Println(hex.EncodeToString(p[2:10]))
	return nil
}
