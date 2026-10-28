package scanwatch

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
)

// TCP states in /proc/net/tcp.
const (
	tcpSynSent    = 0x02
	tcpSynRecv    = 0x03
	tcpListen     = 0x0A
	tcpNewSynRecv = 0x0C
)

type addrPort struct {
	addr netip.Addr
	port uint16
}

// sockets is a snapshot of this server's TCP table, limited to what the port
// scan check asks about.
type sockets struct {
	// Ports with a listening socket on a non-loopback (or the wildcard)
	// address: open services.
	listening map[uint16]bool
	// Connections a local listener accepted, by remote address and local
	// port (handshake started or done, open or closing), for the wanted
	// addresses only.
	accepted map[addrPort]bool
	// Wanted addresses with a connection to an FTP control port (handshake
	// done, open or closing).
	ftpControl map[netip.Addr]bool
}

// readSockets reads /proc/net/tcp and /proc/net/tcp6 under root, read-only.
func readSockets(root string, want map[netip.Addr]bool, control map[uint16]bool) (*sockets, error) {
	s := &sockets{
		listening:  map[uint16]bool{},
		accepted:   map[addrPort]bool{},
		ftpControl: map[netip.Addr]bool{},
	}
	// Without IPv6 there is no tcp6; any other error, even halfway through
	// a file, fails the whole read (missing listeners would count).
	read := 0
	for _, name := range []string{"tcp", "tcp6"} {
		err := s.readFile(filepath.Join(root, "proc/net", name), want, control)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		read++
	}
	if read == 0 {
		return nil, errors.New("no /proc/net/tcp")
	}
	return s, nil
}

func (s *sockets) readFile(path string, want map[netip.Addr]bool, control map[uint16]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 512), 64<<10)
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		var fields [4][]byte
		n := splitFields(sc.Bytes(), fields[:])
		if n < 4 {
			continue
		}
		local, lport, ok1 := parseProcAddr(fields[1])
		remote, _, ok2 := parseProcAddr(fields[2])
		st, err := strconv.ParseUint(string(fields[3]), 16, 8)
		if !ok1 || !ok2 || err != nil {
			continue
		}
		switch state := byte(st); {
		case state == tcpListen:
			if !local.IsLoopback() {
				s.listening[lport] = true
			}
		case state == tcpSynSent: // outgoing, not accepted by a listener
		case want[remote]:
			s.accepted[addrPort{remote, lport}] = true
			if control[lport] && state != tcpSynRecv && state != tcpNewSynRecv {
				s.ftpControl[remote] = true
			}
		}
	}
	return sc.Err()
}

// splitFields fills out with the first space-separated fields of line and
// returns how many it found, without allocating.
func splitFields(line []byte, out [][]byte) int {
	n, i := 0, 0
	for n < len(out) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i == len(line) {
			break
		}
		j := i
		for j < len(line) && line[j] != ' ' && line[j] != '\t' {
			j++
		}
		out[n] = line[i:j]
		n++
		i = j
	}
	return n
}

// parseProcAddr reads "0100007F:0016" (IPv4) or the 32-digit IPv6 form:
// 32-bit words in host byte order (little-endian on the architectures the
// agent is built for). IPv4-mapped IPv6 addresses come back as IPv4.
func parseProcAddr(b []byte) (netip.Addr, uint16, bool) {
	var raw [16]byte
	var words int
	switch len(b) {
	case 8 + 1 + 4:
		words = 1
	case 32 + 1 + 4:
		words = 4
	default:
		return netip.Addr{}, 0, false
	}
	if b[words*8] != ':' {
		return netip.Addr{}, 0, false
	}
	if _, err := hex.Decode(raw[:words*4], b[:words*8]); err != nil {
		return netip.Addr{}, 0, false
	}
	for w := 0; w < words; w++ {
		o := w * 4
		raw[o], raw[o+1], raw[o+2], raw[o+3] = raw[o+3], raw[o+2], raw[o+1], raw[o]
	}
	var port [2]byte
	if _, err := hex.Decode(port[:], b[words*8+1:]); err != nil {
		return netip.Addr{}, 0, false
	}
	p := uint16(port[0])<<8 | uint16(port[1])
	if words == 1 {
		return netip.AddrFrom4([4]byte(raw[:4])), p, true
	}
	return netip.AddrFrom16(raw).Unmap(), p, true
}
