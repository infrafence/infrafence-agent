package loginhistory

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// MaxEntries bounds the addresses kept (the most recent logins win, the
// addresses only service users logged in from go first).
const MaxEntries = 1000

// ServiceUserNets: a user name that logged in from more networks than this
// (/24 for IPv4, /48 for IPv6) in the last 30 days is a service user: a
// deploy or automation account (a CI runner logs in from a new cloud address
// almost every time), not a person, who logs in from a handful of networks.
// The dashboard uses the same value (_ssh_service_user_nets).
const ServiceUserNets = 10

// MaxListedUsers bounds the service users the dashboard can list.
const MaxListedUsers = 50

// ServiceUser is a user whose logins protect no address: Nets networks in
// the last 30 days, or Listed in the dashboard's settings.
type ServiceUser struct {
	User   string
	Nets   int
	Listed bool
}

// Entry is one address SSH logins came from in the last 30 days.
type Entry struct {
	IP    string    `json:"ip"`
	Users []string  `json:"users"`
	First time.Time `json:"first_at"`
	Last  time.Time `json:"last_at"`
	Count int       `json:"count"`
	// Imported: found in the logs read at startup or by the daily scan.
	// Live: seen by the agent as it happened.
	Imported bool `json:"imported"`
	Live     bool `json:"live"`
}

type persisted struct {
	ScannedAt time.Time `json:"scanned_at"`
	Sources   []string  `json:"sources,omitempty"`
	Entries   []Entry   `json:"entries"`
}

// Store is the login history, saved as JSON (0600) at path.
type Store struct {
	path string
	now  func() time.Time

	mu        sync.Mutex
	entries   map[string]*Entry
	scannedAt time.Time
	sources   []string
	// listed: the service users of the dashboard's settings.
	listed map[string]bool
	// The service users and the unprotected addresses, computed again when
	// gen changes or after policyMaxAge.
	gen       uint64
	polGen    uint64
	polAt     time.Time
	service   map[string]int
	unguarded map[string]bool
}

const policyMaxAge = time.Hour

// NewStore returns an empty store saved at path ("" : never saved).
func NewStore(path string) *Store {
	return &Store{path: path, now: time.Now, entries: map[string]*Entry{}, gen: 1}
}

// Load reads the saved history; a missing or unreadable file leaves it
// empty (the next scan fills it).
func (s *Store) Load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scannedAt, s.sources = p.ScannedAt, p.Sources
	s.gen++
	for _, e := range p.Entries {
		ip := normIP(e.IP)
		if ip == "" || e.Last.IsZero() {
			continue
		}
		e := e
		e.IP = ip
		if len(e.Users) > maxUsers {
			e.Users = e.Users[:maxUsers]
		}
		s.entries[ip] = &e
	}
	s.pruneLocked()
	return nil
}

// ScannedAt is when the logs were last read (zero: never).
func (s *Store) ScannedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scannedAt
}

// Apply records a scan's result: what the logs show replaces the counts of
// the addresses they list (a live login is in the logs too, so it is not
// counted twice); addresses the logs no longer show are kept until their
// last login is 30 days old. Returns the addresses that were not known.
func (s *Store) Apply(r Result, at time.Time) []string {
	found := map[string]*Entry{}
	// The same login in two sources (the log file and the journal, or the
	// login records) counts once.
	type key struct {
		ip, user string
		sec      int64
	}
	seen := map[key]bool{}
	for _, l := range r.Logins {
		k := key{l.IP, l.User, l.Time.Unix()}
		if seen[k] {
			continue
		}
		seen[k] = true
		e := found[l.IP]
		if e == nil {
			e = &Entry{IP: l.IP, First: l.Time, Last: l.Time, Imported: true}
			found[l.IP] = e
		}
		e.Count++
		if l.Time.Before(e.First) {
			e.First = l.Time
		}
		if l.Time.After(e.Last) {
			e.Last = l.Time
		}
		e.Users = addUser(e.Users, l.User)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	var added []string
	for ip, f := range found {
		old := s.entries[ip]
		if old == nil {
			s.entries[ip] = f
			added = append(added, ip)
			continue
		}
		old.Imported = true
		old.Count = max(f.Count, 1)
		if f.First.Before(old.First) {
			old.First = f.First
		}
		if f.Last.After(old.Last) {
			old.Last = f.Last
		}
		for _, u := range f.Users {
			old.Users = addUser(old.Users, u)
		}
	}
	s.scannedAt, s.sources = at, append([]string(nil), r.Sources...)
	s.pruneLocked()
	sort.Strings(added)
	return added
}

// Note records a login seen live; true when the address was not known.
func (s *Store) Note(ip, user string, t time.Time) bool {
	ip = normIP(ip)
	if ip == "" {
		return false
	}
	if t.IsZero() {
		t = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[ip]
	isNew := e == nil
	if isNew {
		e = &Entry{IP: ip, First: t}
		s.entries[ip] = e
	}
	e.Live = true
	e.Count++
	if t.After(e.Last) {
		e.Last = t
	}
	if t.Before(e.First) {
		e.First = t
	}
	n := len(e.Users)
	e.Users = addUser(e.Users, cleanUser(user))
	// The service users change only with a new address or user.
	if isNew || len(e.Users) != n {
		s.gen++
	}
	s.pruneLocked()
	return isNew
}

// LastLogin returns when ip last logged in over SSH, if in the last 30 days,
// whoever logged in (Protected says whether that protects the address).
func (s *Store) LastLogin(ip string) (time.Time, bool) {
	ip = normIP(ip)
	if ip == "" {
		return time.Time{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[ip]
	if e == nil || s.now().Sub(e.Last) >= Window {
		return time.Time{}, false
	}
	return e.Last, true
}

// IPs returns the addresses with a login in the last 30 days.
func (s *Store) IPs() []string {
	return s.ips(false)
}

// ProtectedIPs returns the addresses with a login in the last 30 days that
// are protected (Protected).
func (s *Store) ProtectedIPs() []string {
	return s.ips(true)
}

func (s *Store) ips(protectedOnly bool) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if protectedOnly {
		s.policyLocked(now)
	}
	out := make([]string, 0, len(s.entries))
	for ip, e := range s.entries {
		if now.Sub(e.Last) < Window && !(protectedOnly && s.unguarded[ip]) {
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}

// Protected returns when ip last logged in over SSH, if in the last 30 days
// and the login protects the address: some user of it is not a service
// user, or its users are unknown. known: the address is in the history at
// all (a service user's address is known but not protected).
func (s *Store) Protected(ip string) (last time.Time, ok, known bool) {
	ip = normIP(ip)
	if ip == "" {
		return time.Time{}, false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e := s.entries[ip]
	if e == nil || now.Sub(e.Last) >= Window {
		return time.Time{}, false, false
	}
	s.policyLocked(now)
	if s.unguarded[ip] {
		return time.Time{}, false, true
	}
	return e.Last, true, true
}

// ServiceUsers returns the users of the history whose logins protect no
// address, by name.
func (s *Store) ServiceUsers() []ServiceUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyLocked(s.now())
	out := make([]ServiceUser, 0, len(s.service))
	for u, n := range s.service {
		out = append(out, ServiceUser{User: u, Nets: n, Listed: s.listed[u]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// SetServiceUsers sets the service users the dashboard lists (at most
// MaxListedUsers, invalid names left out); true when the list changed.
func (s *Store) SetServiceUsers(users []string) bool {
	next := map[string]bool{}
	for _, u := range users {
		if c := cleanUser(u); c != "" && c == u && len(next) < MaxListedUsers {
			next[c] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(next) == len(s.listed) {
		same := true
		for u := range next {
			if !s.listed[u] {
				same = false
				break
			}
		}
		if same {
			return false
		}
	}
	s.listed = next
	s.gen++
	return true
}

// userNetsLocked counts, per user, the networks of its addresses in the
// last 30 days.
func (s *Store) userNetsLocked(now time.Time) map[string]int {
	nets := map[string]map[string]bool{}
	for ip, e := range s.entries {
		if now.Sub(e.Last) >= Window {
			continue
		}
		n := userNet(ip)
		for _, u := range e.Users {
			if nets[u] == nil {
				nets[u] = map[string]bool{}
			}
			nets[u][n] = true
		}
	}
	out := make(map[string]int, len(nets))
	for u, m := range nets {
		out[u] = len(m)
	}
	return out
}

// policyLocked computes the service users and the addresses only they
// logged in from, when the history or the list changed.
func (s *Store) policyLocked(now time.Time) {
	if s.polGen == s.gen && now.Sub(s.polAt) < policyMaxAge && s.service != nil {
		return
	}
	s.polGen, s.polAt = s.gen, now
	s.service = map[string]int{}
	for u, n := range s.userNetsLocked(now) {
		if n > ServiceUserNets || s.listed[u] {
			s.service[u] = n
		}
	}
	s.unguarded = map[string]bool{}
	for ip, e := range s.entries {
		if now.Sub(e.Last) >= Window || len(e.Users) == 0 {
			continue
		}
		person := false
		for _, u := range e.Users {
			if _, svc := s.service[u]; !svc {
				person = true
				break
			}
		}
		if !person {
			s.unguarded[ip] = true
		}
	}
}

// userNet is the network a user's logins are counted in: the /24 of an
// IPv4 address, the /48 of an IPv6 one.
func userNet(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if v4 := p.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return p.Mask(net.CIDRMask(48, 128)).String()
}

// Entries returns at most limit entries of the last 30 days, the most
// recent login first.
func (s *Store) Entries(limit int) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if now.Sub(e.Last) < Window {
			c := *e
			c.Users = append([]string(nil), e.Users...)
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Last.Equal(out[j].Last) {
			return out[i].Last.After(out[j].Last)
		}
		return out[i].IP < out[j].IP
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Save writes the history (0600, replaced atomically).
func (s *Store) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	p := persisted{ScannedAt: s.scannedAt, Sources: s.sources}
	s.mu.Unlock()
	p.Entries = s.Entries(0)
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), s.path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// pruneLocked drops logins older than 30 days and, past MaxEntries, the
// oldest ones.
func (s *Store) pruneLocked() {
	now := s.now()
	for ip, e := range s.entries {
		if now.Sub(e.Last) >= Window {
			delete(s.entries, ip)
			s.gen++
		}
	}
	if len(s.entries) <= MaxEntries {
		return
	}
	// The addresses only service users logged in from go first, so a busy
	// deploy account cannot push the administrators out.
	s.policyLocked(now)
	ips := make([]string, 0, len(s.entries))
	for ip := range s.entries {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		if ui, uj := s.unguarded[ips[i]], s.unguarded[ips[j]]; ui != uj {
			return ui
		}
		return s.entries[ips[i]].Last.Before(s.entries[ips[j]].Last)
	})
	for _, ip := range ips[:len(ips)-MaxEntries] {
		delete(s.entries, ip)
	}
	s.gen++
}

func addUser(users []string, u string) []string {
	if u == "" {
		return users
	}
	for _, x := range users {
		if x == u {
			return users
		}
	}
	if len(users) >= maxUsers {
		return users
	}
	return append(users, u)
}
