package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/malware"
	"github.com/infrafence/infrafence-agent/internal/preflight"
	"github.com/infrafence/infrafence-agent/internal/trust"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

// Domain verification for the "Monitored by InfraFence" trust badge. Each
// sync lists, in trust_tokens, the domains whose badge needs the
// verification file now. For each one the agent finds the document root
// that serves exactly that name (or its www. counterpart): the hosting
// panel's sites first, then the nginx server blocks and Apache virtual
// hosts, then HestiaCP's per-domain web roots. It writes one file per
// document root with the tokens of all its domains (internal/trust) and
// removes a token, then the file, when its domain is no longer listed.
//
// What was written where is kept in /var/lib/infrafence/trust-state.json
// (0600, replaced atomically), with the last result reported for each
// domain: a removal after a restart is exact, and trust_token_placed,
// trust_token_failed and trust_token_removed are reported once per change,
// not on every sync. Nothing is written or removed while protection is
// switched off; monitor mode does not stop it, since the file blocks
// nothing (like a quarantine restore).

var trustStatePath = "/var/lib/infrafence/trust-state.json"

// maxTrustTokens bounds the domains handled per sync.
const maxTrustTokens = 1000

// Replaced in tests.
var (
	trustSites  = detectTrustSites
	trustPlace  = trust.Place
	trustRemove = trust.Remove
	trustReport = func(client *api.Client, typ string, details map[string]string) {
		reportEvent(client, typ, "info", details)
	}
)

// trustRoot is what one document root's file holds.
type trustRoot struct {
	// CreatedDir: .well-known was created by the agent, so it is removed
	// with the file when empty.
	CreatedDir bool              `json:"created_dir,omitempty"`
	Tokens     map[string]string `json:"tokens"` // domain -> token
}

type trustPersisted struct {
	Roots map[string]*trustRoot `json:"roots"`
	// Reported is the last result reported per domain: "placed <path>" or
	// "failed <reason>".
	Reported map[string]string `json:"reported"`
}

var trustMu sync.Mutex

// trustPanelID is the hosting panel, detected once.
var trustPanelID = sync.OnceValue(func() string { return preflight.DetectPanel().ID })

// loadTrustState reads the state file; a missing one is an empty state, a
// corrupt one is set aside (.corrupt, for a look by hand: the files it
// lists are no longer removed by the agent) and replaced by an empty state.
func loadTrustState() *trustPersisted {
	st := &trustPersisted{}
	data, err := os.ReadFile(trustStatePath)
	if err == nil {
		if err := json.Unmarshal(data, st); err != nil {
			log.Printf("[trust] %s is not valid, set aside as .corrupt: %v", trustStatePath, err)
			_ = os.Rename(trustStatePath, trustStatePath+".corrupt")
			st = &trustPersisted{}
		}
	} else if !os.IsNotExist(err) {
		log.Printf("[trust] read %s: %v", trustStatePath, err)
	}
	if st.Roots == nil {
		st.Roots = map[string]*trustRoot{}
	}
	for root, r := range st.Roots {
		if r == nil || !filepath.IsAbs(root) {
			delete(st.Roots, root)
		} else if r.Tokens == nil {
			r.Tokens = map[string]string{}
		}
	}
	if st.Reported == nil {
		st.Reported = map[string]string{}
	}
	return st
}

func saveTrustState(st *trustPersisted) {
	if len(st.Roots) == 0 && len(st.Reported) == 0 {
		if err := os.Remove(trustStatePath); err != nil && !os.IsNotExist(err) {
			log.Printf("[trust] remove %s: %v", trustStatePath, err)
		}
		return
	}
	if err := writeFileAtomic(trustStatePath, st); err != nil {
		log.Printf("[trust] save %s: %v", trustStatePath, err)
	}
}

// applyTrustTokens brings the verification files in line with the domains
// the dashboard lists.
func applyTrustTokens(client *api.Client, tokens []api.TrustToken) {
	if protectionDisabled() {
		return
	}
	trustMu.Lock()
	defer trustMu.Unlock()
	st := loadTrustState()
	if len(tokens) == 0 && len(st.Roots) == 0 && len(st.Reported) == 0 {
		return
	}
	before, _ := json.Marshal(st)
	if len(tokens) > maxTrustTokens {
		log.Printf("[trust] %d domains listed, only the first %d handled", len(tokens), maxTrustTokens)
		tokens = tokens[:maxTrustTokens]
	}

	// The result of this sync for each listed domain.
	status := map[string]string{}
	why := map[string]string{}                // domain -> the error, logged with a new failure
	desired := map[string]map[string]string{} // root -> domain -> token
	var sites []trust.Site
	if len(tokens) > 0 {
		sites = trustSites()
	}
	valid := map[string]bool{} // domains with a valid entry: the first one counts
	for _, t := range tokens {
		d := trust.NormDomain(t.Domain)
		if d == "" || !trust.ValidToken(t.Token) {
			// Reported under the name as sent, if it is printable.
			key := strings.ToLower(strings.TrimSpace(t.Domain))
			if printableName(key) && !valid[key] {
				status[key] = "failed " + trust.ReasonInvalid
			}
			continue
		}
		if valid[d] {
			continue
		}
		valid[d] = true
		root, reason := trust.Match(d, sites)
		if reason != "" {
			status[d] = "failed " + reason
			continue
		}
		if desired[root] == nil {
			desired[root] = map[string]string{}
		}
		desired[root][d] = t.Token
		status[d] = ""
	}

	roots := make([]string, 0, len(desired)+len(st.Roots))
	for r := range desired {
		roots = append(roots, r)
	}
	for r := range st.Roots {
		if desired[r] == nil {
			roots = append(roots, r)
		}
	}
	slices.Sort(roots)
	for _, root := range roots {
		want, have := desired[root], st.Roots[root]
		if len(want) == 0 {
			err := trustRemove(root, have.CreatedDir)
			if err != nil {
				log.Printf("[trust] %v", err)
				// Retried at the next sync; a file someone else put there
				// (no token of ours left in it) is left alone for good.
				if trust.ReasonOf(err) != trust.ReasonFileExists {
					continue
				}
			} else {
				log.Printf("[trust] removed %s", trust.Path(root))
			}
			delete(st.Roots, root)
			continue
		}
		vals := make([]string, 0, len(want))
		for _, tok := range want {
			vals = append(vals, tok)
		}
		created, err := trustPlace(root, vals)
		if err != nil {
			for d, tok := range want {
				// Still served by the file as it was: unchanged.
				if have != nil && have.Tokens[d] == tok && st.Reported[d] == "placed "+trust.Path(root) {
					status[d] = st.Reported[d]
					continue
				}
				status[d] = "failed " + trust.ReasonOf(err)
				why[d] = err.Error()
			}
			continue
		}
		if have == nil {
			have = &trustRoot{}
			st.Roots[root] = have
		}
		have.CreatedDir = have.CreatedDir || created
		have.Tokens = want
		for d := range want {
			status[d] = "placed " + trust.Path(root)
		}
	}

	domains := make([]string, 0, len(status))
	for d := range status {
		domains = append(domains, d)
	}
	slices.Sort(domains)
	for _, d := range domains {
		s := status[d]
		if st.Reported[d] == s {
			continue
		}
		st.Reported[d] = s
		if path, ok := strings.CutPrefix(s, "placed "); ok {
			log.Printf("[trust] verification file for %q at %s", d, path)
			trustReport(client, "trust_token_placed", map[string]string{"domain": d, "path": path})
		} else {
			reason := strings.TrimPrefix(s, "failed ")
			if why[d] == "" {
				why[d] = reason
			}
			log.Printf("[trust] verification file for %q not placed: %s", d, why[d])
			trustReport(client, "trust_token_failed", map[string]string{"domain": d, "reason": reason})
		}
	}
	// No longer listed: reported removed once no file holds its token.
	gone := make([]string, 0, len(st.Reported))
	for d := range st.Reported {
		gone = append(gone, d)
	}
	slices.Sort(gone)
	for _, d := range gone {
		prev := st.Reported[d]
		if _, listed := status[d]; listed || trustServed(st, d) {
			continue
		}
		delete(st.Reported, d)
		if strings.HasPrefix(prev, "placed ") {
			trustReport(client, "trust_token_removed", map[string]string{"domain": d})
		}
	}

	if after, _ := json.Marshal(st); string(after) != string(before) {
		saveTrustState(st)
	}
}

// printableName: at most 253 printable ASCII characters, nothing else.
func printableName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// trustServed reports whether a file still holds domain's token.
func trustServed(st *trustPersisted, domain string) bool {
	for _, r := range st.Roots {
		if _, ok := r.Tokens[domain]; ok {
			return true
		}
	}
	return false
}

// detectTrustSites lists the sites with their document roots, in order of
// preference. A document root in a system directory is left out.
func detectTrustSites() []trust.Site {
	var sites []trust.Site
	add := func(names []string, root string) {
		if !filepath.IsAbs(root) {
			return
		}
		root = filepath.Clean(root)
		if systemTree(root) != "" {
			return
		}
		sites = append(sites, trust.Site{Names: names, Root: root})
	}
	// Listing the sites can take seconds (Plesk): the panel code's cache.
	if id := trustPanelID(); id != "" {
		for _, s := range cachedSites(id) {
			add([]string{s.Domain}, s.DocumentRoot)
		}
	}
	for _, s := range watcher.DetectSiteRoots() {
		add(s.Names, s.Root)
	}
	for _, r := range malware.DomainWebRoots() {
		add([]string{r.Domain}, r.Path)
	}
	return sites
}

// removeTrustFiles removes every verification file the agent wrote (for
// uninstall) and the state; it returns what was removed.
func removeTrustFiles() (removed []string, err error) {
	trustMu.Lock()
	defer trustMu.Unlock()
	st := loadTrustState()
	var errs []error
	for root, r := range st.Roots {
		if rerr := trustRemove(root, r.CreatedDir); rerr != nil {
			errs = append(errs, rerr)
			if trust.ReasonOf(rerr) != trust.ReasonFileExists {
				continue
			}
		} else {
			removed = append(removed, trust.Path(root))
		}
		delete(st.Roots, root)
	}
	st.Reported = map[string]string{}
	saveTrustState(st)
	slices.Sort(removed)
	return removed, errors.Join(errs...)
}
