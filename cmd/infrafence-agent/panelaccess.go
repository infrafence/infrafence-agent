package main

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/infrafence/infrafence-agent/internal/dbclients"
	"github.com/infrafence/infrafence-agent/internal/loginhistory"
	"github.com/infrafence/infrafence-agent/internal/panel"
)

// "panel ssh-logins" and "panel db-clients": who reaches this server
// regularly, for the plugins' known SSH logins and regular clients of the
// database ports. Both are answered on the server, read only, from what the
// agent keeps itself (the login history of sshlogins.go and the client log
// of dbclients.go, the lists it also sends the dashboard): no request to the
// dashboard. "allowed" says whether the address (for a range, all of it) is
// on this server's allow list now (the dashboard's whitelist and the
// panel's own entries): never banned, and it keeps reaching a closed port.

// panelLoginOut is one element of the ssh-logins answer.
type panelLoginOut struct {
	IP       string   `json:"ip"`
	Users    []string `json:"users"`
	Country  any      `json:"country"`
	FirstAt  any      `json:"first_at"`
	LastAt   any      `json:"last_at"`
	Logins   int      `json:"logins"`
	Imported bool     `json:"imported"`
	Live     bool     `json:"live"`
	Allowed  bool     `json:"allowed"`
	// Protected: the login guard never bans the address (sshlogins.go): a
	// user of it is not a service user, or its users are unknown.
	// NotProtected says why not, null when protected.
	Protected    bool                  `json:"protected"`
	NotProtected *panelNotProtectedOut `json:"not_protected"`
}

// panelNotProtectedOut: every user of the address is a service user
// (loginhistory.ServiceUser). Reason "listed" when each of them is listed
// in the dashboard's settings, "service_user" otherwise.
type panelNotProtectedOut struct {
	Reason string                `json:"reason"`
	Users  []panelServiceUserOut `json:"users"`
}

type panelServiceUserOut struct {
	User     string `json:"user"`
	Networks int    `json:"networks"`
	Listed   bool   `json:"listed"`
}

// panelCountry is the country of a public address, "" when unknown;
// replaced in tests.
var panelCountry = func(ip string) string {
	if g := geoLookup.Load(); g != nil {
		return g.Country(ip)
	}
	return ""
}

// panelLoginView is the login history, when the logs were last read, and
// the guard's own answers: which addresses it protects and the service
// users (loginhistory.Store.Protected, ServiceUsers).
type panelLoginView struct {
	entries   []loginhistory.Entry
	scanned   time.Time
	protected func(ip string) bool
	service   []loginhistory.ServiceUser
}

// panelLogins reads it from the agent's store; replaced in tests.
var panelLogins = func() panelLoginView {
	s := sshLoginStore
	return panelLoginView{
		entries: s.Entries(0), scanned: s.ScannedAt(),
		protected: func(ip string) bool { _, ok, _ := s.Protected(ip); return ok },
		service:   s.ServiceUsers(),
	}
}

func panelSSHLogins(limit int) panel.Response {
	v := panelLogins()
	all, scanned := v.entries, v.scanned
	service := make(map[string]loginhistory.ServiceUser, len(v.service))
	for _, u := range v.service {
		service[u.User] = u
	}
	out := make([]panelLoginOut, 0, min(limit, len(all)))
	for _, e := range all[:min(limit, len(all))] {
		users := make([]string, 0, len(e.Users))
		for _, u := range e.Users {
			if u = cleanText(u, 64); u != "" {
				users = append(users, u)
			}
		}
		country := strings.ToUpper(panelCountry(e.IP))
		if len(country) != 2 {
			country = ""
		}
		out = append(out, panelLoginOut{
			IP: e.IP, Users: users, Country: orNull(country),
			FirstAt: rfc3339(e.First), LastAt: rfc3339(e.Last), Logins: e.Count,
			Imported: e.Imported, Live: e.Live, Allowed: panelIsAllowListed(e.IP),
			Protected: v.protected(e.IP), NotProtected: panelNotProtected(e, v.protected, service),
		})
	}
	return panel.OK(map[string]any{
		"logins": out, "total": len(all), "days": int(loginhistory.Window.Hours() / 24),
		"scanned_at": rfc3339(scanned),
	})
}

// panelNotProtected says why the guard does not protect e: nil when it does.
func panelNotProtected(e loginhistory.Entry, protected func(string) bool, service map[string]loginhistory.ServiceUser) *panelNotProtectedOut {
	if protected(e.IP) {
		return nil
	}
	np := &panelNotProtectedOut{Reason: "listed", Users: []panelServiceUserOut{}}
	for _, u := range e.Users {
		su, ok := service[u]
		if !ok {
			continue
		}
		np.Users = append(np.Users, panelServiceUserOut{User: cleanText(u, 64), Networks: su.Nets, Listed: su.Listed})
		if !su.Listed {
			np.Reason = "service_user"
		}
	}
	if len(np.Users) == 0 {
		// Not protected without a service user among its users: the store
		// changed between the two reads; the next answer says why.
		np.Reason = "service_user"
	}
	return np
}

// panelDBClientOut is one element of the db-clients answer.
type panelDBClientOut struct {
	Port int `json:"port"`
	// An address, or a range for a declared client ("198.51.100.0/24").
	IP string `json:"ip"`
	// "observed", or the panel's list that declares it ("cpanel_access_hosts").
	Source string `json:"source"`
	// The panel's own entry for a declared client ("198.51.100.%", a name).
	Host      any  `json:"host"`
	Days      any  `json:"days"`
	FirstSeen any  `json:"first_seen"`
	LastSeen  any  `json:"last_seen"`
	Allowed   bool `json:"allowed"`
}

// panelDBClientsMax bounds the answer (the client log keeps at most 1000
// addresses per port, internal/dbclients).
const panelDBClientsMax = 500

func panelDBClients() panel.Response {
	var out []panelDBClientOut
	l := dbClientLog.Load()
	for _, port := range closablePortList() {
		for _, c := range l.Regular(port) {
			out = append(out, panelDBClientOut{
				Port: port, IP: c.IP, Source: "observed", Host: nil, Days: c.Days,
				FirstSeen: rfc3339(c.First), LastSeen: rfc3339(c.Last), Allowed: dbAllowNet(c.IP),
			})
		}
	}
	if d := dbDeclared.Load(); d != nil {
		for _, x := range *d {
			if len(out) >= 2*panelDBClientsMax {
				break
			}
			out = append(out, panelDBClientOut{
				Port: dbMySQLPort, IP: x.Entry, Source: cleanText(x.Source, 40), Host: orNull(cleanText(x.Host, 255)),
				Allowed: dbAllowNet(x.Entry),
			})
		}
	}
	// Per port; the observed clients first, the most recently seen first.
	slices.SortStableFunc(out, func(a, b panelDBClientOut) int {
		if c := cmp.Compare(a.Port, b.Port); c != 0 {
			return c
		}
		if ao, bo := a.Source == "observed", b.Source == "observed"; ao != bo {
			if ao {
				return -1
			}
			return 1
		}
		as, _ := a.LastSeen.(string)
		bs, _ := b.LastSeen.(string)
		if c := strings.Compare(bs, as); c != 0 {
			return c
		}
		return strings.Compare(a.IP, b.IP)
	})
	total := len(out)
	if len(out) > panelDBClientsMax {
		out = out[:panelDBClientsMax]
	}
	if out == nil {
		out = []panelDBClientOut{}
	}
	return panel.OK(map[string]any{
		"clients": out, "total": total, "min_days": dbclients.MinDays, "window_days": dbclients.WindowDays,
	})
}
