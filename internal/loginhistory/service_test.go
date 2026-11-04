package loginhistory

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A deploy account on CI runners: a new cloud address at every run.
func ciLogins(user, prefix string, n int, at time.Time) []Login {
	var out []Login
	for i := 1; i <= n; i++ {
		out = append(out, Login{IP: fmt.Sprintf("%s.%d.7", prefix, i), User: user, Time: at.Add(-time.Duration(i) * time.Hour)})
	}
	return out
}

func TestServiceUsers(t *testing.T) {
	s := NewStore("")
	s.now = func() time.Time { return now }
	logins := ciLogins("infrafence-deploy", "20.42", ServiceUserNets+1, now)
	logins = append(logins, ciLogins("ci10", "40.2", ServiceUserNets, now)...)
	logins = append(logins,
		// The administrator: two networks, one shared with a deploy run.
		Login{IP: "81.2.69.142", User: "root", Time: now.Add(-24 * time.Hour)},
		Login{IP: "20.42.3.7", User: "root", Time: now.Add(-2 * time.Hour)},
	)
	// Twelve addresses of one IPv6 /48: one network.
	for i := 1; i <= 12; i++ {
		logins = append(logins, Login{IP: fmt.Sprintf("2a01:4f8:1:%x::5", i), User: "v6", Time: now.Add(-time.Hour)})
	}
	s.Apply(Result{Logins: logins}, now)
	// A live login whose user is unknown.
	s.Note("52.1.1.1", "", now)

	svc := s.ServiceUsers()
	if len(svc) != 1 || svc[0].User != "infrafence-deploy" || svc[0].Nets != ServiceUserNets+1 || svc[0].Listed {
		t.Fatalf("service users %+v", svc)
	}
	if _, ok, known := s.Protected("20.42.5.7"); ok || !known {
		t.Error("a deploy-only address is protected")
	}
	if _, ok := s.LastLogin("20.42.5.7"); !ok {
		t.Error("LastLogin must still see every login")
	}
	for _, ip := range []string{"20.42.3.7", "81.2.69.142", "40.2.10.7", "2a01:4f8:1:c::5", "52.1.1.1", "::ffff:81.2.69.142"} {
		if _, ok, _ := s.Protected(ip); !ok {
			t.Errorf("%s not protected", ip)
		}
	}
	if _, ok, known := s.Protected("192.0.2.1"); ok || known {
		t.Error("unknown address")
	}
	all, prot := s.IPs(), s.ProtectedIPs()
	if len(all)-len(prot) != ServiceUserNets {
		t.Errorf("%d addresses, %d protected", len(all), len(prot))
	}
	for _, ip := range prot {
		if strings.HasPrefix(ip, "20.42.") && ip != "20.42.3.7" {
			t.Errorf("protected %s", ip)
		}
	}

	// One more network for ci10 makes it a service user.
	s.Note("40.2.11.7", "ci10", now)
	if _, ok, _ := s.Protected("40.2.1.7"); ok {
		t.Error("ci10 with 11 networks still protects")
	}
}

func TestServiceUsersListed(t *testing.T) {
	s := NewStore("")
	s.now = func() time.Time { return now }
	s.Apply(Result{Logins: []Login{
		{IP: "89.160.20.112", User: "ops", Time: now.Add(-time.Hour)},
		{IP: "89.160.20.112", User: "root", Time: now.Add(-time.Hour)},
		{IP: "89.160.30.5", User: "ops", Time: now.Add(-time.Hour)},
	}}, now)
	if !s.SetServiceUsers([]string{"ops", "bad user", strings.Repeat("x", 65), ""}) {
		t.Fatal("list not taken")
	}
	if s.SetServiceUsers([]string{"ops"}) {
		t.Error("the same list counts as a change")
	}
	if _, ok, _ := s.Protected("89.160.30.5"); ok {
		t.Error("a listed user protects")
	}
	if _, ok, _ := s.Protected("89.160.20.112"); !ok {
		t.Error("root's address lost its protection")
	}
	if svc := s.ServiceUsers(); len(svc) != 1 || svc[0].User != "ops" || !svc[0].Listed || svc[0].Nets != 2 {
		t.Errorf("service users %+v", svc)
	}
	if !s.SetServiceUsers(nil) {
		t.Error("an empty list is a change")
	}
	if _, ok, _ := s.Protected("89.160.30.5"); !ok {
		t.Error("unlisted user still unprotected")
	}
}

// Past MaxEntries the addresses only service users logged in from go first.
func TestStoreBoundServiceFirst(t *testing.T) {
	s := NewStore("")
	s.now = func() time.Time { return now }
	s.Note("81.2.69.142", "root", now.Add(-20*24*time.Hour))
	for i := 0; i < MaxEntries; i++ {
		s.Note(fmt.Sprintf("20.%d.%d.7", 40+i/250, i%250), "deploy", now.Add(-time.Duration(MaxEntries-i)*time.Minute))
	}
	if n := len(s.IPs()); n != MaxEntries {
		t.Errorf("%d entries", n)
	}
	if _, ok, _ := s.Protected("81.2.69.142"); !ok {
		t.Error("the administrator was pushed out by a deploy account")
	}
}
