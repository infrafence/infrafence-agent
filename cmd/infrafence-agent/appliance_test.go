package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/config"
	"github.com/infrafence/infrafence-agent/internal/opnsense"
	"github.com/infrafence/infrafence-agent/internal/pf"
	"github.com/infrafence/infrafence-agent/internal/pf/pftest"
	"github.com/infrafence/infrafence-agent/internal/platform"
)

// fakeDash is a minimal dashboard: it serves a sync body and records what
// the agent posts.
type fakeDash struct {
	mu        sync.Mutex
	sync      map[string]any
	events    []api.EventRequest
	bans      []api.BanRequest
	heartbeat map[string]json.RawMessage
	modes     []api.ModeRequest
	modeCode  int
	// busy answers 429 with Retry-After to these paths.
	busy map[string]bool
	hits map[string]int
}

func (d *fakeDash) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.hits == nil {
		d.hits = map[string]int{}
	}
	d.hits[r.URL.Path]++
	if d.busy[r.URL.Path] {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	switch r.URL.Path {
	case "/api/v1/agent/sync":
		_ = json.NewEncoder(w).Encode(d.sync)
	case "/api/v1/agent/events":
		var evs []api.EventRequest
		var wrap struct {
			Events []api.EventRequest `json:"events"`
		}
		if json.Unmarshal(body, &wrap) == nil && len(wrap.Events) > 0 {
			evs = wrap.Events
		} else {
			_ = json.Unmarshal(body, &evs)
		}
		d.events = append(d.events, evs...)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	case "/api/v1/agent/bans":
		var b api.BanRequest
		_ = json.Unmarshal(body, &b)
		d.bans = append(d.bans, b)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	case "/api/v1/agent/heartbeat":
		d.heartbeat = map[string]json.RawMessage{}
		_ = json.Unmarshal(body, &d.heartbeat)
		_, _ = w.Write([]byte(`{"status":"ok","config_version":"1"}`))
	case "/api/v1/agent/mode":
		var m api.ModeRequest
		_ = json.Unmarshal(body, &m)
		d.modes = append(d.modes, m)
		if d.modeCode != 0 {
			w.WriteHeader(d.modeCode)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	default:
		http.NotFound(w, r)
	}
}

func (d *fakeDash) eventsOf(typ string) []api.EventRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []api.EventRequest
	for _, e := range d.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func testAppliance(t *testing.T) (*appliance, *pftest.Fake, *fakeDash) {
	t.Helper()
	dir := t.TempDir()
	oldState, oldRun, oldXML, oldGeo := applianceStateDir, applianceRunDir, applianceConfXML, applianceGeoIPDir
	applianceStateDir, applianceRunDir = filepath.Join(dir, "db"), filepath.Join(dir, "run")
	applianceConfXML = filepath.Join("..", "..", "internal", "opnsense", "testdata", "config-exposed.xml")
	applianceGeoIPDir = filepath.Join(dir, "geoip")
	t.Cleanup(func() {
		applianceStateDir, applianceRunDir, applianceConfXML, applianceGeoIPDir = oldState, oldRun, oldXML, oldGeo
	})
	dash := &fakeDash{sync: map[string]any{
		"config": map[string]any{"bf_threshold": 3, "bf_window": 60, "monitor_mode": false},
		"rules":  []any{}, "bans": []any{}, "whitelists": []any{},
	}}
	srv := httptest.NewServer(dash)
	t.Cleanup(srv.Close)
	cfg := &config.Config{ServerURL: srv.URL, AgentToken: "agent-token-for-tests", AgentID: 7}
	client := api.New(srv.URL, cfg.AgentToken)
	f := pftest.NewFake()
	a := newAppliance(cfg, client, f.Run)
	a.info = platform.Info{Kind: platform.KindOPNsense, Product: "OPNsense", Version: "26.7.1", Arch: "amd64"}
	a.refreshConfig(true)
	a.guardTick()
	a.syncs = newSyncRunner(a.sync)
	return a, f, dash
}

func flush(t *testing.T, a *appliance) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.client.FlushEvents(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestApplianceSyncAppliesBansAllowAndThreat(t *testing.T) {
	a, f, dash := testAppliance(t)
	dash.sync["bans"] = []map[string]any{{"id": 1, "ip_address": "80.94.95.1", "expires_at": nil}, {"id": 2, "ip_address": "192.168.10.5"}}
	dash.sync["whitelists"] = []map[string]any{{"id": 1, "ip_address": "37.19.221.10"}}
	dash.sync["threat_feed"] = []map[string]any{{"cidr": "185.220.101.0/24", "source": "spamhaus"}}
	dash.sync["config"] = map[string]any{"bf_threshold": 3, "bf_window": 60, "monitor_config": map[string]any{"block_threat_feeds": true}}
	if err := a.sync(); err != nil {
		t.Fatal(err)
	}
	bans := strings.Join(f.Entries(pf.TableBans), " ")
	if !strings.Contains(bans, "80.94.95.1") || strings.Contains(bans, " 192.168.10.5") {
		t.Fatalf("bans table %s", bans)
	}
	if !strings.Contains(bans, "!37.19.221.10") || !strings.Contains(bans, "!85.1.2.3") {
		t.Fatalf("allow list / own WAN address not negated: %s", bans)
	}
	if !strings.Contains(strings.Join(f.Entries(pf.TableThreat), " "), "185.220.101.0/24") {
		t.Fatal("threat feed not applied")
	}
	// Learning from the dashboard: tables hold only negations.
	dash.sync["config"] = map[string]any{"bf_threshold": 3, "bf_window": 60, "monitor_mode": true}
	a.sync()
	for _, tb := range pf.Tables {
		for _, e := range f.Entries(tb) {
			if !strings.HasPrefix(e, "!") {
				t.Fatalf("Learning: %s blocks %s", tb, e)
			}
		}
	}
	a.guardTick()
	if a.applianceState().Protection != "learning" {
		t.Fatal(a.applianceState().Protection)
	}
}

func TestApplianceBruteForce(t *testing.T) {
	a, f, dash := testAppliance(t)
	a.sync()
	for i := 0; i < 3; i++ {
		a.onAuth(opnsense.AuthEvent{Service: "opnsense-gui", Result: "failure", IP: "45.155.205.233", User: "root", Reason: "brute_force_gui"})
	}
	// An internal host: reported, never banned.
	for i := 0; i < 3; i++ {
		a.onAuth(opnsense.AuthEvent{Service: "ssh", Result: "failure", IP: "192.168.10.50", Reason: "brute_force_ssh"})
	}
	flush(t, a)
	if !strings.Contains(strings.Join(f.Entries(pf.TableBans), " "), "45.155.205.233") {
		t.Fatal("not banned")
	}
	if strings.Contains(strings.Join(f.Entries(pf.TableBans), " "), " 192.168.10.50") {
		t.Fatal("internal address banned")
	}
	evs := dash.eventsOf("brute_force")
	if len(evs) != 2 {
		t.Fatalf("events %+v", evs)
	}
	got := map[string]map[string]string{}
	for _, e := range evs {
		got[e.SourceIP] = e.Details
	}
	if d := got["45.155.205.233"]; d["action"] != "banned" || d["service"] != "opnsense-gui" || d["reason"] != "brute_force_gui" || d["attempts"] != "3" {
		t.Fatalf("ban event %v", d)
	}
	if d := got["192.168.10.50"]; d["action"] != "not_banned" || !strings.Contains(d["not_banned"], "internal") && !strings.Contains(d["not_banned"], "private") {
		t.Fatalf("internal event %v", d)
	}
	dash.mu.Lock()
	nb := len(dash.bans)
	dash.mu.Unlock()
	if nb != 1 {
		t.Fatalf("%d bans reported", nb)
	}
}

func TestApplianceLearningWouldBan(t *testing.T) {
	a, f, dash := testAppliance(t)
	dash.sync["config"] = map[string]any{"bf_threshold": 2, "bf_window": 60, "monitor_mode": true}
	a.sync()
	a.onAuth(opnsense.AuthEvent{Service: "ssh", Result: "failure", IP: "45.155.205.233", Reason: "brute_force_ssh"})
	a.onAuth(opnsense.AuthEvent{Service: "ssh", Result: "failure", IP: "45.155.205.233", Reason: "brute_force_ssh"})
	flush(t, a)
	evs := dash.eventsOf("brute_force")
	if len(evs) != 1 || evs[0].Details["action"] != "would_ban" {
		t.Fatalf("%+v", evs)
	}
	for _, e := range f.Entries(pf.TableBans) {
		if !strings.HasPrefix(e, "!") {
			t.Fatal("Learning banned")
		}
	}
}

func TestApplianceAdminLoginExempts(t *testing.T) {
	a, _, dash := testAppliance(t)
	a.sync()
	a.onAuth(opnsense.AuthEvent{Service: "opnsense-gui", Result: "success", IP: "62.4.1.9", User: "root"})
	flush(t, a)
	if ev := dash.eventsOf("admin_login"); len(ev) != 1 || ev[0].Severity != "info" || ev[0].Details["new_address"] != "true" {
		t.Fatalf("%+v", ev)
	}
	if why := a.store.Why("62.4.1.9"); !strings.Contains(why, "administrator") {
		t.Fatalf("admin address not protected: %q", why)
	}
	// Saved across a restart.
	if _, err := os.Stat(applianceLoginsPath()); err != nil {
		t.Fatal(err)
	}
	// A login right after failures is a guess that worked: critical, not exempt.
	a.onAuth(opnsense.AuthEvent{Service: "ssh", Result: "failure", IP: "45.155.205.7"})
	a.onAuth(opnsense.AuthEvent{Service: "ssh", Result: "failure", IP: "45.155.205.7"})
	a.onAuth(opnsense.AuthEvent{Service: "ssh", Result: "success", IP: "45.155.205.7", User: "root"})
	flush(t, a)
	var crit bool
	for _, e := range dash.eventsOf("admin_login") {
		if e.SourceIP == "45.155.205.7" && e.Severity == "critical" {
			crit = true
		}
	}
	if !crit || a.store.Why("45.155.205.7") != "" {
		t.Fatal("guessed login not flagged or exempted")
	}
}

func TestAppliancePortScanAndBlocks(t *testing.T) {
	a, f, dash := testAppliance(t)
	dash.sync["config"] = map[string]any{"bf_threshold": 3, "bf_window": 60, "monitor_config": map[string]any{"port_scan_ban": true}}
	a.sync()
	for p := 1000; p < 1020; p++ {
		a.onFilter(opnsense.FilterRecord{Action: "block", Dir: "in", Interface: "vtnet1", Proto: "tcp", Src: "45.155.205.99", Dst: "85.1.2.3", DstPort: p})
	}
	// LAN side blocks do not count (vtnet0 is LAN in the fixture).
	a.onFilter(opnsense.FilterRecord{Action: "block", Dir: "in", Interface: "vtnet0", Proto: "tcp", Src: "45.155.205.98", DstPort: 1})
	a.reportBlocks(time.Now())
	flush(t, a)
	if ev := dash.eventsOf("port_scan"); len(ev) != 1 || ev[0].Details["detection"] != "filterlog" {
		t.Fatalf("%+v", ev)
	}
	// Blocked packets can carry a forged source: reported, never banned.
	if strings.Contains(strings.Join(f.Entries(pf.TableBans), " "), "45.155.205.99") {
		t.Fatal("filterlog scanner banned")
	}
	if ev := dash.eventsOf("port_scan"); ev[0].Details["not_banned"] == "" {
		t.Fatalf("%+v", ev[0].Details)
	}
	ev := dash.eventsOf("fw_blocks")
	if len(ev) != 1 || ev[0].Details["blocked"] != "20" || ev[0].Details["top_sources"] != "45.155.205.99=20" {
		t.Fatalf("%+v", ev)
	}
}

func TestApplianceIDSDedup(t *testing.T) {
	a, _, dash := testAppliance(t)
	al, ok := opnsense.ParseEve(`{"timestamp":"2026-11-15T09:40:01.1+0100","in_iface":"vtnet1","event_type":"alert","src_ip":"45.155.205.233","src_port":5,"dest_ip":"85.1.2.3","dest_port":443,"proto":"TCP","alert":{"action":"blocked","signature_id":2024897,"rev":3,"signature":"ET SCAN Nmap","category":"Attack","severity":1}}`)
	if !ok {
		t.Fatal("parse")
	}
	for i := 0; i < 5; i++ {
		a.onIDS(al)
	}
	flush(t, a)
	ev := dash.eventsOf("ids_alert")
	if len(ev) != 1 || ev[0].Severity != "critical" || ev[0].Details["signature_id"] != "2024897" || *ev[0].TargetPort != 443 {
		t.Fatalf("%+v", ev)
	}
}

func TestApplianceHeartbeatAndStatus(t *testing.T) {
	a, _, dash := testAppliance(t)
	a.sync()
	a.runChecks(context.Background())
	a.heartbeat(nil)
	dash.mu.Lock()
	hb := dash.heartbeat
	dash.mu.Unlock()
	if string(hb["kind"]) != `"opnsense"` || string(hb["firewall_mode"]) != `"pf"` {
		t.Fatalf("kind %s mode %s", hb["kind"], hb["firewall_mode"])
	}
	var caps []string
	json.Unmarshal(hb["capabilities"], &caps)
	if len(caps) == 0 || caps[0] != "bans" {
		t.Fatalf("caps %v", caps)
	}
	var app applianceInfo
	if err := json.Unmarshal(hb["appliance"], &app); err != nil {
		t.Fatal(err)
	}
	if app.Product != "OPNsense" || app.Protection != "active" || !app.IDSEnabled || !app.HA || len(app.Findings) == 0 || app.Tables.Limit == 0 {
		t.Fatalf("%+v", app)
	}
	if strings.Contains(string(hb["appliance"]), "$2y$") || strings.Contains(string(hb["appliance"]), "agent-token") {
		t.Fatal("secret in the heartbeat")
	}
	data, err := os.ReadFile(applianceStatusPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "agent-token") {
		t.Fatal("token in status.json")
	}
	var st applianceStatus
	json.Unmarshal(data, &st)
	if st.AgentID != 7 || st.LastHeartbeat == "" || st.Appliance.Mode != "protect" {
		t.Fatalf("%+v", st)
	}
}

func TestApplianceDetectOnly(t *testing.T) {
	a, f, dash := testAppliance(t)
	f.Declare(pf.TableBans, false)
	a.guardTick()
	flush(t, a)
	if st := a.applianceState(); st.Protection != "detect_only" || st.Tables.Ready {
		t.Fatalf("%+v", st)
	}
	if ev := dash.eventsOf("appliance_protection"); len(ev) != 1 || ev[0].Details["state"] != "detect_only" {
		t.Fatalf("%+v", ev)
	}
}

func TestApplianceCountriesFromOPNsenseGeoIP(t *testing.T) {
	a, f, dash := testAppliance(t)
	os.MkdirAll(applianceGeoIPDir, 0o755)
	os.WriteFile(filepath.Join(applianceGeoIPDir, "RU-IPv4"), []byte("5.8.0.0/16\n31.13.0.0/18\n"), 0o644)
	os.WriteFile(filepath.Join(applianceGeoIPDir, "RU-IPv6"), []byte("2a00:1fa0::/29\n"), 0o644)
	dash.sync["config"] = map[string]any{"bf_threshold": 3, "bf_window": 60, "blocked_countries": []string{"ru"}}
	a.sync()
	got := strings.Join(f.Entries(pf.TableGeo), " ")
	for _, n := range []string{"5.8.0.0/16", "31.13.0.0/18", "2a00:1fa0::/29"} {
		if !strings.Contains(got, n) {
			t.Fatalf("geo table %s lacks %s", got, n)
		}
	}
	if a.applianceState().GeoSource != "opnsense-geoip" {
		t.Fatal(a.applianceState().GeoSource)
	}
}

func TestApplianceSetMode(t *testing.T) {
	_, _, dash := testAppliance(t)
	// applianceSetMode loads the config file.
	dir := t.TempDir()
	t.Setenv("INFRAFENCE_CONFIG", filepath.Join(dir, "config.json"))
	srv := httptest.NewServer(dash)
	defer srv.Close()
	if err := config.Save(&config.Config{ServerURL: srv.URL, AgentToken: "tok", AgentID: 1}); err != nil {
		t.Fatal(err)
	}
	res, code := applianceSetMode("monitor", "admin")
	if code != 0 || res["status"] != "ok" || len(dash.modes) != 1 || dash.modes[0].Mode != "monitor" || dash.modes[0].Source != "opnsense-gui" {
		t.Fatalf("%v %d %+v", res, code, dash.modes)
	}
	dash.modeCode = http.StatusNotFound
	if res, code := applianceSetMode("protect", "admin"); code == 0 || res["status"] != "unsupported" {
		t.Fatalf("old dashboard: %v", res)
	}
}

func TestParseRegisterArgs(t *testing.T) {
	u, n, tok, m, err := parseRegisterArgs([]string{"https://d", "fw", "tok123"}, strings.NewReader(""))
	if err != nil || u != "https://d" || n != "fw" || tok != "tok123" || m != "" {
		t.Fatalf("classic form: %q %q %q %q %v", u, n, tok, m, err)
	}
	u, n, tok, m, err = parseRegisterArgs([]string{"--token-stdin", "--mode", "monitor", "https://d", "fw"}, strings.NewReader("secret-token\n"))
	if err != nil || tok != "secret-token" || m != "monitor" || u != "https://d" || n != "fw" {
		t.Fatalf("stdin form: %q %q %q %q %v", u, n, tok, m, err)
	}
	if _, _, _, _, err := parseRegisterArgs([]string{"--mode=bogus", "a", "b", "c"}, nil); err == nil {
		t.Fatal("bad mode accepted")
	}
	if _, _, _, _, err := parseRegisterArgs([]string{"--token-stdin", "a", "b"}, strings.NewReader("")); err == nil {
		t.Fatal("empty stdin accepted")
	}
}

func TestRegisterJSONUnchangedForServers(t *testing.T) {
	// The server agent's register request carries none of the new fields.
	req := api.RegisterRequest{InstallToken: "t", Name: "n", OS: "ubuntu"}
	if kind := applianceRegister(&req, "monitor"); kind != "" && kind != platform.KindOPNsense {
		t.Fatal(kind)
	}
	if applianceRegisterIsNoop() {
		b, _ := json.Marshal(req)
		for _, k := range []string{"kind", "mode", "platform"} {
			if strings.Contains(string(b), `"`+k+`"`) {
				t.Fatalf("%s in %s", k, b)
			}
		}
	}
	var r2 api.RegisterRequest
	fillApplianceRegister(&r2, "monitor", platform.Info{Kind: platform.KindOPNsense, Product: "OPNsense", Version: "26.7.1", Arch: "amd64"})
	b, _ := json.Marshal(r2)
	if !strings.Contains(string(b), `"kind":"opnsense"`) || !strings.Contains(string(b), `"mode":"monitor"`) || !strings.Contains(string(b), `"os":"opnsense"`) {
		t.Fatal(string(b))
	}
	// Heartbeat: nothing new for servers either.
	hb, _ := json.Marshal(api.HeartbeatRequest{Status: "online"})
	for _, k := range []string{"kind", "capabilities", "appliance"} {
		if strings.Contains(string(hb), `"`+k+`"`) {
			t.Fatalf("%s in %s", k, hb)
		}
	}
}

func TestApplianceSpoofableNeverBanned(t *testing.T) {
	a, f, dash := testAppliance(t)
	a.sync()
	for i := 0; i < 5; i++ {
		a.onAuth(opnsense.AuthEvent{Service: "openvpn", Result: "failure", IP: "80.94.95.11", Reason: "brute_force_vpn", Spoofable: true})
	}
	flush(t, a)
	if strings.Contains(strings.Join(f.Entries(pf.TableBans), " "), "80.94.95.11") {
		t.Fatal("spoofable source banned")
	}
	ev := dash.eventsOf("brute_force")
	if len(ev) != 1 || ev[0].Details["action"] != "not_banned" || ev[0].Severity != "warning" {
		t.Fatalf("%+v", ev)
	}
}

func TestAppliance429IsRetryLater(t *testing.T) {
	a, f, dash := testAppliance(t)
	a.sync()
	dash.mu.Lock()
	dash.busy = map[string]bool{"/api/v1/agent/sync": true, "/api/v1/agent/heartbeat": true, "/api/v1/agent/bans": true}
	dash.mu.Unlock()
	if err := a.sync(); err != nil {
		t.Fatalf("429 on sync is an error: %v", err)
	}
	a.heartbeat(nil)
	st := a.applianceState()
	a.mu.Lock()
	syncErr := a.lastSyncErr
	a.mu.Unlock()
	if syncErr != "" || st.Protection != "active" {
		t.Fatalf("429 changed the state: %q %+v", syncErr, st)
	}
	// A ban reported during a 429 is kept and reported again later.
	for i := 0; i < 3; i++ {
		a.onAuth(opnsense.AuthEvent{Service: "ssh", Result: "failure", IP: "45.155.205.233", Reason: "brute_force_ssh"})
	}
	if !strings.Contains(strings.Join(f.Entries(pf.TableBans), " "), "45.155.205.233") {
		t.Fatal("not banned during a 429")
	}
	dash.mu.Lock()
	dash.busy = nil
	dash.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		dash.mu.Lock()
		n := len(dash.bans)
		dash.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	dash.mu.Lock()
	defer dash.mu.Unlock()
	if len(dash.bans) != 1 || dash.hits["/api/v1/agent/bans"] < 2 {
		t.Fatalf("ban not retried after the 429: %d bans, %d tries", len(dash.bans), dash.hits["/api/v1/agent/bans"])
	}
}

func TestApplianceMode429(t *testing.T) {
	_, _, dash := testAppliance(t)
	t.Setenv("INFRAFENCE_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	srv := httptest.NewServer(dash)
	defer srv.Close()
	config.Save(&config.Config{ServerURL: srv.URL, AgentToken: "tok", AgentID: 1})
	dash.busy = map[string]bool{"/api/v1/agent/mode": true}
	res, code := applianceSetMode("monitor", "admin")
	if code == 0 || res["status"] != "retry_later" || !strings.Contains(res["message"], "try again") {
		t.Fatalf("%v", res)
	}
}

func TestApplianceSlimSync(t *testing.T) {
	a, f, dash := testAppliance(t)
	// The dashboard's slim OPNsense sync: no "rules", threat_feed [].
	dash.sync = map[string]any{
		"config": map[string]any{"monitor_mode": false, "suspended": false, "bf_threshold": 5, "bf_window": 600, "bf_ban_duration": 1440,
			"blocked_countries": []string{}, "monitor_config": map[string]any{"block_threat_feeds": true}},
		"bans":        []map[string]any{{"id": 1, "ip_address": "80.94.95.1", "expires_at": nil, "source": "network"}},
		"whitelists":  []any{},
		"threat_feed": []any{},
	}
	if err := a.sync(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.Entries(pf.TableBans), " "), "80.94.95.1") {
		t.Fatal("ban from the slim sync not applied")
	}
	if got := positiveEntries(f.Entries(pf.TableThreat)); len(got) != 0 {
		t.Fatalf("threat table %v", got)
	}
	if st := a.applianceState(); st.Protection != "active" {
		t.Fatal(st.Protection)
	}
}

func positiveEntries(list []string) []string {
	var out []string
	for _, e := range list {
		if !strings.HasPrefix(e, "!") {
			out = append(out, e)
		}
	}
	return out
}

func TestApplianceUnauthenticatedSourceFlag(t *testing.T) {
	a, _, dash := testAppliance(t)
	a.sync()
	// filterlog: port scan and the blocks summary carry the flag.
	for p := 2000; p < 2020; p++ {
		a.onFilter(opnsense.FilterRecord{Action: "block", Dir: "in", Interface: "vtnet1", Proto: "tcp", Src: "45.155.205.98", Dst: "85.1.2.3", DstPort: p})
	}
	a.reportBlocks(time.Now())
	// IDS: UDP flagged, TCP not.
	udp, _ := opnsense.ParseEve(`{"event_type":"alert","src_ip":"45.155.205.50","src_port":53,"dest_ip":"85.1.2.3","dest_port":5060,"proto":"UDP","alert":{"signature_id":1,"signature":"x","severity":2}}`)
	tcp, _ := opnsense.ParseEve(`{"event_type":"alert","src_ip":"45.155.205.51","src_port":5,"dest_ip":"85.1.2.3","dest_port":443,"proto":"TCP","alert":{"signature_id":2,"signature":"y","severity":2}}`)
	a.onIDS(udp)
	a.onIDS(tcp)
	// Authenticated or TCP-handshake sources: no flag.
	for i := 0; i < 3; i++ {
		a.onAuth(opnsense.AuthEvent{Service: "ssh", Result: "failure", IP: "45.155.205.233", Reason: "brute_force_ssh"})
	}
	a.onAuth(opnsense.AuthEvent{Service: "opnsense-gui", Result: "success", IP: "62.4.1.9", User: "root"})
	flush(t, a)
	flag := func(e api.EventRequest) bool { return e.Details["unauthenticated_source"] == "true" }
	for _, typ := range []string{"port_scan", "fw_blocks"} {
		ev := dash.eventsOf(typ)
		if len(ev) != 1 || !flag(ev[0]) {
			t.Errorf("%s: %+v", typ, ev)
		}
	}
	for _, e := range dash.eventsOf("ids_alert") {
		if want := e.SourceIP == "45.155.205.50"; flag(e) != want {
			t.Errorf("ids_alert %s flag=%v", e.SourceIP, flag(e))
		}
	}
	for _, typ := range []string{"brute_force", "admin_login"} {
		for _, e := range dash.eventsOf(typ) {
			if flag(e) {
				t.Errorf("%s from an authenticated source flagged: %+v", typ, e)
			}
		}
	}
}
