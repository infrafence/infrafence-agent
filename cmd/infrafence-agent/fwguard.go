package main

import (
	"log"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/preflight"
)

// The firewall guard keeps the INFRAFENCE chains, jumps and sets in place.
// Other tools (ufw/firewalld reloads, csf -r, netfilter-persistent,
// iptables-restore) can remove them, which silently stops every ban; the
// guard puts them back and reports it.
//
//   - Every minute a full Ensure; every 5 s in between only a look at the
//     INPUT jump (firewall.NeedsRepair, one iptables call), so a rebuild that
//     flushes everything is repaired within seconds. A check that is slow
//     on a huge rule set spaces the next ones out.
//   - A repair found by the quick check is followed by a second Ensure 2 s
//     later, so a tool still adding ACCEPT rules cannot keep its rules
//     ahead of the jump.
//   - Nothing is repaired while csf rebuilds the firewall (its lock held),
//     for at most 2 minutes per lock holder: a hung csf must not leave the
//     server without bans.
//   - Back-off from 5 s to 60 s after an error and after a repair within
//     30 s of the previous one; reset after 5 quiet minutes.
//   - At most one firewall_rules_restored event a minute (with the number
//     of repairs since the last one). Back-to-back repairs, or 3 a hour,
//     mean another tool keeps rewriting the firewall: one firewall_conflict
//     an hour.
//   - Except a restore that only moves the agent's jumps back ahead of the
//     chains of a tool that recreates its rules on a timer (Imunify360,
//     every minute: preflight.PeriodicRuleOwner). That is expected: the
//     first is logged at once, the others are counted and summarized once
//     an hour, in the log and as an info event (never a warning or a
//     firewall_conflict), and they do not count towards the back-off. A
//     restore that repairs anything else is logged and reported as above.
const (
	guardTick       = time.Second
	guardQuick      = 5 * time.Second
	guardFull       = time.Minute
	guardFollowUp   = 2 * time.Second
	guardBackToBack = 30 * time.Second
	guardBackoffMin = 5 * time.Second
	guardBackoffMax = time.Minute
	guardQuiet      = 5 * time.Minute
	guardCSFWait    = 2 * time.Minute
	guardEventEvery = time.Minute
	guardConflict   = time.Hour
	guardExpected   = time.Hour
)

type firewallGuard struct {
	now         func() time.Time
	needsRepair func() (bool, error)
	csfHolder   func() (pid int, held bool)
	ensure      func() (firewall.EnsureResult, error)
	report      func([]api.EventRequest) error
	// periodicOwner names the installed tool that owns a chain and
	// recreates its rules on a timer ("" for none); nil: none.
	periodicOwner func(chain string) string
	// earlyDrop reports whether bans are also dropped in the raw table.
	earlyDrop func() bool

	nextQuick, nextFull, followUp time.Time

	backoff     time.Duration
	retryAt     time.Time // no repair before (back-off)
	lastTrouble time.Time // last error or back-to-back repair

	lastRepair   time.Time
	repairs      []time.Time // the last hour's, 30 s apart at least
	lastConflict time.Time

	lastEvent   time.Time
	pendingN    int
	pendingWhat map[string]bool

	csfPID    int
	csfSince  time.Time
	csfForced bool // waited long enough for this lock holder

	// Expected restores (expectedAfter): the first was logged; then how
	// many since expSince, after which tools, repairing what.
	expLogged    bool
	lastExpected time.Time
	expSince     time.Time
	expN         int
	expTools     map[string]bool
	expWhat      map[string]bool
}

func newFirewallGuard(client *api.Client) *firewallGuard {
	g := &firewallGuard{
		now:         time.Now,
		needsRepair: firewall.NeedsRepair,
		csfHolder:   firewall.CSFLockHolder,
		ensure:      firewall.Ensure,
		report:      client.ReportEvents,

		periodicOwner: preflight.PeriodicRuleOwner,
		earlyDrop:     firewall.EarlyDropInForce,
	}
	g.start()
	return g
}

func (g *firewallGuard) start() {
	now := g.now()
	g.nextQuick, g.nextFull = now.Add(guardQuick), now.Add(guardFull)
}

func runFirewallGuard(client *api.Client) {
	g := newFirewallGuard(client)
	for range time.Tick(guardTick) {
		g.tick()
	}
}

// tick does whatever is due now.
func (g *firewallGuard) tick() {
	now := g.now()
	g.flushEvents(now)
	g.flushExpected(now)
	if g.backoff > 0 && now.Sub(g.lastTrouble) >= guardQuiet {
		g.backoff, g.retryAt = 0, time.Time{}
	}
	followUp, full, quick := false, false, false
	switch {
	case !g.followUp.IsZero() && !now.Before(g.followUp):
		followUp = true
	case !now.Before(g.nextFull):
		full = true
	case !now.Before(g.nextQuick):
		missing, err := g.needsRepair()
		took := g.now().Sub(now)
		g.nextQuick = now.Add(guardQuick)
		if err != nil {
			log.Printf("[firewall] guard: check: %v", err)
			g.trouble(now)
			g.nextQuick = g.retryAt
			return
		}
		if !missing {
			// Only a check that found everything in place measures the
			// rule set's cost: one made while another tool rewrites it
			// is slow for that reason alone.
			if d := 10 * took; d > guardQuick {
				g.nextQuick = now.Add(d)
			}
			return
		}
		quick = true
	default:
		return
	}
	if now.Before(g.retryAt) || g.waitForCSF(now) {
		return // the due follow-up or full check stays due
	}
	if followUp {
		g.followUp = time.Time{}
	}
	if full {
		g.nextFull = now.Add(guardFull)
	}
	res, err := g.ensure()
	if err != nil {
		log.Printf("[firewall] guard: %v", err)
		g.trouble(now)
		return
	}
	if res.First || len(res.Repairs) == 0 {
		return
	}
	if quick {
		g.followUp = now.Add(guardFollowUp)
	}
	// A tool's periodic rebuild comes a minute apart: one within 30 s of
	// the last (its follow-up aside) is not that, and is reported as usual.
	if tools := g.expectedAfter(res); tools != "" && (followUp || g.lastExpected.IsZero() || now.Sub(g.lastExpected) >= guardBackToBack) {
		if !followUp {
			g.lastExpected = now
		}
		g.noteExpected(now, tools, res.Repairs)
		return
	}
	log.Printf("[firewall] guard: restored %v", res.Repairs)
	// A follow-up finishing the same rebuild is not the other tool
	// rewriting the firewall again.
	backToBack := !followUp && !g.lastRepair.IsZero() && now.Sub(g.lastRepair) < guardBackToBack
	g.lastRepair = now
	if backToBack {
		g.trouble(now)
	}
	g.noteRepair(now, res.Repairs, backToBack)
}

// trouble starts or doubles the back-off.
func (g *firewallGuard) trouble(now time.Time) {
	switch {
	case g.backoff == 0:
		g.backoff = guardBackoffMin
	case g.backoff < guardBackoffMax:
		g.backoff = min(2*g.backoff, guardBackoffMax)
	}
	g.retryAt, g.lastTrouble = now.Add(g.backoff), now
}

// waitForCSF reports whether to leave the firewall alone because csf is
// rebuilding it.
func (g *firewallGuard) waitForCSF(now time.Time) bool {
	pid, held := g.csfHolder()
	if !held {
		g.csfPID, g.csfSince, g.csfForced = 0, time.Time{}, false
		return false
	}
	if pid != g.csfPID || g.csfSince.IsZero() {
		g.csfPID, g.csfSince, g.csfForced = pid, now, false
	}
	if g.csfForced {
		return false
	}
	if now.Sub(g.csfSince) < guardCSFWait {
		return true
	}
	g.csfForced = true
	log.Printf("[firewall] guard: csf (pid %d) has held its restart lock for %s, repairing anyway", pid, now.Sub(g.csfSince).Round(time.Second))
	return false
}

// noteRepair queues the repair for the next firewall_rules_restored event
// and raises firewall_conflict when another tool keeps rewriting the rules.
func (g *firewallGuard) noteRepair(now time.Time, what []string, backToBack bool) {
	if g.pendingWhat == nil {
		g.pendingWhat = map[string]bool{}
	}
	g.pendingN++
	for _, w := range what {
		g.pendingWhat[w] = true
	}
	recent := g.repairs[:0]
	for _, t := range g.repairs {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 || now.Sub(recent[len(recent)-1]) >= guardBackToBack {
		recent = append(recent, now)
	}
	g.repairs = recent
	g.flushEvents(now)
	if (backToBack || len(g.repairs) >= 3) && (g.lastConflict.IsZero() || now.Sub(g.lastConflict) >= guardConflict) {
		g.lastConflict = now
		g.send([]api.EventRequest{{
			Type:     "firewall_conflict",
			Severity: "warning",
			Details: map[string]string{
				"restores_last_hour": strconv.Itoa(len(g.repairs)),
				"back_to_back":       strconv.FormatBool(backToBack),
				"hint":               "another tool keeps rewriting the firewall (ufw, firewalld, csf, netfilter-persistent, a config-management run?)",
			},
			OccurredAt: now.UTC().Format(time.RFC3339),
		}})
	}
}

// flushEvents sends the queued repairs as one event, at most once a minute.
func (g *firewallGuard) flushEvents(now time.Time) {
	if g.pendingN == 0 || (!g.lastEvent.IsZero() && now.Sub(g.lastEvent) < guardEventEvery) {
		return
	}
	what := make([]string, 0, len(g.pendingWhat))
	for w := range g.pendingWhat {
		what = append(what, w)
	}
	sort.Strings(what)
	g.send([]api.EventRequest{{
		Type:       "firewall_rules_restored",
		Severity:   "warning",
		Details:    map[string]string{"restored": strings.Join(what, ", "), "count": strconv.Itoa(g.pendingN)},
		OccurredAt: now.UTC().Format(time.RFC3339),
	}})
	g.lastEvent, g.pendingN, g.pendingWhat = now, 0, nil
}

func (g *firewallGuard) send(events []api.EventRequest) {
	if err := g.report(events); err != nil {
		log.Printf("[firewall] guard: failed to report: %v", err)
	}
}

// expectedAfter names the tools whose periodic rebuild explains every
// repair of res ("" when one is not explained): each is a jump-order
// repair, and every rule that could ACCEPT ahead of the agent's jump is a
// jump to a chain of an installed tool that recreates its rules on a
// timer.
func (g *firewallGuard) expectedAfter(res firewall.EnsureResult) string {
	if g.periodicOwner == nil {
		return ""
	}
	var tools []string
	for _, r := range res.Repairs {
		ahead := res.Ahead[r]
		if !strings.HasPrefix(r, "jump-order:") || ahead == "" {
			return ""
		}
		// Every rule that could ACCEPT ahead of the agent's jump.
		for _, chain := range strings.Split(ahead, ",") {
			owner := g.periodicOwner(chain)
			if owner == "" {
				return ""
			}
			if !slices.Contains(tools, owner) {
				tools = append(tools, owner)
			}
		}
	}
	sort.Strings(tools)
	return strings.Join(tools, ", ")
}

// noteExpected logs the first expected restore and counts the others for
// flushExpected.
func (g *firewallGuard) noteExpected(now time.Time, tools string, what []string) {
	if !g.expLogged {
		g.expLogged = true
		held := "bans are not enforced meanwhile for traffic its chains accept"
		if g.earlyDrop != nil && g.earlyDrop() {
			held = "bans hold meanwhile in the raw table"
		}
		log.Printf("[firewall] guard: restored %v after %s recreated its rules (expected: it recreates them on its own; %s). Further restores like this are summarized once an hour", what, tools, held)
		g.sendExpected(now, tools, what, 1)
		return
	}
	if g.expN == 0 {
		g.expSince, g.expTools, g.expWhat = now, map[string]bool{}, map[string]bool{}
	}
	g.expN++
	g.expTools[tools] = true
	for _, w := range what {
		g.expWhat[w] = true
	}
}

// flushExpected logs and reports the expected restores counted, once an
// hour.
func (g *firewallGuard) flushExpected(now time.Time) {
	if g.expN == 0 || now.Sub(g.expSince) < guardExpected {
		return
	}
	tools := strings.Join(sortedKeys(g.expTools), ", ")
	what := sortedKeys(g.expWhat)
	log.Printf("[firewall] guard: jump order restored %d times in the last hour after %s recreated its rules (expected)", g.expN, tools)
	g.sendExpected(now, tools, what, g.expN)
	g.expN, g.expTools, g.expWhat = 0, nil, nil
}

// sendExpected reports expected restores as one event: info, not an
// alert, while the raw table holds the bans meanwhile; a warning (at most
// one an hour) where it cannot, since banned traffic the tool's chains
// accept then gets through for those seconds.
func (g *firewallGuard) sendExpected(now time.Time, tools string, what []string, n int) {
	early := g.earlyDrop != nil && g.earlyDrop()
	sev := "info"
	if !early {
		sev = "warning"
	}
	g.send([]api.EventRequest{{
		Type:     "firewall_rules_restored",
		Severity: sev,
		Details: map[string]string{
			"restored":       strings.Join(what, ", "),
			"count":          strconv.Itoa(n),
			"expected_after": tools,
			"bans_held":      strconv.FormatBool(early),
		},
		OccurredAt: now.UTC().Format(time.RFC3339),
	}})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
