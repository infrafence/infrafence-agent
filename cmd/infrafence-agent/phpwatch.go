package main

import (
	"fmt"
	"log"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/phpconf"
	"github.com/infrafence/infrafence-agent/internal/remediation"
)

// runPHPWatcher watches the PHP configuration files. A dangerous value
// that appears (or comes back) is reported once as php_config_risk; a
// drop-in of ours changed by someone else as php_dropin_changed; after any
// change the hardening check runs again, debounced, so the dashboard's PHP
// findings stay current.
func runPHPWatcher(client *api.Client) {
	w := &phpconf.Watcher{
		OnRisk: func(r phpconf.Risk) {
			details := map[string]string{
				"runtime":   r.Runtime,
				"file":      r.File,
				"directive": r.Directive,
				"value":     r.Value,
			}
			if r.Line > 0 {
				details["line"] = fmt.Sprint(r.Line)
			}
			if r.Pool != "" {
				details["pool"] = r.Pool
			}
			if id := r.CheckID(); id != "" {
				// The hardening check reporting it: its subject (resolution.go).
				details["check_id"] = id
			}
			log.Printf("[php] %s = %s for %s %s (%s:%d)", r.Directive, r.Value, r.Runtime, r.Pool, r.File, r.Line)
			reportEvent(client, "php_config_risk", r.Severity, details)
		},
		OnChange: func(phpconf.Host) {
			// Not while a fix is being applied: both rewrite the drop-ins.
			fixMu.Lock()
			changes := remediation.CheckPHPDropIns(remediation.System)
			fixMu.Unlock()
			for _, c := range changes {
				log.Printf("[php] %s was %s by someone else", c.File, c.Change)
				reportEvent(client, "php_dropin_changed", "warning", map[string]string{
					"runtime": c.Runtime, "file": c.File, "change": c.Change,
				})
			}
			runScan(client, 0)
		},
	}
	w.Start()
}
