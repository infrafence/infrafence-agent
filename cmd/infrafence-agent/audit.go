package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/infrafence/infrafence-agent/internal/audit"
)

// auditUsage is printed for a wrong argument.
const auditUsage = `usage: infrafence-agent audit [--upload URL | --no-upload] [--json]

A free, read-only security audit of this server: SSH, exposed services,
updates, firewall, brute-force protection, accounts, system files, PHP, and
the attacks of the last 24 hours. Nothing on the server is changed.

  --upload URL  where to send the report (default ` + audit.DefaultUploadURL + `)
  --no-upload   send nothing: print the report as text and JSON only
  --json        print only the JSON report on standard output
`

// uploadWait is the pause before the upload when someone is watching the
// terminal: time to read what is sent and press Ctrl+C. curl | sh has no
// stdin to ask a question on, so there is no prompt.
const uploadWait = 5 * time.Second

// uploadInteractive: standard output is a terminal and /dev/tty can be
// opened. Not when the output goes to a file, a pipe or a log (cron,
// provisioning scripts): no wait there. A variable for the tests.
var uploadInteractive = func() bool {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return false
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	_ = tty.Close()
	return true
}

type auditArgs struct {
	upload   string
	noUpload bool
	json     bool
}

func parseAuditArgs(args []string) (auditArgs, error) {
	a := auditArgs{upload: audit.DefaultUploadURL}
	uploadSet := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--no-upload":
			a.noUpload = true
		case "--json":
			a.json = true
		case "--upload":
			if i+1 >= len(args) {
				return a, fmt.Errorf("--upload needs a URL")
			}
			i++
			a.upload, uploadSet = args[i], true
		default:
			return a, fmt.Errorf("unknown argument %q", args[i])
		}
	}
	if a.noUpload && uploadSet {
		return a, fmt.Errorf("--upload and --no-upload exclude each other")
	}
	if !a.noUpload {
		if _, err := audit.CheckUploadURL(a.upload); err != nil {
			return a, err
		}
	}
	return a, nil
}

// cmdAudit runs the one-shot audit. Exit status: 0 done (whatever it
// found), 1 the audit or the upload failed, 2 wrong arguments.
func cmdAudit(args []string) {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Print(auditUsage)
			return
		}
	}
	a, err := parseAuditArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "infrafence-agent audit: %v\n\n%s", err, auditUsage)
		os.Exit(2)
	}
	// Before anything runs a command (LowerPriority re-execs with this
	// environment).
	if err := audit.PinPath(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "infrafence-agent audit: %v\n", err)
		os.Exit(1)
	}
	audit.LowerPriority()
	// The checks' own logging is for the service's journal, not this
	// terminal.
	log.SetOutput(io.Discard)
	os.Exit(runAudit(a, os.Stdout, os.Stderr))
}

func runAudit(a auditArgs, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "Warning: not running as root. The authentication logs and the SSH configuration need root to be read, so this report is incomplete.")
	}
	tmp, err := os.MkdirTemp("", "infrafence-audit-")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "infrafence-agent audit: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	// The contract's limit, whatever a check or the network does: the
	// whole run, upload included, ends by audit.HardLimit.
	watchdog := time.AfterFunc(audit.HardLimit, func() {
		_ = os.RemoveAll(tmp)
		_, _ = fmt.Fprintf(stderr, "infrafence-agent audit: stopped after %s (the time limit); nothing more was read or sent\n", audit.HardLimit)
		os.Exit(1)
	})
	defer watchdog.Stop()
	ctx, cancel := context.WithTimeout(ctx, audit.HardLimit-time.Second)
	defer cancel()

	if !a.json {
		_, _ = fmt.Fprintln(stderr, "Auditing this server (read-only, at most a minute)...")
	}
	r, err := audit.Collect(ctx, audit.Options{Version: version, TempDir: tmp})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "infrafence-agent audit: %v\n", err)
		return 1
	}
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "infrafence-agent audit: %v\n", err)
		return 1
	}

	if a.json {
		_, _ = fmt.Fprintln(stdout, string(body))
	} else {
		audit.WriteSummary(stdout, r)
		_, _ = fmt.Fprintln(stdout)
		if a.noUpload {
			_, _ = fmt.Fprintln(stdout, "The report (JSON):")
		} else {
			_, _ = fmt.Fprintf(stdout, "Everything that is sent to %s (nothing else is):\n", a.upload)
		}
		_, _ = fmt.Fprintln(stdout, string(body))
	}
	if a.noUpload {
		if !a.json {
			_, _ = fmt.Fprintln(stdout, "\nNothing was sent (--no-upload).")
		}
		return 0
	}
	if uploadInteractive() && !pauseBeforeUpload(ctx, stderr, uploadWait) {
		return 1
	}
	res, err := audit.Upload(ctx, a.upload, body, version)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "infrafence-agent audit: %v\n", err)
		return 1
	}
	out := stdout
	if a.json {
		out = stderr
	}
	_, _ = fmt.Fprintf(out, "\nYour report: %s\n", res.URL)
	if res.ExpiresAt != "" {
		_, _ = fmt.Fprintf(out, "The link works until %s; only its holder can open it.\n", res.ExpiresAt)
	}
	return 0
}

// pauseBeforeUpload says the report is about to be sent and waits; false
// (nothing sent) when Ctrl+C, SIGTERM or the time limit ends the wait.
func pauseBeforeUpload(ctx context.Context, stderr io.Writer, wait time.Duration) bool {
	_, _ = fmt.Fprintf(stderr, "\nUploading in %d s, press Ctrl+C to cancel (or run with --no-upload)\n", int(wait.Round(time.Second)/time.Second))
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		_, _ = fmt.Fprintln(stderr, "Cancelled: nothing was sent.")
		return false
	case <-t.C:
		return true
	}
}
