// Command infrafence-router is the InfraFence agent for OpenWrt and GL.iNet
// routers. It shares the dashboard protocol with the server agent
// (internal/api: register, heartbeat, sync, events) and nothing else: no
// log watchers, WAF, malware scanner or panels, which a router has no use
// for and no room for.
//
//	infrafence-router run                      the service (procd)
//	infrafence-router register --token T [--server URL] [--name NAME]
//	infrafence-router status                   print the status (JSON)
//	infrafence-router cleanup                  remove the firewall table and the DNS list
//	infrafence-router version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/config"
	"github.com/infrafence/infrafence-agent/internal/router/dnsblock"
	"github.com/infrafence/infrafence-agent/internal/router/sysinfo"
)

var version = "0.1.0-dev"

const (
	stateDir   = "/tmp/infrafence" // tmpfs: lists, spool, cache
	statusPath = "/var/run/infrafence/status.json"
	secretPath = "/etc/infrafence/device-key" // flash, 0600, written once
	defaultURL = "https://infrafence.com"
)

func main() {
	log.SetFlags(0) // procd/logd timestamps the lines
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run()
	case "register":
		err = register(os.Args[2:])
	case "status":
		err = printStatus()
	case "cleanup":
		err = cleanup()
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "infrafence-router:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: infrafence-router run | register --token TOKEN [--server URL] [--name NAME] | status | cleanup | version")
	os.Exit(2)
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not registered (%v): run `infrafence-router register --token ...` or enrol from LuCI", err)
	}
	applyTestIntervals()
	a, err := newAgent(cfg, loadSettings())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for s := range sig {
			if s == syscall.SIGHUP {
				// The firewall include and procd's reload: check the
				// rules at once and re-read the settings.
				a.poke()
				continue
			}
			log.Printf("[agent] %s: stopping", s)
			cancel()
			return
		}
	}()
	a.run(ctx)
	return nil
}

// register enrols the router with an install token and saves the agent
// token (0600). The install token comes from the dashboard's "Add router"
// page; it is never printed or logged.
func register(args []string) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	token := fs.String("token", "", "install token from the dashboard")
	tokenFile := fs.String("token-file", "", "read the install token from this file (\"-\": stdin)")
	server := fs.String("server", "", "dashboard URL (default: UCI infrafence.main.server_url or "+defaultURL+")")
	name := fs.String("name", "", "name shown in the dashboard (default: the router's model and host name)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tok := strings.TrimSpace(*token)
	if *tokenFile != "" {
		var r io.Reader = os.Stdin
		if *tokenFile != "-" {
			if st, err := os.Lstat(*tokenFile); err != nil {
				return err
			} else if !st.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file", *tokenFile)
			}
			f, err := os.Open(*tokenFile)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}
		b, err := io.ReadAll(io.LimitReader(r, 4096))
		if err != nil {
			return err
		}
		tok = strings.TrimSpace(string(b))
		// A token handed over in /tmp (LuCI's enrolment) is read once.
		if strings.HasPrefix(filepath.Clean(*tokenFile), "/tmp/") {
			_ = os.Remove(*tokenFile)
		}
	}
	if tok == "" || len(tok) > 512 || strings.ContainsAny(tok, " \t\r\n") {
		return errors.New("a valid --token is required")
	}
	st := loadSettings()
	srv := strings.TrimRight(strings.TrimSpace(*server), "/")
	if srv == "" {
		srv = st.ServerURL
	}
	if err := checkServerURL(srv); err != nil {
		return err
	}
	info := sysinfo.Detect()
	n := strings.TrimSpace(*name)
	if n == "" {
		n = info.Hostname
		if info.Model != "" {
			n = info.Model + " (" + info.Hostname + ")"
		}
	}
	c := api.New(srv, "")
	c.SetVersion(version)
	resp, err := c.Register(api.RegisterRequest{
		InstallToken: tok,
		Name:         n,
		Hostname:     info.Hostname,
		IPAddress:    primaryAddress(),
		OS:           "openwrt",
		OSVersion:    info.Version,
		Version:      version,
		Kind:         api.AgentKindRouter,
		Board:        info.Model,
		Arch:         info.Arch,
		Capabilities: capabilities(info),
	})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	if resp.Token == "" {
		return errors.New("registration failed: the dashboard sent no agent token")
	}
	if err := config.Save(&config.Config{ServerURL: srv, AgentToken: resp.Token, AgentID: resp.Agent.ID}); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	fmt.Printf("registered as agent %d with %s\n", resp.Agent.ID, srv)
	return nil
}

// checkServerURL accepts https URLs (http only for a local test dashboard).
func checkServerURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid server URL %q", s)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && os.Getenv("INFRAFENCE_ALLOW_HTTP") == "1" {
		return nil
	}
	return fmt.Errorf("the server URL must use https: %q", s)
}

func printStatus() error {
	b, err := os.ReadFile(statusPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, cerr := config.Load()
			out := map[string]any{"running": false, "registered": cerr == nil}
			return json.NewEncoder(os.Stdout).Encode(out)
		}
		return err
	}
	_, err = os.Stdout.Write(b)
	return err
}

// cleanup removes everything the agent put in place at runtime (firewall
// table or chains, the DNS list in dnsmasq's conf-dir). The init script
// runs it on stop, the package's prerm on removal.
func cleanup() error {
	info := sysinfo.Detect()
	var errs []error
	if be := chooseBackend(info); be != nil {
		if err := be.Teardown(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := dnsblock.New(stateDir).Remove(); err != nil {
		errs = append(errs, err)
	}
	_ = os.Remove(statusPath)
	return errors.Join(errs...)
}
