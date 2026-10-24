package main

import (
	"context"
	"io"
	"log"
	"os"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/geoip"
	"github.com/infrafence/infrafence-agent/internal/netstate"
)

// The country database (DB-IP "IP to Country Lite", CC BY 4.0) comes from
// the dashboard, and only while a country is blocked: syncAndApply tells
// geoUpdater, which downloads on its own goroutine to geoip.DefaultPath,
// at most once a day. A new database loads the country sets again.
//
// GEOIP_DB_PATH names a database the operator maintains: then nothing is
// downloaded.
var geoUpdater *geoip.Updater

// geoMonitorLogged: monitor mode's "country blocks not applied" was logged
// (once until monitor mode ends; syncs run one at a time).
var geoMonitorLogged bool

// startGeoUpdater starts the updater, unless GEOIP_DB_PATH is set. Called
// once, before any sync runs.
func startGeoUpdater(client *api.Client, geo *geoip.Lookup, geoBlocker *firewall.GeoBlocker, resync func(string)) {
	if p := os.Getenv("GEOIP_DB_PATH"); p != "" {
		log.Printf("[geoip] GEOIP_DB_PATH=%s: the country database is not downloaded from the dashboard", p)
		return
	}
	fetch := func(ctx context.Context, etag string, w io.Writer, maxBytes int64) (bool, time.Duration, error) {
		d, err := client.DownloadGeoIP(ctx, etag, w, maxBytes)
		if err != nil {
			_, retryAfter := api.HTTPStatus(err)
			return false, retryAfter, err
		}
		return d.NotModified, 0, nil
	}
	geoUpdater = geoip.NewUpdater(geo, geoip.DefaultPath, fetch, func() {
		// The sync applies the countries as usual (monitor mode, protection
		// switched off); the sets of countries already blocked are
		// swapped for ones from the new database.
		geoBlocker.Reload()
		resync("country database updated")
	})
	go geoUpdater.Run(context.Background())
}

// sshSessionAddrs returns the public addresses of the SSH sessions logged
// in right now (netstate.SSHSessionAddrs): a country set loaded while they
// are open leaves them out, so blocking a country never cuts off an
// administrator logged in from there. A connection that has not logged in
// is not exempt.
func sshSessionAddrs() []string { return netstate.SSHSessionAddrs() }
