// Command mkmmdb writes a small country database (MaxMind DB format, IPv4)
// for test/distro: the test containers have no GeoIP database, and country
// blocks need one. Usage: mkmmdb -out FILE -cidr 198.51.100.0/25 -country XX
// [-anchors] [-type DBIP-Country-Lite]. -anchors adds the networks the agent
// checks a downloaded database with (8.8.8.8 US, 193.0.6.139 NL,
// 200.160.2.3 BR).
package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/infrafence/infrafence-agent/internal/geoip/mmdbtest"
)

func main() {
	out := flag.String("out", "", "database file to write")
	cidr := flag.String("cidr", "", "IPv4 network of the country")
	country := flag.String("country", "XX", "ISO code of that network")
	anchors := flag.Bool("anchors", false, "add the networks a downloaded database is checked with")
	dbType := flag.String("type", "GeoLite2-Country", "database type")
	flag.Parse()
	data, err := build(*cidr, *country, *anchors, *dbType, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		log.Fatal(err)
	}
}

func build(cidr, country string, anchors bool, dbType string, now time.Time) ([]byte, error) {
	networks := []mmdbtest.Network{{CIDR: cidr, Country: country}}
	if anchors {
		networks = append(networks, mmdbtest.Anchors...)
	}
	return mmdbtest.Build(dbType, networks, now)
}
