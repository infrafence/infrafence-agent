// Command wafcatalog prints the agent's built-in WAF rules as JSON. The
// release workflow publishes its output as waf-catalog.json.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/infrafence/infrafence-agent/internal/watcher"
)

func main() {
	version := flag.String("version", "dev", "agent version the catalog describes")
	flag.Parse()
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(watcher.BuiltinWAFCatalog(*version)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
