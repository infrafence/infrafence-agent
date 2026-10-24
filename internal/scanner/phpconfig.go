package scanner

import "github.com/infrafence/infrafence-agent/internal/phpconf"

// ─── PHP configuration checks (internal/phpconf) ───

// checkPHPConfig runs the PHP configuration checks of every runtime and
// pool. Each finding names the runtime, the file and the line the value
// comes from.
func checkPHPConfig() []Finding {
	h := phpconf.Discover(phpconf.System)
	var out []Finding
	for _, f := range phpconf.Check(h, phpconf.Options{Usage: phpconf.FindUsage}) {
		out = append(out, Finding{
			Category:       "php_config",
			Severity:       f.Severity,
			CheckID:        f.CheckID,
			Title:          f.Title,
			Description:    f.Description,
			Recommendation: f.Recommendation,
			Details:        f.Details,
			Passed:         f.Passed,
		})
	}
	return out
}
