package version

import "fmt"

const DefaultGitHubRepo = "shostwp-byte/da-resourcelimiter"

var (
	Version   = "v0.1.0-dev"
	Commit    = "none"
	BuildTime = "unknown"
)

func Info() string {
	return fmt.Sprintf("da-resourced %s (commit: %s, built: %s)", Version, Commit, BuildTime)
}
