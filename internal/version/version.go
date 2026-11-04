package version

import "fmt"

var (
	// DefaultGitHubRepo is pinned at compile time to prevent repository hijacking over IPC (S1).
	DefaultGitHubRepo = "shostwp-byte/da-resourcelimiter"

	// DefaultReleasePublicKeyHex is the embedded 32-byte Ed25519 public key (hex-encoded)
	// used to verify checksums.txt.sig before staging or executing any update (S1).
	DefaultReleasePublicKeyHex = "0195c5127917180c22a76082e1746b1583142623a4602e6cc53b9788e7d8c6c5"

	Version   = "v1.0.4.1"
	Commit    = "none"
	BuildTime = "unknown"
)

func Info() string {
	return fmt.Sprintf("da-resourced %s (commit: %s, built: %s)", Version, Commit, BuildTime)
}
