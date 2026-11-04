package updater

import (
	"strconv"
	"strings"
)

type parsedSemVer struct {
	major      int
	minor      int
	patch      int
	prerelease string
	valid      bool
}

func parseSemVer(v string) parsedSemVer {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}

	pre := ""
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		pre = s[idx+1:]
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return parsedSemVer{}
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	pat := 0
	var err3 error
	if len(parts) == 3 {
		pat, err3 = strconv.Atoi(parts[2])
	}
	if err1 != nil || err2 != nil || err3 != nil {
		return parsedSemVer{}
	}
	return parsedSemVer{
		major:      maj,
		minor:      min,
		patch:      pat,
		prerelease: pre,
		valid:      true,
	}
}

// CompareSemVer returns 1 if a > b, -1 if a < b, and 0 if equal (per SemVer 2.0 precedence).
func CompareSemVer(a, b string) int {
	pa := parseSemVer(a)
	pb := parseSemVer(b)
	if !pa.valid || !pb.valid {
		if strings.TrimSpace(a) == strings.TrimSpace(b) {
			return 0
		}
		if strings.TrimSpace(a) > strings.TrimSpace(b) {
			return 1
		}
		return -1
	}

	if pa.major != pb.major {
		return cmpInt(pa.major, pb.major)
	}
	if pa.minor != pb.minor {
		return cmpInt(pa.minor, pb.minor)
	}
	if pa.patch != pb.patch {
		return cmpInt(pa.patch, pb.patch)
	}

	// Normal release has higher precedence than a pre-release (e.g. 1.0.0 > 1.0.0-beta.1)
	if pa.prerelease == "" && pb.prerelease != "" {
		return 1
	}
	if pa.prerelease != "" && pb.prerelease == "" {
		return -1
	}
	if pa.prerelease == pb.prerelease {
		return 0
	}
	if pa.prerelease > pb.prerelease {
		return 1
	}
	return -1
}

// IsNewerVersion returns true when candidateVersion is strictly newer than currentVersion.
func IsNewerVersion(currentVersion, candidateVersion string) bool {
	return CompareSemVer(candidateVersion, currentVersion) > 0
}

func cmpInt(a, b int) int {
	if a > b {
		return 1
	}
	return -1
}
