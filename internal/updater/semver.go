package updater

import (
	"strconv"
	"strings"
)

type parsedSemVer struct {
	major      int
	minor      int
	patch      int
	revision   int
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
	if len(parts) < 2 || len(parts) > 4 {
		return parsedSemVer{}
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	pat := 0
	rev := 0
	var err3, err4 error
	if len(parts) >= 3 {
		pat, err3 = strconv.Atoi(parts[2])
	}
	if len(parts) == 4 {
		rev, err4 = strconv.Atoi(parts[3])
	}
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return parsedSemVer{}
	}
	if maj < 0 || min < 0 || pat < 0 || rev < 0 {
		return parsedSemVer{}
	}
	return parsedSemVer{
		major:      maj,
		minor:      min,
		patch:      pat,
		revision:   rev,
		prerelease: pre,
		valid:      true,
	}
}

// CompareSemVer returns 1 if a > b, -1 if a < b, and 0 if equal (supports 2-4 numeric segments + SemVer 2.0 pre-releases).
func CompareSemVer(a, b string) int {
	pa := parseSemVer(a)
	pb := parseSemVer(b)
	if !pa.valid || !pb.valid {
		ta := strings.TrimSpace(a)
		tb := strings.TrimSpace(b)
		if ta == tb {
			return 0
		}
		if ta > tb {
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
	if pa.revision != pb.revision {
		return cmpInt(pa.revision, pb.revision)
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
	return comparePrerelease(pa.prerelease, pb.prerelease)
}

func comparePrerelease(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")
	limit := len(partsA)
	if len(partsB) < limit {
		limit = len(partsB)
	}
	for i := 0; i < limit; i++ {
		if partsA[i] == partsB[i] {
			continue
		}
		numA, errA := strconv.Atoi(partsA[i])
		numB, errB := strconv.Atoi(partsB[i])
		if errA == nil && errB == nil {
			return cmpInt(numA, numB)
		}
		if errA == nil && errB != nil {
			return -1 // numeric identifiers have lower precedence than non-numeric per SemVer 2.0
		}
		if errA != nil && errB == nil {
			return 1
		}
		if partsA[i] > partsB[i] {
			return 1
		}
		return -1
	}
	return cmpInt(len(partsA), len(partsB))
}

// IsNewerVersion returns true when candidateVersion is strictly newer than currentVersion.
func IsNewerVersion(currentVersion, candidateVersion string) bool {
	return CompareSemVer(candidateVersion, currentVersion) > 0
}

func cmpInt(a, b int) int {
	if a > b {
		return 1
	}
	if a < b {
		return -1
	}
	return 0
}
