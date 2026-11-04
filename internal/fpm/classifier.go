package fpm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/shostwp-byte/da-resourcelimiter/internal/cgroup"
	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
)

// UIDFunc extracts the real owner UID of a /proc/<pid> directory (overridable in unit tests).
type UIDFunc func(procPIDPath string) (uint32, error)

// EnabledCheckFunc reports whether Cgroup enforcement is active for the given DirectAdmin account.
type EnabledCheckFunc func(acct dausers.Account) bool

// Classifier scans /proc for PHP-FPM and OpenLiteSpeed lsphp workers owned by DirectAdmin users
// and migrates them from system.slice into user-<UID>.slice/da-php.scope.
type Classifier struct {
	ProcRoot     string
	Registry     *dausers.Registry
	CgroupMgr    *cgroup.Manager
	ReadUID      UIDFunc
	IsEnabled    EnabledCheckFunc
	classifiedOK map[string]uint32 // pid -> uid cache to avoid redundant file writes on steady workers
}

func NewClassifier(procRoot string, reg *dausers.Registry, cgMgr *cgroup.Manager, isEnabled EnabledCheckFunc) *Classifier {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &Classifier{
		ProcRoot:     procRoot,
		Registry:     reg,
		CgroupMgr:    cgMgr,
		ReadUID:      statUID,
		IsEnabled:    isEnabled,
		classifiedOK: make(map[string]uint32, 256),
	}
}

// ScanOnce inspects /proc once and moves any unclassified customer PHP workers into their user slice.
// Returns the count of newly migrated PIDs.
func (c *Classifier) ScanOnce(ctx context.Context, filterUID uint32) (int, error) {
	entries, err := os.ReadDir(c.ProcRoot)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", c.ProcRoot, err)
	}

	alivePIDs := make(map[string]struct{}, len(entries))
	migrated := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if !isDigits(pid) {
			continue
		}
		alivePIDs[pid] = struct{}{}

		// Fast skip if this exact PID was already verified inside da-php.scope
		if cachedUID, ok := c.classifiedOK[pid]; ok {
			if filterUID == 0 || cachedUID == filterUID {
				continue
			}
		}

		procPath := filepath.Join(c.ProcRoot, pid)
		commRaw, err := os.ReadFile(filepath.Join(procPath, "comm"))
		if err != nil {
			continue // Process exited mid-scan
		}
		comm := strings.TrimSpace(string(commRaw))
		if !isPHPWorkerComm(comm) {
			continue
		}

		uid, err := c.ReadUID(procPath)
		if err != nil {
			continue
		}
		if uid < dausers.MinValidUID || uid > dausers.MaxValidUID {
			continue
		}
		if filterUID != 0 && uid != filterUID {
			continue
		}

		acct, managed := c.Registry.LookupByUID(uid)
		if !managed {
			continue
		}
		if c.IsEnabled != nil && !c.IsEnabled(acct) {
			continue
		}

		cgBytes, err := os.ReadFile(filepath.Join(procPath, "cgroup"))
		if err != nil {
			continue
		}
		targetRel := fmt.Sprintf("user-%d.slice/%s", uid, cgroup.PHPScopeName)
		if strings.Contains(string(cgBytes), targetRel) {
			c.classifiedOK[pid] = uid
			continue
		}

		if err := c.CgroupMgr.EnsureSliceAndPHPScope(ctx, uid); err != nil {
			continue
		}

		procsFile := filepath.Join(c.CgroupMgr.PHPScopeDir(uid), "cgroup.procs")
		if err := writePIDToCgroupProcs(procsFile, pid); err != nil {
			continue
		}

		c.classifiedOK[pid] = uid
		migrated++
	}

	// Prune exited PIDs so cache stays bounded
	for pid := range c.classifiedOK {
		if _, alive := alivePIDs[pid]; !alive {
			delete(c.classifiedOK, pid)
		}
	}

	return migrated, nil
}

func isPHPWorkerComm(comm string) bool {
	return strings.HasPrefix(comm, "php-fpm") || strings.HasPrefix(comm, "lsphp")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func writePIDToCgroupProcs(procsPath, pid string) error {
	f, err := os.OpenFile(procsPath, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		// In unit tests with mock directories cgroup.procs may not pre-exist like kernel cgroup2fs
		if errors.Is(err, os.ErrNotExist) {
			return os.WriteFile(procsPath, []byte(pid+"\n"), 0o644)
		}
		return err
	}
	defer f.Close()
	_, err = f.WriteString(pid + "\n")
	return err
}

// SyncDAUserPHPConf updates DA_PHP_MAX_CHILDREN and DA_PHP_MEM_LIMIT tokens inside
// /usr/local/directadmin/data/users/<username>/user.conf while strictly preserving
// DirectAdmin's required diradmin:diradmin (0600) ownership and all other fields.
func SyncDAUserPHPConf(daUsersDir, username string, limits config.ResourceLimits) error {
	if err := config.ValidateIdentifier(username); err != nil {
		return err
	}
	if daUsersDir == "" {
		daUsersDir = "/usr/local/directadmin/data/users"
	}
	userDir := filepath.Join(daUsersDir, username)
	userConf := filepath.Join(userDir, "user.conf")

	rawBytes, err := os.ReadFile(userConf)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	curUID, curGID, curMode, hasStat := statOwnerAndMode(userConf)
	if curMode == 0 {
		curMode = 0o600
	}

	// Determine authoritative DirectAdmin ownership (diradmin:diradmin) when running as root
	// so daemon never leaves user.conf owned by root:root (which causes "Unable to show user" in DA).
	targetUID, targetGID := -1, -1
	if os.Geteuid() == 0 {
		targetUID, targetGID = lookupAccountUIDGID("/etc/passwd", "diradmin")
		if targetUID < 0 {
			if dirUID, dirGID, _, dirOK := statOwnerAndMode(userDir); dirOK && dirUID > 0 {
				targetUID, targetGID = dirUID, dirGID
			} else if hasStat {
				targetUID, targetGID = curUID, curGID
			}
		}
	}

	var keptLines []string
	scanner := bufio.NewScanner(strings.NewReader(string(rawBytes)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "DA_PHP_MAX_CHILDREN=") || strings.HasPrefix(trimmed, "DA_PHP_MEM_LIMIT=") {
			continue
		}
		keptLines = append(keptLines, line)
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return scanErr
	}

	if limits.Enabled {
		keptLines = append(keptLines,
			fmt.Sprintf("DA_PHP_MAX_CHILDREN=%d", limits.PHPMaxChildren),
			fmt.Sprintf("DA_PHP_MEM_LIMIT=%dM", limits.PHPMemLimitMB),
		)
	}

	out := strings.Join(keptLines, "\n") + "\n"

	// Avoid unnecessary disk writes if content is already identical, while still self-healing
	// ownership if a prior version left user.conf owned by root:root.
	if out == string(rawBytes) {
		if targetUID >= 0 && targetGID >= 0 && hasStat && (curUID != targetUID || curGID != targetGID) {
			_ = os.Chown(userConf, targetUID, targetGID)
		}
		return nil
	}

	tmp := userConf + ".da-limiter.tmp"
	if err := os.WriteFile(tmp, []byte(out), curMode); err != nil {
		return err
	}
	if targetUID >= 0 && targetGID >= 0 {
		if err := os.Chown(tmp, targetUID, targetGID); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("chown %s to diradmin (%d:%d): %w", tmp, targetUID, targetGID, err)
		}
	}
	if err := os.Rename(tmp, userConf); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func lookupAccountUIDGID(passwdPath, username string) (int, int) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return -1, -1
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) >= 4 && parts[0] == username {
			uid, err1 := strconv.Atoi(parts[2])
			gid, err2 := strconv.Atoi(parts[3])
			if err1 == nil && err2 == nil {
				return uid, gid
			}
		}
	}
	return -1, -1
}
