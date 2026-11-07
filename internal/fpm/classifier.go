package fpm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/cgroup"
	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
)

const DefaultLockDir = "/run/da-resourced/locks"

// UIDFunc extracts the real owner UID of a /proc/<pid> directory (overridable in unit tests).
type UIDFunc func(procPIDPath string) (uint32, error)

// EnabledCheckFunc reports whether Cgroup enforcement is active for the given DirectAdmin account.
type EnabledCheckFunc func(acct dausers.Account) bool

type classifiedPID struct {
	uid       uint32
	startTime string
}

// Classifier scans /proc for PHP-FPM and OpenLiteSpeed lsphp workers owned by DirectAdmin users
// and migrates them from system.slice into user-<UID>.slice/da-php.scope.
type Classifier struct {
	ProcRoot  string
	Registry  *dausers.Registry
	CgroupMgr *cgroup.Manager
	ReadUID   UIDFunc
	IsEnabled EnabledCheckFunc

	mu           sync.Mutex
	classifiedOK map[string]classifiedPID // pid -> (uid, startTime) cache guarded by mu
	lastErrLogAt time.Time
}

var userConfSyncMu sync.Mutex

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
		classifiedOK: make(map[string]classifiedPID, 256),
	}
}

func (c *Classifier) logCgroupErrorLocked(msg string, err error) {
	if err == nil || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return
	}
	now := time.Now()
	if now.Sub(c.lastErrLogAt) >= 60*time.Second {
		c.lastErrLogAt = now
		log.Printf("warning: %s: %v", msg, err)
	}
}

// ScanOnce inspects /proc once and moves any unclassified customer PHP workers into their user slice.
// Serialized via c.mu so concurrent periodic scans and IPC/hook ApplyUser calls are completely race-free.
func (c *Classifier) ScanOnce(ctx context.Context, filterUID uint32) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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

		procPath := filepath.Join(c.ProcRoot, pid)
		curStart := ""

		// Fast skip only if this exact (PID, startTime) instance was already verified inside da-php.scope.
		// Non-cached PIDs check comm FIRST before reading /proc/<pid>/stat to save /proc I/O (N17).
		if cached, ok := c.classifiedOK[pid]; ok {
			curStart = readProcStartTime(procPath)
			if cached.startTime == curStart && (filterUID == 0 || cached.uid == filterUID) {
				continue
			}
		}

		commRaw, err := os.ReadFile(filepath.Join(procPath, "comm"))
		if err != nil {
			continue // Process exited mid-scan
		}
		comm := strings.TrimSpace(string(commRaw))
		if !isPHPWorkerComm(comm) {
			continue
		}
		if curStart == "" {
			curStart = readProcStartTime(procPath)
		}

		uid, err := c.ReadUID(procPath)
		if err != nil {
			continue
		}
		if c.Registry != nil {
			if !c.Registry.ValidUID(uid) {
				continue
			}
		} else if uid < dausers.MinValidUID || uid > dausers.MaxValidUID {
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
			c.classifiedOK[pid] = classifiedPID{uid: uid, startTime: curStart}
			continue
		}

		if err := c.CgroupMgr.EnsureSliceAndPHPScope(ctx, uid); err != nil {
			c.logCgroupErrorLocked(fmt.Sprintf("ensure da-php.scope for uid %d", uid), err)
			continue
		}

		// Re-verify process identity right before writing cgroup.procs to guard against PID reuse (R10)
		recheckComm, err := os.ReadFile(filepath.Join(procPath, "comm"))
		if err != nil || !isPHPWorkerComm(strings.TrimSpace(string(recheckComm))) {
			continue
		}
		if recheckUID, err := c.ReadUID(procPath); err != nil || recheckUID != uid {
			continue
		}
		if recheckStart := readProcStartTime(procPath); recheckStart != curStart {
			continue
		}

		procsFile := filepath.Join(c.CgroupMgr.PHPScopeDir(uid), "cgroup.procs")
		if err := writePIDToCgroupProcs(procsFile, pid); err != nil {
			c.logCgroupErrorLocked(fmt.Sprintf("write pid %s to %s", pid, procsFile), err)
			continue
		}

		c.classifiedOK[pid] = classifiedPID{uid: uid, startTime: curStart}
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

// readProcStartTime extracts field 22 (starttime in clock ticks since boot) from /proc/<pid>/stat
// when present, preventing recycled PIDs from hitting stale cache entries.
func readProcStartTime(procPIDPath string) string {
	raw, err := os.ReadFile(filepath.Join(procPIDPath, "stat"))
	if err != nil {
		return ""
	}
	s := string(raw)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return ""
	}
	fields := strings.Fields(s[closeParen+2:])
	// Field 3 is fields[0], so field 22 (starttime) is fields[19]
	if len(fields) > 19 {
		return fields[19]
	}
	return ""
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
// DirectAdmin's required diradmin:diradmin (0600) ownership and serializing concurrent writes.
func SyncDAUserPHPConf(daUsersDir, username string, limits config.ResourceLimits) error {
	if err := config.ValidateIdentifier(username); err != nil {
		return err
	}
	if daUsersDir == "" {
		daUsersDir = "/usr/local/directadmin/data/users"
	}
	userDir := filepath.Join(daUsersDir, username)
	userConf := filepath.Join(userDir, "user.conf")

	userConfSyncMu.Lock()
	defer userConfSyncMu.Unlock()

	if st, err := os.Stat(userDir); err != nil || !st.IsDir() {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return nil
	}

	unlock, lockErr := acquireFileLock(resolveUserConfLockPath(username))
	if lockErr == nil && unlock != nil {
		defer unlock()
	}
	// Clean up legacy v1.0.4.1 lockfile inside DirectAdmin user directory if present (N20c)
	_ = os.Remove(filepath.Join(userDir, ".user.conf.da-limiter.lock"))

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
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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

	tmpFile, err := os.CreateTemp(userDir, ".user.conf.da-limiter-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmpFile.WriteString(out); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(curMode); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	if targetUID >= 0 && targetGID >= 0 {
		if err := os.Chown(tmpName, targetUID, targetGID); err != nil {
			return fmt.Errorf("chown %s to diradmin (%d:%d): %w", tmpName, targetUID, targetGID, err)
		}
	}

	// Re-check user.conf hasn't changed while staging temp file to avoid clobbering concurrent DA edits (R6)
	if latestRaw, rErr := os.ReadFile(userConf); rErr == nil && string(latestRaw) != string(rawBytes) {
		return fmt.Errorf("concurrent modification detected on %s; skipping to preserve DirectAdmin state", userConf)
	}

	if err := os.Rename(tmpName, userConf); err != nil {
		return err
	}
	cleanupTmp = false
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

// resolveUserConfLockPath places advisory lock files under /run/da-resourced/locks (0700)
// instead of leaving dotfiles inside /usr/local/directadmin/data/users/<user> (N20c).
func resolveUserConfLockPath(username string) string {
	lockDir := strings.TrimSpace(os.Getenv("DA_LIMITER_LOCK_DIR"))
	if lockDir == "" {
		lockDir = DefaultLockDir
	}
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		fallback := filepath.Join(os.TempDir(), fmt.Sprintf("da-resourced-locks-%d", os.Geteuid()))
		_ = os.MkdirAll(fallback, 0o700)
		lockDir = fallback
	}
	return filepath.Join(lockDir, username+".user.conf.lock")
}
