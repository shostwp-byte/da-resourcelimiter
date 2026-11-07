package dausers

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
)

const (
	MinValidUID uint32 = 1000
	// MaxValidUID defaults to 65533 so high-UID hosting accounts (60000..65533) work out of the box
	// while still strictly blocking system overflow accounts such as nobody/nfsnobody (65534).
	MaxValidUID uint32 = 65533
)

// Account represents a DirectAdmin hosting user mapped to its Linux UID.
type Account struct {
	Username string `json:"username"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	Package  string `json:"package"`
	UserType string `json:"user_type"`
}

// Registry maintains a concurrency-safe cache of DirectAdmin users and their OS UIDs.
type Registry struct {
	daUsersDir string
	passwdPath string
	MinUID     uint32
	MaxUID     uint32

	reloadMu         sync.Mutex
	mu               sync.RWMutex
	byName           map[string]Account
	byUID            map[uint32]Account
	passwdUIDs       map[uint32]struct{}
	missingStreaks   map[uint32]int
	sortedNamesDesc  []string
	lastSkipLogState string
}

func NewRegistry(daUsersDir, passwdPath string) *Registry {
	if daUsersDir == "" {
		daUsersDir = "/usr/local/directadmin/data/users"
	}
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	minUID := MinValidUID
	maxUID := MaxValidUID
	if rawMin := strings.TrimSpace(os.Getenv("DA_LIMITER_MIN_UID")); rawMin != "" {
		if v, err := strconv.ParseUint(rawMin, 10, 32); err == nil && v >= 100 {
			minUID = uint32(v)
		}
	}
	if rawMax := strings.TrimSpace(os.Getenv("DA_LIMITER_MAX_UID")); rawMax != "" {
		if v, err := strconv.ParseUint(rawMax, 10, 32); err == nil && uint32(v) >= minUID && v != 65534 {
			maxUID = uint32(v)
		}
	}
	return &Registry{
		daUsersDir:     daUsersDir,
		passwdPath:     passwdPath,
		MinUID:         minUID,
		MaxUID:         maxUID,
		byName:         make(map[string]Account),
		byUID:          make(map[uint32]Account),
		missingStreaks: make(map[uint32]int),
	}
}

func (r *Registry) effectiveBounds() (uint32, uint32) {
	minU := r.MinUID
	if minU == 0 {
		minU = MinValidUID
	}
	maxU := r.MaxUID
	if maxU == 0 {
		maxU = MaxValidUID
	}
	return minU, maxU
}

// ValidUID reports whether uid falls within the configured customer UID range and is not nobody (65534).
func (r *Registry) ValidUID(uid uint32) bool {
	minU, maxU := r.effectiveBounds()
	return uid >= minU && uid <= maxU && uid != 65534
}

type passwdEntry struct {
	uid uint32
	gid uint32
}

// Reload scans /etc/passwd and /usr/local/directadmin/data/users to rebuild the in-memory lookup tables.
// Serialized via r.reloadMu so concurrent periodic and hook-triggered reloads never overwrite newer state (N15).
// Treats missing daUsersDir as an error and retains prior active accounts if a user.conf fails to parse (N2).
func (r *Registry) Reload() error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	pwMap, err := parsePasswd(r.passwdPath)
	if err != nil {
		return fmt.Errorf("parse passwd %s: %w", r.passwdPath, err)
	}

	entries, err := os.ReadDir(r.daUsersDir)
	if err != nil {
		return fmt.Errorf("read DirectAdmin users dir %s: %w", r.daUsersDir, err)
	}

	nextPasswdUIDs := make(map[uint32]struct{}, len(pwMap))
	for _, pe := range pwMap {
		nextPasswdUIDs[pe.uid] = struct{}{}
	}

	r.mu.RLock()
	prevByName := make(map[string]Account, len(r.byName))
	for k, v := range r.byName {
		prevByName[k] = v
	}
	r.mu.RUnlock()

	minU, maxU := r.effectiveBounds()
	nextByName := make(map[string]Account, len(entries))
	nextByUID := make(map[uint32]Account, len(entries))
	var names []string
	skippedAdmin := 0
	skippedUIDRange := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		username := entry.Name()
		if err := config.ValidateIdentifier(username); err != nil {
			continue
		}

		pw, exists := pwMap[username]
		if !exists {
			continue
		}
		if pw.uid < minU || pw.uid > maxU || pw.uid == 65534 {
			skippedUIDRange++
			continue
		}

		userConfPath := filepath.Join(r.daUsersDir, username, "user.conf")
		kv, err := config.ParseKeyValueFile(userConfPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: read %s failed (%v); retaining user %q in registry", userConfPath, err, username)
			if prev, hadPrev := prevByName[username]; hadPrev {
				prev.UID = pw.uid
				prev.GID = pw.gid
				nextByName[username] = prev
				nextByUID[pw.uid] = prev
				names = append(names, username)
			} else if username != "admin" {
				acct := Account{
					Username: username,
					UID:      pw.uid,
					GID:      pw.gid,
					UserType: "user",
				}
				nextByName[username] = acct
				nextByUID[pw.uid] = acct
				names = append(names, username)
			}
			continue
		}

		userType := strings.ToLower(strings.TrimSpace(kv["usertype"]))
		if userType == "" {
			userType = "user"
		}
		// Skip panel administrator accounts by default so sysadmin SSH/panel tasks are not throttled
		if userType == "admin" || username == "admin" {
			skippedAdmin++
			continue
		}

		acct := Account{
			Username: username,
			UID:      pw.uid,
			GID:      pw.gid,
			Package:  strings.TrimSpace(kv["package"]),
			UserType: userType,
		}
		nextByName[username] = acct
		nextByUID[pw.uid] = acct
		names = append(names, username)
	}

	// Sort longest username first so ResolveDBUser handles usernames containing '_' accurately
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})

	skipSummary := fmt.Sprintf("admin=%d,uid_range=%d(%d..%d)", skippedAdmin, skippedUIDRange, minU, maxU)

	r.mu.Lock()
	nextStreaks := make(map[uint32]int)
	for uid := range r.byUID {
		if _, stillPresent := nextByUID[uid]; !stillPresent {
			nextStreaks[uid] = 1
		}
	}
	for uid, prevCount := range r.missingStreaks {
		if _, stillPresent := nextByUID[uid]; !stillPresent {
			nextStreaks[uid] = prevCount + 1
		}
	}
	r.missingStreaks = nextStreaks
	r.passwdUIDs = nextPasswdUIDs
	r.byName = nextByName
	r.byUID = nextByUID
	r.sortedNamesDesc = names
	changedSkip := r.lastSkipLogState != skipSummary
	r.lastSkipLogState = skipSummary
	r.mu.Unlock()

	if changedSkip && (skippedAdmin > 0 || skippedUIDRange > 0) {
		log.Printf("registry loaded %d hosting users (exempted %d admin accounts, skipped %d accounts outside UID range %d..%d)",
			len(nextByName), skippedAdmin, skippedUIDRange, minU, maxU)
	}
	return nil
}

// CanPruneOrphanUID reports whether a slice UID absent from ActiveUIDSet is safe to delete during
// untargeted periodic pruning: only after at least one successful Reload() AND either the UID is gone
// from /etc/passwd or has been absent across >= 2 consecutive successful Reload() cycles (N2).
func (r *Registry) CanPruneOrphanUID(uid uint32) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.passwdUIDs == nil {
		return false
	}
	if _, active := r.byUID[uid]; active {
		return false
	}
	if _, inPasswd := r.passwdUIDs[uid]; !inPasswd {
		return true
	}
	return r.missingStreaks[uid] >= 2
}

func (r *Registry) LookupByName(username string) (Account, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	acct, ok := r.byName[username]
	return acct, ok
}

func (r *Registry) LookupByUID(uid uint32) (Account, bool) {
	if !r.ValidUID(uid) {
		return Account{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	acct, ok := r.byUID[uid]
	return acct, ok
}

func (r *Registry) All() []Account {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Account, 0, len(r.byName))
	for _, acct := range r.byName {
		out = append(out, acct)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Username < out[j].Username
	})
	return out
}

// ActiveUIDSet returns a snapshot set of all currently managed customer UIDs.
func (r *Registry) ActiveUIDSet() map[uint32]struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[uint32]struct{}, len(r.byUID))
	for uid := range r.byUID {
		out[uid] = struct{}{}
	}
	return out
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byName)
}

// ResolveDBUser maps a MySQL/MariaDB username (e.g. "vina_host_wp" or "vinahost")
// back to its owning DirectAdmin system user via exact or longest "<da_user>_" prefix match.
func (r *Registry) ResolveDBUser(dbUser string) (Account, bool) {
	dbUser = strings.TrimSpace(dbUser)
	if dbUser == "" {
		return Account{}, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if acct, ok := r.byName[dbUser]; ok {
		return acct, true
	}

	for _, name := range r.sortedNamesDesc {
		if len(dbUser) > len(name)+1 && dbUser[len(name)] == '_' && strings.HasPrefix(dbUser, name) {
			return r.byName[name], true
		}
	}
	return Account{}, false
}

func parsePasswd(path string) (map[string]passwdEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := make(map[string]passwdEntry)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		uid64, err1 := strconv.ParseUint(parts[2], 10, 32)
		gid64, err2 := strconv.ParseUint(parts[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		res[parts[0]] = passwdEntry{
			uid: uint32(uid64),
			gid: uint32(gid64),
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}
