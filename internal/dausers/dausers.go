package dausers

import (
	"bufio"
	"errors"
	"fmt"
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
	MaxValidUID uint32 = 59999 // Blocks system accounts such as nobody/nfsnobody (65534)
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

	mu              sync.RWMutex
	byName          map[string]Account
	byUID           map[uint32]Account
	sortedNamesDesc []string
}

func NewRegistry(daUsersDir, passwdPath string) *Registry {
	if daUsersDir == "" {
		daUsersDir = "/usr/local/directadmin/data/users"
	}
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	return &Registry{
		daUsersDir: daUsersDir,
		passwdPath: passwdPath,
		byName:     make(map[string]Account),
		byUID:      make(map[uint32]Account),
	}
}

type passwdEntry struct {
	uid uint32
	gid uint32
}

// Reload scans /etc/passwd and /usr/local/directadmin/data/users to rebuild the in-memory lookup tables.
func (r *Registry) Reload() error {
	pwMap, err := parsePasswd(r.passwdPath)
	if err != nil {
		return fmt.Errorf("parse passwd %s: %w", r.passwdPath, err)
	}

	entries, err := os.ReadDir(r.daUsersDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.mu.Lock()
			r.byName = make(map[string]Account)
			r.byUID = make(map[uint32]Account)
			r.sortedNamesDesc = nil
			r.mu.Unlock()
			return nil
		}
		return fmt.Errorf("read DirectAdmin users dir %s: %w", r.daUsersDir, err)
	}

	nextByName := make(map[string]Account, len(entries))
	nextByUID := make(map[uint32]Account, len(entries))
	var names []string

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
		if pw.uid < MinValidUID || pw.uid > MaxValidUID {
			continue
		}

		userConfPath := filepath.Join(r.daUsersDir, username, "user.conf")
		kv, err := config.ParseKeyValueFile(userConfPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			continue
		}

		userType := strings.ToLower(strings.TrimSpace(kv["usertype"]))
		if userType == "" {
			userType = "user"
		}
		// Skip panel administrator accounts by default so sysadmin SSH/panel tasks are not throttled
		if userType == "admin" || username == "admin" {
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

	r.mu.Lock()
	r.byName = nextByName
	r.byUID = nextByUID
	r.sortedNamesDesc = names
	r.mu.Unlock()
	return nil
}

func (r *Registry) LookupByName(username string) (Account, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	acct, ok := r.byName[username]
	return acct, ok
}

func (r *Registry) LookupByUID(uid uint32) (Account, bool) {
	if uid < MinValidUID || uid > MaxValidUID {
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
