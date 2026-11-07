package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/cgroup"
	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
	"github.com/shostwp-byte/da-resourcelimiter/internal/fpm"
	"github.com/shostwp-byte/da-resourcelimiter/internal/ipc"
	"github.com/shostwp-byte/da-resourcelimiter/internal/logger"
	"github.com/shostwp-byte/da-resourcelimiter/internal/mysqlgov"
	"github.com/shostwp-byte/da-resourcelimiter/internal/version"
)

const DefaultAsyncSyncThreshold = 20

// UpdaterProvider abstracts GitHub Releases operations implemented in Phase 4.
type UpdaterProvider interface {
	GetStatus(ctx context.Context) (ipc.UpdaterStatusData, error)
	CheckLatest(ctx context.Context) (ipc.UpdaterStatusData, error)
	TriggerUpdate(ctx context.Context, targetVersion string) (string, error)
	TriggerRollback(ctx context.Context) (string, error)
}

type adminAuthCacheEntry struct {
	username  string
	ok        bool
	expiresAt time.Time
}

// Engine coordinates Cgroups v2, PHP-FPM classification, MariaDB Governor, Violation Logs, and IPC requests.
type Engine struct {
	StartedAt          time.Time
	Store              *config.Store
	Registry           *dausers.Registry
	CgroupMgr          *cgroup.Manager
	Classifier         *fpm.Classifier
	MySQLGov           *mysqlgov.Governor
	Logger             *logger.ViolationLogger
	Updater            UpdaterProvider
	DADataRoot         string // Default: /usr/local/directadmin/data
	DAUsersDir         string // Default: /usr/local/directadmin/data/users
	PasswdPath         string // Default: /etc/passwd
	DiradminUID        uint32
	AsyncSyncThreshold int

	applySemOnce sync.Once
	applySem     chan struct{}

	authCacheMu    sync.RWMutex
	adminAuthCache map[uint32]adminAuthCacheEntry

	bgMu          sync.Mutex
	bgDirtyAll    bool
	bgDirtyPkgs   map[string]struct{}
	bgRunning     bool
	bgActiveLabel string
	bgWakeCh      chan struct{}
	bgWorkerBound bool

	oomMu       sync.Mutex
	oomBaseline map[uint32]uint64
}

func New(
	store *config.Store,
	reg *dausers.Registry,
	cgMgr *cgroup.Manager,
	cls *fpm.Classifier,
	mysqlGov *mysqlgov.Governor,
	vlog *logger.ViolationLogger,
	daDataRoot string,
	passwdPath string,
) *Engine {
	if daDataRoot == "" {
		daDataRoot = "/usr/local/directadmin/data"
	}
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	e := &Engine{
		StartedAt:          time.Now(),
		Store:              store,
		Registry:           reg,
		CgroupMgr:          cgMgr,
		Classifier:         cls,
		MySQLGov:           mysqlGov,
		Logger:             vlog,
		DADataRoot:         daDataRoot,
		DAUsersDir:         filepath.Join(daDataRoot, "users"),
		PasswdPath:         passwdPath,
		DiradminUID:        lookupUserUID(passwdPath, "diradmin"),
		AsyncSyncThreshold: DefaultAsyncSyncThreshold,
		adminAuthCache:     make(map[uint32]adminAuthCacheEntry),
		bgDirtyPkgs:        make(map[string]struct{}),
		bgWakeCh:           make(chan struct{}, 1),
		oomBaseline:        make(map[uint32]uint64),
	}
	e.ensureApplySem()
	return e
}

func (e *Engine) ensureApplySem() chan struct{} {
	e.applySemOnce.Do(func() {
		e.applySem = make(chan struct{}, 1)
	})
	return e.applySem
}

// acquireApplyLock acquires the single-slot apply semaphore while respecting ctx cancellation/deadlines (N9).
func (e *Engine) acquireApplyLock(ctx context.Context) (func(), error) {
	sem := e.ensureApplySem()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("engine apply lock wait aborted: %w", ctx.Err())
	}
}

// AuthorizeSocketPeer implements ipc.PeerAuthorizer so unauthorized UIDs are rejected before reading JSON.
func (e *Engine) AuthorizeSocketPeer(peerUID uint32, isAdminSocket bool) error {
	if isAdminSocket {
		if _, ok := e.IsAuthorizedAdminUID(peerUID); !ok {
			return fmt.Errorf("permission denied: caller UID %d is not a DirectAdmin administrator", peerUID)
		}
		return nil
	}
	if _, ok := e.IsAuthorizedAdminUID(peerUID); ok {
		return nil
	}
	if _, ok := e.Registry.LookupByUID(peerUID); ok {
		return nil
	}
	return errors.New("caller UID is not a managed DirectAdmin hosting account")
}

// IsRootOrDiradminUID restricts root-equivalent operations (self-updater config, update, rollback)
// strictly to UID 0 (root) or the system diradmin daemon UID, blocking secondary DA admins.
func (e *Engine) IsRootOrDiradminUID(peerUID uint32) bool {
	if peerUID == 0 {
		return true
	}
	if e.DiradminUID > 0 && peerUID == e.DiradminUID {
		return true
	}
	return lookupUsernameByUID(e.PasswdPath, peerUID) == "diradmin"
}

// ApplyUser applies OS Cgroups v2 slice, DirectAdmin PHP tokens, PHP PID migration, and MariaDB Tier-2 limits.
func (e *Engine) ApplyUser(ctx context.Context, username string) error {
	if err := config.ValidateIdentifier(username); err != nil {
		return err
	}
	release, err := e.acquireApplyLock(ctx)
	if err != nil {
		return err
	}
	defer release()

	return e.applyUserLocked(ctx, username, true)
}

func (e *Engine) applyUserLocked(ctx context.Context, username string, reloadRegistry bool) error {
	if reloadRegistry {
		_ = e.Registry.Reload()
	}
	acct, ok := e.Registry.LookupByName(username)
	if !ok {
		return fmt.Errorf("DirectAdmin hosting user %q not found", username)
	}

	limits, err := e.Store.ResolveUserLimits(acct.Username, acct.Package)
	if err != nil {
		return err
	}

	if err := e.CgroupMgr.ApplyUserSliceForAccount(ctx, acct.Username, acct.UID, limits); err != nil {
		return fmt.Errorf("apply cgroup slice: %w", err)
	}
	if err := fpm.SyncDAUserPHPConf(e.DAUsersDir, acct.Username, limits); err != nil {
		log.Printf("warning: sync PHP user.conf tokens for %s: %v", acct.Username, err)
	}
	if e.Classifier != nil && limits.Enabled {
		_, _ = e.Classifier.ScanOnce(ctx, acct.UID)
	}
	if e.MySQLGov != nil {
		if err := e.MySQLGov.ApplyUserAccountLimits(ctx, acct.Username, limits); err != nil {
			log.Printf("warning: apply MariaDB limits for %s: %v", acct.Username, err)
		}
	}
	return nil
}

// ApplyAll batch-synchronizes Cgroups v2 slices, PHP tokens, and batched MariaDB limits for all DirectAdmin users.
func (e *Engine) ApplyAll(ctx context.Context) error {
	release, err := e.acquireApplyLock(ctx)
	if err != nil {
		return err
	}
	defer release()

	return e.applyAllLocked(ctx)
}

func (e *Engine) applyAllLocked(ctx context.Context) error {
	accounts := e.Registry.All()
	anySliceChanged := false
	var enabledAccounts []dausers.Account
	mysqlBatch := make(map[string]config.ResourceLimits, len(accounts))

	for _, acct := range accounts {
		if err := ctx.Err(); err != nil {
			return err
		}
		limits, err := e.Store.ResolveUserLimits(acct.Username, acct.Package)
		if err != nil {
			log.Printf("skip %s: resolve limits error: %v", acct.Username, err)
			continue
		}
		changed, err := e.CgroupMgr.StageUserSliceForAccount(acct.Username, acct.UID, limits)
		if err != nil {
			log.Printf("skip %s (uid %d): stage slice error: %v", acct.Username, acct.UID, err)
			continue
		}
		if changed {
			anySliceChanged = true
		}
		if limits.Enabled {
			enabledAccounts = append(enabledAccounts, acct)
		}
		if err := fpm.SyncDAUserPHPConf(e.DAUsersDir, acct.Username, limits); err != nil {
			log.Printf("warning: sync PHP user.conf for %s: %v", acct.Username, err)
		}
		mysqlBatch[acct.Username] = limits
	}

	if e.MySQLGov != nil && len(mysqlBatch) > 0 {
		if err := e.MySQLGov.ApplyBatchUserLimits(ctx, mysqlBatch); err != nil {
			log.Printf("warning: batched MariaDB limits sync: %v", err)
		}
	}

	if anySliceChanged {
		if err := e.CgroupMgr.ReloadSystemd(ctx); err != nil {
			return err
		}
	}

	for _, acct := range enabledAccounts {
		if err := e.CgroupMgr.EnsureSliceAndPHPScope(ctx, acct.UID); err != nil {
			log.Printf("ensure slice %s (uid %d): %v", acct.Username, acct.UID, err)
		}
	}

	if pruned, err := e.CgroupMgr.PruneOrphanSlicesWithPolicy(ctx, e.Registry.ActiveUIDSet(), "", e.Registry.CanPruneOrphanUID); err != nil {
		log.Printf("warning: prune orphan slices: %v", err)
	} else if pruned > 0 {
		log.Printf("pruned %d orphaned user-*.slice drop-in(s)", pruned)
	}

	return nil
}

// ApplyPackage re-applies limits to all users assigned to packageName unless they have CUSTOM_OVERRIDE=yes.
func (e *Engine) ApplyPackage(ctx context.Context, packageName string) (int, error) {
	if err := config.ValidateIdentifier(packageName); err != nil {
		return 0, err
	}
	release, err := e.acquireApplyLock(ctx)
	if err != nil {
		return 0, err
	}
	defer release()

	return e.applyPackageLocked(ctx, packageName)
}

func (e *Engine) applyPackageLocked(ctx context.Context, packageName string) (int, error) {
	_ = e.Registry.Reload()

	var targets []dausers.Account
	for _, acct := range e.Registry.All() {
		if acct.Package != packageName {
			continue
		}
		if userConfPath, err := e.Store.UserConfPath(acct.Username); err == nil {
			if kv, err := config.ParseKeyValueFile(userConfPath); err == nil {
				if strings.EqualFold(kv["CUSTOM_OVERRIDE"], "yes") || strings.EqualFold(kv["CUSTOM_OVERRIDE"], "true") {
					continue
				}
			}
		}
		targets = append(targets, acct)
	}

	anySliceChanged := false
	var enabledTargets []dausers.Account
	mysqlBatch := make(map[string]config.ResourceLimits, len(targets))
	synced := 0

	for _, acct := range targets {
		if err := ctx.Err(); err != nil {
			return synced, err
		}
		limits, err := e.Store.ResolveUserLimits(acct.Username, acct.Package)
		if err != nil {
			log.Printf("apply package %s -> user %s resolve error: %v", packageName, acct.Username, err)
			continue
		}
		changed, err := e.CgroupMgr.StageUserSliceForAccount(acct.Username, acct.UID, limits)
		if err != nil {
			log.Printf("apply package %s -> user %s stage error: %v", packageName, acct.Username, err)
			continue
		}
		if changed {
			anySliceChanged = true
		}
		if limits.Enabled {
			enabledTargets = append(enabledTargets, acct)
		}
		_ = fpm.SyncDAUserPHPConf(e.DAUsersDir, acct.Username, limits)
		mysqlBatch[acct.Username] = limits
		synced++
	}

	if e.MySQLGov != nil && len(mysqlBatch) > 0 {
		if err := e.MySQLGov.ApplyBatchUserLimits(ctx, mysqlBatch); err != nil {
			log.Printf("warning: package %s MariaDB batch sync: %v", packageName, err)
		}
	}
	if anySliceChanged {
		if err := e.CgroupMgr.ReloadSystemd(ctx); err != nil {
			return synced, err
		}
	}
	for _, acct := range enabledTargets {
		_ = e.CgroupMgr.EnsureSliceAndPHPScope(ctx, acct.UID)
	}
	// Scan /proc once for all users in the package instead of N separate /proc walks (N17)
	if len(enabledTargets) > 0 && e.Classifier != nil {
		_, _ = e.Classifier.ScanOnce(ctx, 0)
	}

	return synced, nil
}

// ApplyNewDBUser immediately enforces Tier-2 MariaDB limits on a newly created database user owned by daUsername.
func (e *Engine) ApplyNewDBUser(ctx context.Context, daUsername, dbUser string) error {
	if err := config.ValidateIdentifier(daUsername); err != nil {
		return err
	}
	if e.MySQLGov == nil {
		return nil
	}
	_ = e.Registry.Reload()
	acct, ok := e.Registry.LookupByName(daUsername)
	if !ok {
		return fmt.Errorf("DirectAdmin hosting user %q not found", daUsername)
	}
	limits, err := e.Store.ResolveUserLimits(acct.Username, acct.Package)
	if err != nil {
		return err
	}
	return e.MySQLGov.ApplySingleOwnedDBUserLimits(ctx, acct.Username, dbUser, limits)
}

// RemoveUser cleans up slice drop-in files (including post-deletion orphans), resets MariaDB limits, and deletes custom user config.
func (e *Engine) RemoveUser(ctx context.Context, username string) error {
	if err := config.ValidateIdentifier(username); err != nil {
		return err
	}
	release, err := e.acquireApplyLock(ctx)
	if err != nil {
		return err
	}
	defer release()

	if acct, ok := e.Registry.LookupByName(username); ok {
		_ = e.CgroupMgr.RemoveUserSlice(ctx, acct.UID)
		e.oomMu.Lock()
		delete(e.oomBaseline, acct.UID)
		e.oomMu.Unlock()
	}

	_ = e.Registry.Reload()
	if _, err := e.CgroupMgr.PruneOrphanSlicesWithPolicy(ctx, e.Registry.ActiveUIDSet(), username, e.Registry.CanPruneOrphanUID); err != nil {
		log.Printf("warning: prune orphan slice for removed user %s: %v", username, err)
	}

	if e.MySQLGov != nil {
		_ = e.MySQLGov.UnblockUser(ctx, username)
		_ = e.MySQLGov.RemoveUserAccountLimits(ctx, username)
	}
	if err := e.Store.DeleteUserLimits(username); err != nil {
		return err
	}
	return nil
}

// PruneOrphans scans /etc/systemd/system/user-*.slice.d/50-da-limits.conf and deletes drop-ins
// whose UID is no longer an active DirectAdmin hosting account.
func (e *Engine) PruneOrphans(ctx context.Context) {
	release, err := e.acquireApplyLock(ctx)
	if err != nil {
		return
	}
	defer release()

	validUIDs := e.Registry.ActiveUIDSet()
	e.oomMu.Lock()
	for uid := range e.oomBaseline {
		if _, ok := validUIDs[uid]; !ok {
			delete(e.oomBaseline, uid)
		}
	}
	e.oomMu.Unlock()

	if pruned, err := e.CgroupMgr.PruneOrphanSlicesWithPolicy(ctx, validUIDs, "", e.Registry.CanPruneOrphanUID); err != nil {
		log.Printf("warning: periodic orphan slice prune failed: %v", err)
	} else if pruned > 0 {
		log.Printf("pruned %d orphaned user-*.slice drop-in(s)", pruned)
	}
}

// StartBackgroundWorker launches a single WaitGroup-tracked background sync worker that coalesces
// repeated default/package sync requests and starts its 5m execution timer AFTER acquiring applySem (N9).
func (e *Engine) StartBackgroundWorker(ctx context.Context, wg *sync.WaitGroup) {
	e.bgMu.Lock()
	if e.bgWakeCh == nil {
		e.bgWakeCh = make(chan struct{}, 1)
	}
	if e.bgDirtyPkgs == nil {
		e.bgDirtyPkgs = make(map[string]struct{})
	}
	e.bgWorkerBound = true
	wakeCh := e.bgWakeCh
	e.bgMu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-wakeCh:
				e.drainBackgroundSyncQueue(ctx)
			}
		}
	}()
}

// SyncStatus reports whether a coalesced background ApplyAll/ApplyPackage job is currently pending or running.
func (e *Engine) SyncStatus() (inProgress bool, label string) {
	e.bgMu.Lock()
	defer e.bgMu.Unlock()
	if e.bgRunning {
		return true, e.bgActiveLabel
	}
	if e.bgDirtyAll {
		return true, "queued:all"
	}
	if len(e.bgDirtyPkgs) > 0 {
		return true, "queued:package"
	}
	return false, ""
}

func (e *Engine) enqueueBackgroundSyncAll() {
	e.bgMu.Lock()
	if e.bgWakeCh == nil {
		e.bgWakeCh = make(chan struct{}, 1)
	}
	e.bgDirtyAll = true
	// ApplyAll covers every package, so pending single-package syncs can be coalesced away.
	for k := range e.bgDirtyPkgs {
		delete(e.bgDirtyPkgs, k)
	}
	bound := e.bgWorkerBound
	alreadyRunning := e.bgRunning
	wakeCh := e.bgWakeCh
	if !bound && !alreadyRunning {
		e.bgRunning = true
		e.bgActiveLabel = "default-limits"
	}
	e.bgMu.Unlock()

	if bound {
		select {
		case wakeCh <- struct{}{}:
		default:
		}
		return
	}
	if !alreadyRunning {
		go e.drainBackgroundSyncQueue(context.Background())
	}
}

func (e *Engine) enqueueBackgroundSyncPackage(pkg string) {
	e.bgMu.Lock()
	if e.bgWakeCh == nil {
		e.bgWakeCh = make(chan struct{}, 1)
	}
	if e.bgDirtyPkgs == nil {
		e.bgDirtyPkgs = make(map[string]struct{})
	}
	if !e.bgDirtyAll {
		e.bgDirtyPkgs[pkg] = struct{}{}
	}
	bound := e.bgWorkerBound
	alreadyRunning := e.bgRunning
	wakeCh := e.bgWakeCh
	if !bound && !alreadyRunning {
		e.bgRunning = true
		e.bgActiveLabel = "package:" + pkg
	}
	e.bgMu.Unlock()

	if bound {
		select {
		case wakeCh <- struct{}{}:
		default:
		}
		return
	}
	if !alreadyRunning {
		go e.drainBackgroundSyncQueue(context.Background())
	}
}

func (e *Engine) drainBackgroundSyncQueue(parentCtx context.Context) {
	for {
		if parentCtx.Err() != nil {
			e.bgMu.Lock()
			e.bgRunning = false
			e.bgActiveLabel = ""
			e.bgMu.Unlock()
			return
		}

		e.bgMu.Lock()
		doAll := e.bgDirtyAll
		targetPkg := ""
		if doAll {
			e.bgDirtyAll = false
			for k := range e.bgDirtyPkgs {
				delete(e.bgDirtyPkgs, k)
			}
			e.bgRunning = true
			e.bgActiveLabel = "default-limits"
		} else {
			for k := range e.bgDirtyPkgs {
				targetPkg = k
				delete(e.bgDirtyPkgs, k)
				break
			}
			if targetPkg == "" {
				e.bgRunning = false
				e.bgActiveLabel = ""
				e.bgMu.Unlock()
				return
			}
			e.bgRunning = true
			e.bgActiveLabel = "package:" + targetPkg
		}
		label := e.bgActiveLabel
		e.bgMu.Unlock()

		release, lockErr := e.acquireApplyLock(parentCtx)
		if lockErr != nil {
			e.bgMu.Lock()
			e.bgRunning = false
			e.bgActiveLabel = ""
			e.bgMu.Unlock()
			return
		}

		// Start the 5-minute budget ONLY AFTER acquiring applySem so queued jobs never starve on lock wait (N9c)
		jobCtx, cancel := context.WithTimeout(parentCtx, 5*time.Minute)
		var runErr error
		if doAll {
			runErr = e.applyAllLocked(jobCtx)
		} else {
			_, runErr = e.applyPackageLocked(jobCtx, targetPkg)
		}
		cancel()
		release()

		if runErr != nil && parentCtx.Err() == nil {
			log.Printf("background sync (%s) error: %v", label, runErr)
		}
	}
}

func (e *Engine) countPackageUsers(packageName string) int {
	n := 0
	for _, acct := range e.Registry.All() {
		if acct.Package == packageName {
			n++
		}
	}
	return n
}

// CheckOOMEvents polls Cgroups v2 memory.events counters and logs any newly occurred Kernel OOM Kills.
func (e *Engine) CheckOOMEvents() {
	if e.Logger == nil {
		return
	}
	nowUnix := time.Now().UTC().Unix()
	for _, acct := range e.Registry.All() {
		st, err := e.CgroupMgr.ReadSliceStats(acct.UID)
		if err != nil {
			continue
		}

		e.oomMu.Lock()
		prev, seen := e.oomBaseline[acct.UID]
		e.oomBaseline[acct.UID] = st.OOMKillEvents
		e.oomMu.Unlock()

		if !seen || st.OOMKillEvents <= prev {
			continue
		}

		delta := st.OOMKillEvents - prev
		limits, _ := e.Store.ResolveUserLimits(acct.Username, acct.Package)
		_ = e.Logger.Log(ipc.ViolationEntry{
			TimestampUnix: nowUnix,
			Username:      acct.Username,
			Type:          logger.TypeCgroupOOMKill,
			MemoryMB:      float64(limits.MemMaxMB),
			Detail: fmt.Sprintf("Kernel Cgroup OOM Killer terminated %d process(es) in user-%d.slice (MemoryMax=%dMB, total_oom_kills=%d)",
				delta, acct.UID, limits.MemMaxMB, st.OOMKillEvents),
		})
	}
}

// BuildUserSnapshot assembles live OS Cgroups v2 + MariaDB + 24h violation telemetry for a single user.
func (e *Engine) BuildUserSnapshot(acct dausers.Account, include24hCounts bool) ipc.UserUsageSnapshot {
	limits, _ := e.Store.ResolveUserLimits(acct.Username, acct.Package)
	cgStats, _ := e.CgroupMgr.ReadSliceStats(acct.UID)

	snap := ipc.UserUsageSnapshot{
		Username:         acct.Username,
		UID:              acct.UID,
		Package:          acct.Package,
		CPUPercent:       cgStats.CPUPercent,
		MemoryCurrentMB:  cgStats.MemoryCurrentMB,
		ActiveProcesses:  cgStats.ActiveProcesses,
		MemoryHighEvents: cgStats.MemoryHighEvents,
		OOMKillEvents:    cgStats.OOMKillEvents,
		Limits:           limits,
	}

	if e.MySQLGov != nil {
		dbUsage, pen, penalized := e.MySQLGov.GetLiveUsage(acct.Username)
		snap.MySQLMemoryMB = float64(dbUsage.MemoryBytes) / (1024.0 * 1024.0)
		snap.MySQLActiveQueries = dbUsage.ActiveQueries
		snap.MySQLTotalConns = dbUsage.TotalConnections
		if penalized {
			snap.PenaltyActive = true
			snap.PenaltyExpiresUnix = pen.ExpiresUnix
			snap.PenaltyReason = pen.Reason
		}
	}

	if include24hCounts && e.Logger != nil {
		cutoff := time.Now().UTC().Add(-24 * time.Hour).Unix()
		oom24, sql24, _ := e.Logger.CountSince(acct.Username, cutoff)
		snap.OOMKills24h = oom24
		snap.MySQLKills24h = sql24
	}
	return snap
}

// IsAuthorizedAdminUID verifies via Linux Kernel SO_PEERCRED UID whether the caller is root (0),
// diradmin, or a DirectAdmin Administrator listed in admin.list / user.conf (usertype=admin).
// Non-fast-path lookups are cached for 5s so unprivileged bursts cannot amplify disk I/O (N8).
func (e *Engine) IsAuthorizedAdminUID(peerUID uint32) (string, bool) {
	if peerUID == 0 {
		return "root", true
	}
	if e.DiradminUID > 0 && peerUID == e.DiradminUID {
		return "diradmin", true
	}

	now := time.Now()
	e.authCacheMu.RLock()
	if e.adminAuthCache != nil {
		if ent, exists := e.adminAuthCache[peerUID]; exists && now.Before(ent.expiresAt) {
			e.authCacheMu.RUnlock()
			return ent.username, ent.ok
		}
	}
	e.authCacheMu.RUnlock()

	username, ok := e.uncachedAuthorizedAdminUID(peerUID)

	e.authCacheMu.Lock()
	if e.adminAuthCache == nil {
		e.adminAuthCache = make(map[uint32]adminAuthCacheEntry)
	} else if len(e.adminAuthCache) > 256 {
		for k, v := range e.adminAuthCache {
			if !now.Before(v.expiresAt) {
				delete(e.adminAuthCache, k)
			}
		}
	}
	e.adminAuthCache[peerUID] = adminAuthCacheEntry{
		username:  username,
		ok:        ok,
		expiresAt: now.Add(5 * time.Second),
	}
	e.authCacheMu.Unlock()

	return username, ok
}

func (e *Engine) uncachedAuthorizedAdminUID(peerUID uint32) (string, bool) {
	username := lookupUsernameByUID(e.PasswdPath, peerUID)
	if username == "" || config.ValidateIdentifier(username) != nil {
		return "", false
	}
	if username == "diradmin" {
		return "diradmin", true
	}

	for _, adm := range readLinesList(filepath.Join(e.DADataRoot, "admin", "admin.list")) {
		if adm == username {
			return username, true
		}
	}

	userConfPath := filepath.Join(e.DAUsersDir, username, "user.conf")
	if kv, err := config.ParseKeyValueFile(userConfPath); err == nil {
		if strings.EqualFold(strings.TrimSpace(kv["usertype"]), "admin") {
			return username, true
		}
	}

	return "", false
}

// HandleAdminRequest implements ipc.RequestHandler for /var/run/da-resourced.sock.
func (e *Engine) HandleAdminRequest(ctx context.Context, peerUID uint32, req ipc.Request) ipc.Response {
	if _, ok := e.IsAuthorizedAdminUID(peerUID); !ok {
		return ipc.Response{
			OK:    false,
			Error: fmt.Sprintf("permission denied: caller UID %d is not a DirectAdmin administrator", peerUID),
		}
	}

	switch req.Action {
	case ipc.ActionPing:
		return ipc.Response{OK: true, Data: e.buildPingData()}

	case ipc.ActionGetRealtimeStats:
		accounts := e.Registry.All()
		users := make([]ipc.UserUsageSnapshot, 0, len(accounts))
		for _, acct := range accounts {
			users = append(users, e.BuildUserSnapshot(acct, false))
		}
		return ipc.Response{
			OK: true,
			Data: ipc.RealtimeDashboardData{
				Daemon: e.buildPingData(),
				Users:  users,
			},
		}

	case ipc.ActionGetUserStats:
		acct, ok := e.Registry.LookupByName(req.Username)
		if !ok {
			return ipc.Response{OK: false, Error: fmt.Sprintf("user %q not found", req.Username)}
		}
		return ipc.Response{OK: true, Data: e.buildUserPortalData(acct)}

	case ipc.ActionGetPackages:
		data, err := e.listPackagesData()
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Data: data}

	case ipc.ActionSaveDefaultLimits:
		if req.Limits == nil {
			return ipc.Response{OK: false, Error: "missing limits payload"}
		}
		if err := e.Store.SaveDefaultLimits(*req.Limits); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		if req.SyncUsers {
			total := e.Registry.Count()
			if e.AsyncSyncThreshold > 0 && total > e.AsyncSyncThreshold {
				e.enqueueBackgroundSyncAll()
				return ipc.Response{OK: true, Message: fmt.Sprintf("saved default limits (background sync queued for %d users)", total)}
			}
			if err := e.ApplyAll(ctx); err != nil {
				return ipc.Response{OK: false, Error: err.Error()}
			}
		}
		return ipc.Response{OK: true, Message: "saved default limits"}

	case ipc.ActionSavePackageLimits:
		if req.Limits == nil {
			return ipc.Response{OK: false, Error: "missing limits payload"}
		}
		if err := e.Store.SavePackageLimits(req.Package, *req.Limits); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		if req.SyncUsers {
			pkgCount := e.countPackageUsers(req.Package)
			if e.AsyncSyncThreshold > 0 && pkgCount > e.AsyncSyncThreshold {
				e.enqueueBackgroundSyncPackage(req.Package)
				return ipc.Response{OK: true, Message: fmt.Sprintf("saved package %q (background sync queued for %d users)", req.Package, pkgCount)}
			}
			synced, err := e.ApplyPackage(ctx, req.Package)
			if err != nil {
				return ipc.Response{OK: false, Error: err.Error()}
			}
			return ipc.Response{OK: true, Message: fmt.Sprintf("saved package %q (synced %d users)", req.Package, synced)}
		}
		return ipc.Response{OK: true, Message: fmt.Sprintf("saved package %q", req.Package)}

	case ipc.ActionSaveUserLimits:
		if req.Limits == nil {
			return ipc.Response{OK: false, Error: "missing limits payload"}
		}
		lim := *req.Limits
		lim.CustomOverride = true
		if err := e.Store.SaveUserLimits(req.Username, lim); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		if err := e.ApplyUser(ctx, req.Username); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: fmt.Sprintf("saved and applied custom limits for %q", req.Username)}

	case ipc.ActionResetUserLimits:
		if err := e.Store.DeleteUserLimits(req.Username); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		if err := e.ApplyUser(ctx, req.Username); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: fmt.Sprintf("reset %q to package defaults", req.Username)}

	case ipc.ActionApplyUserLimits:
		if err := e.ApplyUser(ctx, req.Username); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: fmt.Sprintf("applied limits for %q", req.Username)}

	case ipc.ActionApplyPackageLimits:
		pkgCount := e.countPackageUsers(req.Package)
		if e.AsyncSyncThreshold > 0 && pkgCount > e.AsyncSyncThreshold {
			e.enqueueBackgroundSyncPackage(req.Package)
			return ipc.Response{OK: true, Message: fmt.Sprintf("background sync queued for %d users in package %q", pkgCount, req.Package)}
		}
		synced, err := e.ApplyPackage(ctx, req.Package)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: fmt.Sprintf("synced %d users in package %q", synced, req.Package)}

	case ipc.ActionApplyDBUser:
		if err := e.ApplyNewDBUser(ctx, req.Username, req.DBUser); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: fmt.Sprintf("applied MariaDB limits to %q", req.DBUser)}

	case ipc.ActionRemoveUser:
		if err := e.RemoveUser(ctx, req.Username); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: fmt.Sprintf("removed limits for %q", req.Username)}

	case ipc.ActionUnblockPenalty:
		if e.MySQLGov == nil {
			return ipc.Response{OK: false, Error: "MariaDB Governor is not active"}
		}
		if err := e.MySQLGov.UnblockUser(ctx, req.Username); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: fmt.Sprintf("unblocked MySQL penalty for %q", req.Username)}

	case ipc.ActionGetLogs:
		if e.Logger == nil {
			return ipc.Response{OK: true, Data: []ipc.ViolationEntry{}}
		}
		entries, err := e.Logger.Query(req.Username, req.ViolationType, req.Limit)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Data: entries}

	case ipc.ActionGetUpdaterStatus:
		return e.handleGetUpdaterStatus(ctx, peerUID)

	case ipc.ActionCheckUpdate:
		if e.Updater == nil {
			return ipc.Response{OK: false, Error: "GitHub Updater service is not initialized"}
		}
		st, err := e.Updater.CheckLatest(ctx)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		st.CanManageUpdater = (peerUID == 0)
		return ipc.Response{OK: true, Data: st}

	case ipc.ActionSaveUpdaterConfig:
		// DirectAdmin executes admin/api.raw as UID diradmin regardless of which DA admin account is logged in,
		// so root-equivalent updater mutations are strictly locked to UID 0 (root SSH CLI) (N11).
		if peerUID != 0 {
			return ipc.Response{
				OK:    false,
				Error: "permission denied: updater configuration is restricted to root CLI (run `da-resourced config-updater` as root via SSH)",
			}
		}
		return e.handleSaveUpdaterConfig(req)

	case ipc.ActionTriggerUpdate:
		if peerUID != 0 {
			return ipc.Response{
				OK:    false,
				Error: "permission denied: self-update execution is restricted to root CLI (run `da-resourced update` as root via SSH)",
			}
		}
		if e.Updater == nil {
			return ipc.Response{OK: false, Error: "GitHub Updater service is not initialized"}
		}
		msg, err := e.Updater.TriggerUpdate(ctx, req.TargetVersion)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: msg}

	case ipc.ActionRollbackUpdate:
		if peerUID != 0 {
			return ipc.Response{
				OK:    false,
				Error: "permission denied: snapshot rollback is restricted to root CLI (run `da-resourced rollback` as root via SSH)",
			}
		}
		if e.Updater == nil {
			return ipc.Response{OK: false, Error: "GitHub Updater service is not initialized"}
		}
		msg, err := e.Updater.TriggerRollback(ctx)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: msg}

	default:
		return ipc.Response{OK: false, Error: fmt.Sprintf("unknown action %q", req.Action)}
	}
}

// HandleUserRequest implements kernel-isolated read-only telemetry for /var/run/da-resourced-user.sock.
func (e *Engine) HandleUserRequest(_ context.Context, peerUID uint32, req ipc.Request) ipc.Response {
	var acct dausers.Account
	var ok bool

	// Only root, diradmin, or a DirectAdmin Administrator may inspect arbitrary req.Username;
	// regular customer processes are strictly locked to their kernel SO_PEERCRED UID.
	if adminName, isAdmin := e.IsAuthorizedAdminUID(peerUID); isAdmin {
		if req.Username != "" {
			acct, ok = e.Registry.LookupByName(req.Username)
		}
		if !ok {
			cgStats, _ := e.CgroupMgr.ReadSliceStats(peerUID)
			displayName := adminName
			if req.Username != "" && config.ValidateIdentifier(req.Username) == nil {
				displayName = req.Username
			}
			switch req.Action {
			case ipc.ActionGetUserStats:
				return ipc.Response{
					OK: true,
					Data: ipc.UserPortalData{
						Snapshot: ipc.UserUsageSnapshot{
							Username:        displayName,
							UID:             peerUID,
							Package:         "admin (Miễn trừ giới hạn)",
							CPUPercent:      cgStats.CPUPercent,
							MemoryCurrentMB: cgStats.MemoryCurrentMB,
							ActiveProcesses: cgStats.ActiveProcesses,
							Limits:          config.ResourceLimits{Enabled: false},
						},
					},
				}
			case ipc.ActionGetLogs:
				return ipc.Response{OK: true, Data: []ipc.ViolationEntry{}}
			default:
				return ipc.Response{OK: false, Error: "permission denied: read-only user socket"}
			}
		}
	} else {
		acct, ok = e.Registry.LookupByUID(peerUID)
		if !ok {
			return ipc.Response{OK: false, Error: "caller UID is not a managed DirectAdmin hosting account"}
		}
	}

	switch req.Action {
	case ipc.ActionGetUserStats:
		return ipc.Response{OK: true, Data: e.buildUserPortalData(acct)}

	case ipc.ActionGetLogs:
		if e.Logger == nil {
			return ipc.Response{OK: true, Data: []ipc.ViolationEntry{}}
		}
		limit := req.Limit
		if limit <= 0 || limit > 20 {
			limit = 10
		}
		entries, err := e.Logger.Query(acct.Username, req.ViolationType, limit)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Data: entries}

	default:
		return ipc.Response{OK: false, Error: "permission denied: read-only user socket"}
	}
}

func (e *Engine) buildPingData() ipc.PingData {
	penalties := 0
	if e.MySQLGov != nil {
		penalties = len(e.MySQLGov.ActivePenalties())
	}
	syncInProgress, syncLabel := e.SyncStatus()
	return ipc.PingData{
		Version:         version.Version,
		Commit:          version.Commit,
		BuildTime:       version.BuildTime,
		UptimeSeconds:   int64(time.Since(e.StartedAt).Seconds()),
		ManagedUsers:    e.Registry.Count(),
		ActivePenalties: penalties,
		SyncInProgress:  syncInProgress,
		SyncLabel:       syncLabel,
	}
}

func (e *Engine) buildUserPortalData(acct dausers.Account) ipc.UserPortalData {
	snap := e.BuildUserSnapshot(acct, true)
	var topSQL []ipc.ViolationEntry
	if e.Logger != nil {
		recent, _ := e.Logger.Query(acct.Username, "", 50)
		for _, item := range recent {
			if item.Type == logger.TypeMySQLHighMemory || item.Type == logger.TypeMySQLSlowQuery {
				topSQL = append(topSQL, item)
				if len(topSQL) >= 5 {
					break
				}
			}
		}
	}
	return ipc.UserPortalData{
		Snapshot:         snap,
		TopKilledQueries: topSQL,
	}
}

func (e *Engine) listPackagesData() (ipc.PackagesData, error) {
	defLimits := config.DefaultLimits()
	if kv, err := config.ParseKeyValueFile(e.Store.DefaultConfPath()); err == nil {
		defLimits = config.ApplyKV(defLimits, kv)
	}
	defLimits, _ = defLimits.ClampPenaltyUpperBounds()

	pkgNames := make(map[string]struct{})
	userCounts := make(map[string]int)

	// 1. Admin packages.list
	for _, p := range readLinesList(filepath.Join(e.DADataRoot, "admin", "packages.list")) {
		if config.ValidateIdentifier(p) == nil {
			pkgNames[p] = struct{}{}
		}
	}

	// 2. Reseller packages.list & active user packages
	for _, acct := range e.Registry.All() {
		if acct.Package != "" && config.ValidateIdentifier(acct.Package) == nil {
			pkgNames[acct.Package] = struct{}{}
			userCounts[acct.Package]++
		}
		for _, p := range readLinesList(filepath.Join(e.DAUsersDir, acct.Username, "packages.list")) {
			if config.ValidateIdentifier(p) == nil {
				pkgNames[p] = struct{}{}
			}
		}
	}

	// 3. Existing configured files in plugin/data/packages/*.conf
	if entries, err := os.ReadDir(filepath.Join(e.Store.DataDir, "packages")); err == nil {
		for _, ent := range entries {
			if !ent.IsDir() && strings.HasSuffix(ent.Name(), ".conf") {
				p := strings.TrimSuffix(ent.Name(), ".conf")
				if config.ValidateIdentifier(p) == nil {
					pkgNames[p] = struct{}{}
				}
			}
		}
	}

	sorted := make([]string, 0, len(pkgNames))
	for p := range pkgNames {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)

	items := make([]ipc.PackageConfigItem, 0, len(sorted))
	for _, p := range sorted {
		lim := defLimits
		lim.Package = p
		hasCustom := false
		if pkgPath, err := e.Store.PackageConfPath(p); err == nil {
			if kv, err := config.ParseKeyValueFile(pkgPath); err == nil {
				lim = config.ApplyKV(lim, kv)
				lim.Package = p
				hasCustom = true
			}
		}
		lim, _ = lim.ClampPenaltyUpperBounds()
		items = append(items, ipc.PackageConfigItem{
			Package:       p,
			HasCustomFile: hasCustom,
			UserCount:     userCounts[p],
			Limits:        lim,
		})
	}

	return ipc.PackagesData{
		DefaultLimits: defLimits,
		Packages:      items,
	}, nil
}

func (e *Engine) handleGetUpdaterStatus(ctx context.Context, peerUID uint32) ipc.Response {
	canManage := (peerUID == 0)
	if e.Updater != nil {
		st, err := e.Updater.GetStatus(ctx)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		st.CanManageUpdater = canManage
		return ipc.Response{OK: true, Data: st}
	}

	cfg, err := e.Store.LoadUpdaterConfig()
	if err != nil {
		return ipc.Response{OK: false, Error: err.Error()}
	}
	return ipc.Response{
		OK: true,
		Data: ipc.UpdaterStatusData{
			CurrentVersion:    version.Version,
			GitHubRepo:        cfg.GitHubRepo,
			RepoPinned:        !cfg.AllowCustomRepo,
			SignatureRequired: version.DefaultReleasePublicKeyHex != "",
			RootOnlyActions:   true,
			CanManageUpdater:  canManage,
			HasToken:          cfg.GitHubToken != "",
			MaskedToken:       cfg.MaskedToken(),
			UpdateChannel:     cfg.UpdateChannel,
			BackupRetention:   cfg.BackupRetention,
		},
	}
}

func (e *Engine) handleSaveUpdaterConfig(req ipc.Request) ipc.Response {
	existing, err := e.Store.LoadUpdaterConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ipc.Response{OK: false, Error: err.Error()}
	}
	// Repository is pinned over IPC to block privilege escalation via untrusted repositories (S1).
	if trimmedRepo := strings.TrimSpace(req.GitHubRepo); trimmedRepo != "" && trimmedRepo != existing.GitHubRepo {
		return ipc.Response{
			OK:    false,
			Error: fmt.Sprintf("changing github_repo over IPC is disabled (pinned to %q)", existing.GitHubRepo),
		}
	}
	if !req.KeepStoredToken {
		existing.GitHubToken = req.GitHubToken
	}
	if req.UpdateChannel != "" {
		existing.UpdateChannel = req.UpdateChannel
	}
	if req.BackupRetention > 0 {
		existing.BackupRetention = req.BackupRetention
	}
	if err := e.Store.SaveUpdaterConfig(existing); err != nil {
		return ipc.Response{OK: false, Error: err.Error()}
	}
	return ipc.Response{OK: true, Message: "saved GitHub Updater configuration"}
}

func readLinesList(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func lookupUserUID(passwdPath, username string) uint32 {
	f, err := os.Open(passwdPath)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) >= 3 && parts[0] == username {
			if uid, err := strconv.ParseUint(parts[2], 10, 32); err == nil {
				return uint32(uid)
			}
		}
	}
	return 0
}

func lookupUsernameByUID(passwdPath string, targetUID uint32) string {
	f, err := os.Open(passwdPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) >= 3 {
			if uid, err := strconv.ParseUint(parts[2], 10, 32); err == nil && uint32(uid) == targetUID {
				return strings.TrimSpace(parts[0])
			}
		}
	}
	return ""
}
