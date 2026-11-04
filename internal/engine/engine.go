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

// UpdaterProvider abstracts GitHub Releases operations implemented in Phase 4.
type UpdaterProvider interface {
	GetStatus(ctx context.Context) (ipc.UpdaterStatusData, error)
	CheckLatest(ctx context.Context) (ipc.UpdaterStatusData, error)
	TriggerUpdate(ctx context.Context, targetVersion string) (string, error)
	TriggerRollback(ctx context.Context) (string, error)
}

// Engine coordinates Cgroups v2, PHP-FPM classification, MariaDB Governor, Violation Logs, and IPC requests.
type Engine struct {
	StartedAt     time.Time
	Store         *config.Store
	Registry      *dausers.Registry
	CgroupMgr     *cgroup.Manager
	Classifier    *fpm.Classifier
	MySQLGov      *mysqlgov.Governor
	Logger        *logger.ViolationLogger
	Updater       UpdaterProvider
	DADataRoot    string // Default: /usr/local/directadmin/data
	DAUsersDir    string // Default: /usr/local/directadmin/data/users
	PasswdPath    string // Default: /etc/passwd
	DiradminUID   uint32

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
	return &Engine{
		StartedAt:   time.Now(),
		Store:       store,
		Registry:    reg,
		CgroupMgr:   cgMgr,
		Classifier:  cls,
		MySQLGov:    mysqlGov,
		Logger:      vlog,
		DADataRoot:  daDataRoot,
		DAUsersDir:  filepath.Join(daDataRoot, "users"),
		PasswdPath:  passwdPath,
		DiradminUID: lookupUserUID(passwdPath, "diradmin"),
		oomBaseline: make(map[uint32]uint64),
	}
}

// ApplyUser applies OS Cgroups v2 slice, DirectAdmin PHP tokens, PHP PID migration, and MariaDB Tier-2 limits.
func (e *Engine) ApplyUser(ctx context.Context, username string) error {
	if err := config.ValidateIdentifier(username); err != nil {
		return err
	}
	acct, ok := e.Registry.LookupByName(username)
	if !ok {
		// Refresh registry in case DirectAdmin just created this user milliseconds ago
		_ = e.Registry.Reload()
		acct, ok = e.Registry.LookupByName(username)
		if !ok {
			return fmt.Errorf("DirectAdmin hosting user %q not found", username)
		}
	}

	limits, err := e.Store.ResolveUserLimits(acct.Username, acct.Package)
	if err != nil {
		return err
	}

	if err := e.CgroupMgr.ApplyUserSlice(ctx, acct.UID, limits); err != nil {
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

// ApplyAll batch-synchronizes Cgroups v2 slices, PHP tokens, and MariaDB limits for all DirectAdmin users.
func (e *Engine) ApplyAll(ctx context.Context) error {
	accounts := e.Registry.All()
	anySliceChanged := false
	var enabledAccounts []dausers.Account

	for _, acct := range accounts {
		limits, err := e.Store.ResolveUserLimits(acct.Username, acct.Package)
		if err != nil {
			log.Printf("skip %s: resolve limits error: %v", acct.Username, err)
			continue
		}
		changed, err := e.CgroupMgr.StageUserSlice(acct.UID, limits)
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
		_ = fpm.SyncDAUserPHPConf(e.DAUsersDir, acct.Username, limits)
		if e.MySQLGov != nil {
			if err := e.MySQLGov.ApplyUserAccountLimits(ctx, acct.Username, limits); err != nil {
				log.Printf("warning: MariaDB limits for %s: %v", acct.Username, err)
			}
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
	return nil
}

// ApplyPackage re-applies limits to all users assigned to packageName unless they have CUSTOM_OVERRIDE=yes.
func (e *Engine) ApplyPackage(ctx context.Context, packageName string) (int, error) {
	if err := config.ValidateIdentifier(packageName); err != nil {
		return 0, err
	}
	_ = e.Registry.Reload()

	synced := 0
	for _, acct := range e.Registry.All() {
		if acct.Package != packageName {
			continue
		}
		// Respect explicit per-user overrides
		if userConfPath, err := e.Store.UserConfPath(acct.Username); err == nil {
			if kv, err := config.ParseKeyValueFile(userConfPath); err == nil {
				if strings.EqualFold(kv["CUSTOM_OVERRIDE"], "yes") || strings.EqualFold(kv["CUSTOM_OVERRIDE"], "true") {
					continue
				}
			}
		}
		if err := e.ApplyUser(ctx, acct.Username); err != nil {
			log.Printf("apply package %s -> user %s error: %v", packageName, acct.Username, err)
			continue
		}
		synced++
	}
	return synced, nil
}

// ApplyNewDBUser immediately enforces Tier-2 MariaDB limits on a newly created database user.
func (e *Engine) ApplyNewDBUser(ctx context.Context, daUsername, dbUser string) error {
	if err := config.ValidateIdentifier(daUsername); err != nil {
		return err
	}
	if e.MySQLGov == nil {
		return nil
	}
	_ = e.Registry.Reload()
	pkg := ""
	if acct, ok := e.Registry.LookupByName(daUsername); ok {
		pkg = acct.Package
	}
	limits, err := e.Store.ResolveUserLimits(daUsername, pkg)
	if err != nil {
		return err
	}
	return e.MySQLGov.ApplySingleDBUserLimits(ctx, dbUser, limits)
}

// RemoveUser cleans up slice drop-in files, resets MariaDB limits, and deletes custom user config.
func (e *Engine) RemoveUser(ctx context.Context, username string) error {
	if err := config.ValidateIdentifier(username); err != nil {
		return err
	}
	if acct, ok := e.Registry.LookupByName(username); ok {
		_ = e.CgroupMgr.RemoveUserSlice(ctx, acct.UID)
		e.oomMu.Lock()
		delete(e.oomBaseline, acct.UID)
		e.oomMu.Unlock()
	}
	if e.MySQLGov != nil {
		_ = e.MySQLGov.UnblockUser(ctx, username)
		_ = e.MySQLGov.RemoveUserAccountLimits(ctx, username)
	}
	if err := e.Store.DeleteUserLimits(username); err != nil {
		return err
	}
	_ = e.Registry.Reload()
	return nil
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

// HandleAdminRequest implements ipc.RequestHandler for /var/run/da-resourced.sock.
func (e *Engine) HandleAdminRequest(ctx context.Context, req ipc.Request) ipc.Response {
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
			_ = e.ApplyAll(ctx)
		}
		return ipc.Response{OK: true, Message: "saved default limits"}

	case ipc.ActionSavePackageLimits:
		if req.Limits == nil {
			return ipc.Response{OK: false, Error: "missing limits payload"}
		}
		if err := e.Store.SavePackageLimits(req.Package, *req.Limits); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		synced := 0
		if req.SyncUsers {
			var err error
			synced, err = e.ApplyPackage(ctx, req.Package)
			if err != nil {
				return ipc.Response{OK: false, Error: err.Error()}
			}
		}
		return ipc.Response{OK: true, Message: fmt.Sprintf("saved package %q (synced %d users)", req.Package, synced)}

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
		return e.handleGetUpdaterStatus(ctx)

	case ipc.ActionSaveUpdaterConfig:
		return e.handleSaveUpdaterConfig(req)

	case ipc.ActionCheckUpdate:
		if e.Updater == nil {
			return ipc.Response{OK: false, Error: "GitHub Updater service is not initialized"}
		}
		st, err := e.Updater.CheckLatest(ctx)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Data: st}

	case ipc.ActionTriggerUpdate:
		if e.Updater == nil {
			return ipc.Response{OK: false, Error: "GitHub Updater service is not initialized"}
		}
		msg, err := e.Updater.TriggerUpdate(ctx, req.TargetVersion)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Message: msg}

	case ipc.ActionRollbackUpdate:
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

	// Only root (UID 0) or diradmin may specify req.Username; customer processes are locked to their kernel SO_PEERCRED UID
	if peerUID == 0 || (e.DiradminUID > 0 && peerUID == e.DiradminUID) {
		acct, ok = e.Registry.LookupByName(req.Username)
		if !ok {
			return ipc.Response{OK: false, Error: "hosting user not found"}
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
	return ipc.PingData{
		Version:         version.Version,
		Commit:          version.Commit,
		BuildTime:       version.BuildTime,
		UptimeSeconds:   int64(time.Since(e.StartedAt).Seconds()),
		ManagedUsers:    e.Registry.Count(),
		ActivePenalties: penalties,
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

func (e *Engine) handleGetUpdaterStatus(ctx context.Context) ipc.Response {
	if e.Updater != nil {
		st, err := e.Updater.GetStatus(ctx)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Data: st}
	}

	cfg, err := e.Store.LoadUpdaterConfig()
	if err != nil {
		return ipc.Response{OK: false, Error: err.Error()}
	}
	return ipc.Response{
		OK: true,
		Data: ipc.UpdaterStatusData{
			CurrentVersion:  version.Version,
			GitHubRepo:      cfg.GitHubRepo,
			HasToken:        cfg.GitHubToken != "",
			MaskedToken:     cfg.MaskedToken(),
			UpdateChannel:   cfg.UpdateChannel,
			BackupRetention: cfg.BackupRetention,
		},
	}
}

func (e *Engine) handleSaveUpdaterConfig(req ipc.Request) ipc.Response {
	existing, err := e.Store.LoadUpdaterConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ipc.Response{OK: false, Error: err.Error()}
	}
	if req.GitHubRepo != "" {
		existing.GitHubRepo = req.GitHubRepo
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
