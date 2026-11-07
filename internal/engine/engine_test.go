package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/cgroup"
	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
	"github.com/shostwp-byte/da-resourcelimiter/internal/ipc"
	"github.com/shostwp-byte/da-resourcelimiter/internal/logger"
	"github.com/shostwp-byte/da-resourcelimiter/internal/mysqlgov"
)

type noopCmdRunner struct{}

func (noopCmdRunner) Run(_ context.Context, _ string, _ ...string) error { return nil }

type mockEngineSQL struct {
	executed []string
}

func (m *mockEngineSQL) QueryTSV(_ context.Context, _ string) ([]string, error) { return nil, nil }
func (m *mockEngineSQL) ExecBatch(_ context.Context, sql string) error {
	m.executed = append(m.executed, sql)
	return nil
}

type mockUpdater struct{}

func (mockUpdater) GetStatus(_ context.Context) (ipc.UpdaterStatusData, error) {
	return ipc.UpdaterStatusData{CurrentVersion: "v1.0.4.1", RepoPinned: true}, nil
}
func (mockUpdater) CheckLatest(_ context.Context) (ipc.UpdaterStatusData, error) {
	return ipc.UpdaterStatusData{CurrentVersion: "v1.0.4.1", LatestVersion: "v1.0.4.1"}, nil
}
func (mockUpdater) TriggerUpdate(_ context.Context, _ string) (string, error) {
	return "update started", nil
}
func (mockUpdater) TriggerRollback(_ context.Context) (string, error) {
	return "rollback started", nil
}

func TestEngineSecurityUpdaterLockDBOwnershipAndOrphanCleanup(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "plugin_data")
	daRoot := filepath.Join(tmp, "da_data")
	daUsersDir := filepath.Join(daRoot, "users")
	passwdPath := filepath.Join(tmp, "passwd")
	systemdDir := filepath.Join(tmp, "systemd")
	cgRoot := filepath.Join(tmp, "cgroup")

	passwd := "" +
		"diradmin:x:995:995::/usr/local/directadmin:/bin/false\n" +
		"admin:x:1001:1001::/home/admin:/bin/bash\n" +
		"alice:x:1005:1005::/home/alice:/bin/bash\n" +
		"bob:x:1006:1006::/home/bob:/bin/bash\n"
	_ = os.WriteFile(passwdPath, []byte(passwd), 0o644)

	_ = os.MkdirAll(filepath.Join(daUsersDir, "admin"), 0o755)
	_ = os.WriteFile(filepath.Join(daUsersDir, "admin", "user.conf"), []byte("usertype=admin\n"), 0o600)

	for _, u := range []string{"alice", "bob"} {
		_ = os.MkdirAll(filepath.Join(daUsersDir, u), 0o755)
		_ = os.WriteFile(filepath.Join(daUsersDir, u, "user.conf"), []byte("usertype=user\npackage=gold\n"), 0o600)
	}
	_ = os.MkdirAll(filepath.Join(daRoot, "admin"), 0o755)
	_ = os.WriteFile(filepath.Join(daRoot, "admin", "admin.list"), []byte("admin\n"), 0o644)
	_ = os.WriteFile(filepath.Join(daRoot, "admin", "packages.list"), []byte("gold\nsilver\n"), 0o644)

	store := config.NewStore(dataDir, filepath.Join(tmp, "updater.conf"))
	reg := dausers.NewRegistry(daUsersDir, passwdPath)
	_ = reg.Reload()
	cgMgr := cgroup.NewManager(systemdDir, cgRoot, noopCmdRunner{})
	vlog := logger.NewViolationLogger(filepath.Join(tmp, "violations.jsonl"), 1024*1024, 2)
	sqlMock := &mockEngineSQL{}
	gov := mysqlgov.NewGovernor(sqlMock, reg, func(acct dausers.Account) (config.ResourceLimits, error) {
		return store.ResolveUserLimits(acct.Username, acct.Package)
	}, vlog, filepath.Join(tmp, "penalties.json"))

	eng := New(store, reg, cgMgr, nil, gov, vlog, daRoot, passwdPath)
	eng.Updater = mockUpdater{}

	// 1. Verify AuthorizeSocketPeer blocks non-admin UID 1005 on Admin socket before decode (S5)
	if err := eng.AuthorizeSocketPeer(1005, true); err == nil {
		t.Fatal("expected customer UID 1005 to fail pre-decode authorization on Admin socket")
	}
	if err := eng.AuthorizeSocketPeer(1005, false); err != nil {
		t.Fatalf("expected customer UID 1005 to pass pre-decode authorization on User socket: %v", err)
	}

	// 2. Verify secondary DA admin (UID 1001) CAN manage hosting limits, but CANNOT trigger root updater actions (S1)
	vipLimits := config.DefaultLimits()
	vipLimits.CPUQuota = 400
	resp := eng.HandleAdminRequest(context.Background(), 1001, ipc.Request{
		Action:   ipc.ActionSaveUserLimits,
		Username: "bob",
		Limits:   &vipLimits,
	})
	if !resp.OK {
		t.Fatalf("SaveUserLimits bob as DA admin (UID 1001) failed: %+v", resp)
	}

	// Verify BOTH secondary DA admin (UID 1001) AND diradmin Web CGI (UID 995) are blocked from updater mutations (N11),
	// while still receiving read-only updater status with CanManageUpdater=false.
	diradminStatus := eng.HandleAdminRequest(context.Background(), 995, ipc.Request{Action: ipc.ActionGetUpdaterStatus})
	if !diradminStatus.OK {
		t.Fatalf("GetUpdaterStatus as diradmin failed: %+v", diradminStatus)
	}
	if st, ok := diradminStatus.Data.(ipc.UpdaterStatusData); !ok || st.CanManageUpdater {
		t.Fatalf("expected CanManageUpdater=false for diradmin UID 995 (N11), got %+v", diradminStatus.Data)
	}

	rootStatus := eng.HandleAdminRequest(context.Background(), 0, ipc.Request{Action: ipc.ActionGetUpdaterStatus})
	if st, ok := rootStatus.Data.(ipc.UpdaterStatusData); !ok || !st.CanManageUpdater {
		t.Fatalf("expected CanManageUpdater=true for root UID 0 (N11), got %+v", rootStatus.Data)
	}

	for _, nonRootUID := range []uint32{1001, 995} {
		for _, rootOnlyAct := range []string{ipc.ActionSaveUpdaterConfig, ipc.ActionTriggerUpdate, ipc.ActionRollbackUpdate} {
			denied := eng.HandleAdminRequest(context.Background(), nonRootUID, ipc.Request{Action: rootOnlyAct})
			if denied.OK {
				t.Fatalf("expected UID %d to be blocked from %s (N11), got %+v", nonRootUID, rootOnlyAct, denied)
			}
		}
	}

	// Verify root (UID 0) CAN run updater actions, EXCEPT changing github_repo over IPC (S1, N11)
	repoChangeAttempt := eng.HandleAdminRequest(context.Background(), 0, ipc.Request{
		Action:          ipc.ActionSaveUpdaterConfig,
		GitHubRepo:      "attacker/evilrepo",
		KeepStoredToken: true,
	})
	if repoChangeAttempt.OK {
		t.Fatalf("expected changing github_repo over IPC to be rejected even for root (S1)")
	}
	validRootSave := eng.HandleAdminRequest(context.Background(), 0, ipc.Request{
		Action:          ipc.ActionSaveUpdaterConfig,
		UpdateChannel:   "stable",
		BackupRetention: 5,
		KeepStoredToken: true,
	})
	if !validRootSave.OK {
		t.Fatalf("expected root UID 0 to save token/channel config: %+v", validRootSave)
	}
	rootTrigger := eng.HandleAdminRequest(context.Background(), 0, ipc.Request{Action: ipc.ActionTriggerUpdate})
	if !rootTrigger.OK {
		t.Fatalf("expected root UID 0 to trigger update: %+v", rootTrigger)
	}

	// 3. Update package "gold" to 200% CPU with SyncUsers=true -> must sync alice, skipping bob's custom override
	goldLimits := config.DefaultLimits()
	goldLimits.CPUQuota = 200
	pkgResp := eng.HandleAdminRequest(context.Background(), 0, ipc.Request{
		Action:    ipc.ActionSavePackageLimits,
		Package:   "gold",
		SyncUsers: true,
		Limits:    &goldLimits,
	})
	if !pkgResp.OK {
		t.Fatalf("SavePackageLimits gold failed: %+v", pkgResp)
	}

	bobResolved, _ := store.ResolveUserLimits("bob", "gold")
	if bobResolved.CPUQuota != 400 {
		t.Fatalf("expected bob's custom override (400%%) to remain untouched, got %d%%", bobResolved.CPUQuota)
	}
	aliceResolved, _ := store.ResolveUserLimits("alice", "gold")
	if aliceResolved.CPUQuota != 200 {
		t.Fatalf("expected alice to inherit gold (200%%), got %d%%", aliceResolved.CPUQuota)
	}

	// 4. Verify S9: ApplyNewDBUser rejects protected system account "da_admin" and cross-tenant DB user "alice_wp" for "bob"
	if err := eng.ApplyNewDBUser(context.Background(), "bob", "da_admin"); err == nil {
		t.Fatal("expected ApplyNewDBUser to block protected account da_admin (S9)")
	}
	if err := eng.ApplyNewDBUser(context.Background(), "bob", "alice_wp"); err == nil {
		t.Fatal("expected ApplyNewDBUser to block cross-tenant DB user alice_wp under bob (S9)")
	}
	if err := eng.ApplyNewDBUser(context.Background(), "bob", "bob_wp"); err != nil {
		t.Fatalf("expected ApplyNewDBUser for owned DB user bob_wp to succeed: %v", err)
	}

	// 5. Verify R5: Simulate DirectAdmin deleting "bob" from /etc/passwd and da_data/users/bob BEFORE RemoveUser runs,
	// AND after a periodic Registry.Reload() already cleared bob from memory!
	if _, err := os.Stat(cgMgr.SliceDropInPath(1006)); err != nil {
		t.Fatalf("expected user-1006 drop-in to exist before deletion: %v", err)
	}
	newPasswd := strings.ReplaceAll(passwd, "bob:x:1006:1006::/home/bob:/bin/bash\n", "")
	_ = os.WriteFile(passwdPath, []byte(newPasswd), 0o644)
	_ = os.RemoveAll(filepath.Join(daUsersDir, "bob"))
	_ = reg.Reload() // bob is now gone from Registry in memory too!

	if err := eng.RemoveUser(context.Background(), "bob"); err != nil {
		t.Fatalf("RemoveUser after passwd removal: %v", err)
	}
	if _, err := os.Stat(cgMgr.SliceDropInPath(1006)); !os.IsNotExist(err) {
		t.Fatalf("expected orphaned user-1006.slice drop-in to be cleaned up (R5), err=%v", err)
	}

	// 6. Verify SO_PEERCRED isolation: UID 1005 (alice) asks for Username="bob" -> MUST receive "alice" instead!
	userResp := eng.HandleUserRequest(context.Background(), 1005, ipc.Request{
		Action:   ipc.ActionGetUserStats,
		Username: "bob",
	})
	if !userResp.OK {
		t.Fatalf("HandleUserRequest failed: %+v", userResp)
	}
	portal, ok := userResp.Data.(ipc.UserPortalData)
	if !ok || portal.Snapshot.Username != "alice" {
		t.Fatalf("tenant isolation breach: UID 1005 got %+v", userResp.Data)
	}
}

func TestApplyLockContextCancelAndCoalescingBackgroundWorker(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "plugin_data")
	daRoot := filepath.Join(tmp, "da_data")
	daUsersDir := filepath.Join(daRoot, "users")
	passwdPath := filepath.Join(tmp, "passwd")

	_ = os.WriteFile(passwdPath, []byte("alice:x:1005:1005::/home/alice:/bin/bash\nbob:x:1006:1006::/home/bob:/bin/bash\n"), 0o644)
	for _, u := range []string{"alice", "bob"} {
		_ = os.MkdirAll(filepath.Join(daUsersDir, u), 0o755)
		_ = os.WriteFile(filepath.Join(daUsersDir, u, "user.conf"), []byte("usertype=user\npackage=gold\n"), 0o600)
	}

	store := config.NewStore(dataDir, filepath.Join(tmp, "updater.conf"))
	reg := dausers.NewRegistry(daUsersDir, passwdPath)
	_ = reg.Reload()
	cgMgr := cgroup.NewManager(filepath.Join(tmp, "systemd"), filepath.Join(tmp, "cgroup"), noopCmdRunner{})

	eng := New(store, reg, cgMgr, nil, nil, nil, daRoot, passwdPath)
	eng.AsyncSyncThreshold = 1 // Force background sync queue when >1 user

	// 1. N9a: acquireApplyLock respects context deadline when semaphore is already held
	release, err := eng.acquireApplyLock(context.Background())
	if err != nil {
		t.Fatalf("acquireApplyLock #1: %v", err)
	}

	shortCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := eng.ApplyUser(shortCtx, "alice"); err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		release()
		t.Fatalf("expected ApplyUser to abort on context deadline while lock is held (N9a), got err=%v", err)
	}

	// 2. N9c: StartBackgroundWorker coalesces rapid SavePackageLimits + SaveDefaultLimits while lock is held!
	workerCtx, stopWorker := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	eng.StartBackgroundWorker(workerCtx, &wg)

	lim := config.DefaultLimits()
	lim.CPUQuota = 250
	for i := 0; i < 5; i++ {
		r := eng.HandleAdminRequest(context.Background(), 0, ipc.Request{
			Action:    ipc.ActionSavePackageLimits,
			Package:   "gold",
			SyncUsers: true,
			Limits:    &lim,
		})
		if !r.OK {
			release()
			stopWorker()
			t.Fatalf("SavePackageLimits #%d: %+v", i, r)
		}
	}
	lim.CPUQuota = 300
	rDef := eng.HandleAdminRequest(context.Background(), 0, ipc.Request{
		Action:    ipc.ActionSaveDefaultLimits,
		SyncUsers: true,
		Limits:    &lim,
	})
	if !rDef.OK {
		release()
		stopWorker()
		t.Fatalf("SaveDefaultLimits: %+v", rDef)
	}

	if inProg, _ := eng.SyncStatus(); !inProg {
		release()
		stopWorker()
		t.Fatal("expected SyncStatus() == true while background job is queued behind applySem (N9c)")
	}

	// Release semaphore so the coalesced background worker drains cleanly
	release()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		inProg, _ := eng.SyncStatus()
		if !inProg {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if inProg, lbl := eng.SyncStatus(); inProg {
		stopWorker()
		t.Fatalf("expected background sync queue to finish draining, still running (%s)", lbl)
	}

	stopWorker()
	wg.Wait()
}
