package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shostwp-byte/da-resourcelimiter/internal/cgroup"
	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
	"github.com/shostwp-byte/da-resourcelimiter/internal/ipc"
	"github.com/shostwp-byte/da-resourcelimiter/internal/logger"
)

type noopCmdRunner struct{}

func (noopCmdRunner) Run(_ context.Context, _ string, _ ...string) error { return nil }

func TestEngineUserIsolationAndPackageSyncRespectsCustomOverride(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "plugin_data")
	daRoot := filepath.Join(tmp, "da_data")
	daUsersDir := filepath.Join(daRoot, "users")
	passwdPath := filepath.Join(tmp, "passwd")
	systemdDir := filepath.Join(tmp, "systemd")
	cgRoot := filepath.Join(tmp, "cgroup")

	passwd := "" +
		"diradmin:x:995:995::/usr/local/directadmin:/bin/false\n" +
		"alice:x:1005:1005::/home/alice:/bin/bash\n" +
		"bob:x:1006:1006::/home/bob:/bin/bash\n"
	_ = os.WriteFile(passwdPath, []byte(passwd), 0o644)

	for _, u := range []string{"alice", "bob"} {
		_ = os.MkdirAll(filepath.Join(daUsersDir, u), 0o755)
		_ = os.WriteFile(filepath.Join(daUsersDir, u, "user.conf"), []byte("usertype=user\npackage=gold\n"), 0o600)
	}
	_ = os.MkdirAll(filepath.Join(daRoot, "admin"), 0o755)
	_ = os.WriteFile(filepath.Join(daRoot, "admin", "packages.list"), []byte("gold\nsilver\n"), 0o644)

	store := config.NewStore(dataDir, filepath.Join(tmp, "updater.conf"))
	reg := dausers.NewRegistry(daUsersDir, passwdPath)
	_ = reg.Reload()
	cgMgr := cgroup.NewManager(systemdDir, cgRoot, noopCmdRunner{})
	vlog := logger.NewViolationLogger(filepath.Join(tmp, "violations.jsonl"), 1024*1024, 2)

	eng := New(store, reg, cgMgr, nil, nil, vlog, daRoot, passwdPath)

	// Give bob a custom VIP override (400% CPU)
	vipLimits := config.DefaultLimits()
	vipLimits.CPUQuota = 400
	resp := eng.HandleAdminRequest(context.Background(), ipc.Request{
		Action:   ipc.ActionSaveUserLimits,
		Username: "bob",
		Limits:   &vipLimits,
	})
	if !resp.OK {
		t.Fatalf("SaveUserLimits bob failed: %+v", resp)
	}

	// Update package "gold" to 200% CPU with SyncUsers=true -> must sync alice (1 user), skipping bob's custom override!
	goldLimits := config.DefaultLimits()
	goldLimits.CPUQuota = 200
	pkgResp := eng.HandleAdminRequest(context.Background(), ipc.Request{
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

	// Verify SO_PEERCRED isolation: UID 1005 (alice) asks for Username="bob" -> MUST receive "alice" instead!
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
