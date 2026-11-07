package cgroup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
)

type fakeRunner struct {
	calls [][]string
	onRun func(name string, args ...string) error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) error {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	if f.onRun != nil {
		return f.onRun(name, args...)
	}
	return nil
}

func TestApplyUserSliceStatsAndOrphanPrune(t *testing.T) {
	tmp := t.TempDir()
	systemdDir := filepath.Join(tmp, "systemd")
	cgRoot := filepath.Join(tmp, "cgroup")

	if err := os.MkdirAll(cgRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "cgroup.controllers"), []byte("cpu memory io pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	uid := uint32(1005)
	runner := &fakeRunner{
		onRun: func(name string, args ...string) error {
			if name == "systemctl" && len(args) == 2 && args[0] == "start" && strings.HasPrefix(args[1], "user-") {
				return os.MkdirAll(filepath.Join(cgRoot, "user.slice", args[1]), 0o755)
			}
			return nil
		},
	}

	mgr := NewManager(systemdDir, cgRoot, runner)
	if err := mgr.VerifyUnifiedHierarchy(); err != nil {
		t.Fatalf("VerifyUnifiedHierarchy: %v", err)
	}

	limits := config.DefaultLimits()
	limits.CPUQuota = 150
	limits.MemHighMB = 1536
	limits.MemMaxMB = 2048
	limits.TasksMax = 100

	if err := mgr.ApplyUserSliceForAccount(context.Background(), "vinahost", uid, limits); err != nil {
		t.Fatalf("ApplyUserSliceForAccount: %v", err)
	}

	raw, err := os.ReadFile(mgr.SliceDropInPath(uid))
	if err != nil {
		t.Fatalf("read drop-in: %v", err)
	}
	content := string(raw)
	for _, expected := range []string{"# DA-User=vinahost", "CPUQuota=150%", "MemoryHigh=1536M", "MemoryMax=2048M", "MemorySwapMax=0M", "TasksMax=100"} {
		if !strings.Contains(content, expected) {
			t.Errorf("drop-in missing %q:\n%s", expected, content)
		}
	}

	if st, err := os.Stat(mgr.PHPScopeDir(uid)); err != nil || !st.IsDir() {
		t.Fatalf("expected da-php.scope directory to exist, err=%v", err)
	}

	// Re-applying identical limits must NOT invoke daemon-reload again
	prevCalls := len(runner.calls)
	if err := mgr.ApplyUserSliceForAccount(context.Background(), "vinahost", uid, limits); err != nil {
		t.Fatalf("idempotent ApplyUserSliceForAccount: %v", err)
	}
	if len(runner.calls) != prevCalls {
		t.Fatalf("expected 0 extra systemctl calls on unchanged slice, got %v", runner.calls[prevCalls:])
	}

	// Stage a second user (uid 1009, "deleteduser"), then prune orphans with only uid 1005 active (R5)
	if _, err := mgr.StageUserSliceForAccount("deleteduser", 1009, limits); err != nil {
		t.Fatalf("StageUserSliceForAccount 1009: %v", err)
	}
	pruned, err := mgr.PruneOrphanSlices(context.Background(), map[uint32]struct{}{1005: {}}, "deleteduser")
	if err != nil {
		t.Fatalf("PruneOrphanSlices: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("expected 1 orphaned slice pruned, got %d", pruned)
	}
	if _, err := os.Stat(mgr.SliceDropInPath(1009)); !os.IsNotExist(err) {
		t.Fatalf("expected orphaned user-1009 drop-in to be removed, err=%v", err)
	}
	if _, err := os.Stat(mgr.SliceDropInPath(1005)); err != nil {
		t.Fatalf("active user-1005 drop-in must remain intact: %v", err)
	}

	// Simulate kernel cgroup v2 stat files and read telemetry
	sliceDir := mgr.SliceCgroupDir(uid)
	_ = os.WriteFile(filepath.Join(sliceDir, "memory.current"), []byte("536870912\n"), 0o644) // 512 MB
	_ = os.WriteFile(filepath.Join(sliceDir, "pids.current"), []byte("14\n"), 0o644)
	_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("low 0\nhigh 7\nmax 2\noom 1\noom_kill 3\n"), 0o644)
	_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("usage_usec 1000000\n"), 0o644)

	firstStats, err := mgr.ReadSliceStats(uid)
	if err != nil {
		t.Fatalf("ReadSliceStats #1: %v", err)
	}
	if firstStats.MemoryCurrentMB != 512 || firstStats.ActiveProcesses != 14 || firstStats.MemoryHighEvents != 7 || firstStats.OOMKillEvents != 3 {
		t.Fatalf("unexpected slice stats: %+v", firstStats)
	}

	time.Sleep(20 * time.Millisecond)
	_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("usage_usec 1010000\n"), 0o644)
	secondStats, err := mgr.ReadSliceStats(uid)
	if err != nil {
		t.Fatalf("ReadSliceStats #2: %v", err)
	}
	if secondStats.CPUPercent <= 0 {
		t.Fatalf("expected positive CPUPercent delta, got %f", secondStats.CPUPercent)
	}
}

func TestPruneOrphanSlicesCircuitBreakerAndConfirmationPolicy(t *testing.T) {
	tmp := t.TempDir()
	systemdDir := filepath.Join(tmp, "systemd")
	cgRoot := filepath.Join(tmp, "cgroup")
	mgr := NewManager(systemdDir, cgRoot, &fakeRunner{})

	lim := config.DefaultLimits()
	for idx, uid := range []uint32{1001, 1002, 1003, 1004, 1005, 1006} {
		user := "user" + string(rune('a'+idx))
		if _, err := mgr.StageUserSliceForAccount(user, uid, lim); err != nil {
			t.Fatalf("StageUserSliceForAccount %d: %v", uid, err)
		}
	}

	// 1. N2: Empty validUIDs map when managed drop-ins exist MUST abort with error without deleting anything!
	prunedEmpty, err := mgr.PruneOrphanSlicesWithPolicy(context.Background(), map[uint32]struct{}{}, "", nil)
	if err == nil || prunedEmpty != 0 {
		t.Fatalf("expected empty validUIDs guard to abort with pruned=0, got pruned=%d err=%v", prunedEmpty, err)
	}
	if _, err := os.Stat(mgr.SliceDropInPath(1001)); err != nil {
		t.Fatal("slice 1001 must remain untouched when validUIDs is empty")
	}

	// 2. N2: Mass-deletion circuit breaker (>20% missing: 2 out of 6 = 33% > 20%) MUST abort untargeted sweep!
	partialValid := map[uint32]struct{}{1001: {}, 1002: {}, 1003: {}, 1004: {}}
	prunedMass, err := mgr.PruneOrphanSlicesWithPolicy(context.Background(), partialValid, "", nil)
	if err == nil || prunedMass != 0 {
		t.Fatalf("expected >20%% circuit breaker to abort mass deletion, got pruned=%d err=%v", prunedMass, err)
	}
	if _, err := os.Stat(mgr.SliceDropInPath(1005)); err != nil {
		t.Fatal("slice 1005 must survive mass-deletion circuit breaker")
	}

	// 3. N2: Single missing UID (1 out of 6 = 16.6% <= 20%) respects confirmOrphan callback!
	fiveValid := map[uint32]struct{}{1001: {}, 1002: {}, 1003: {}, 1004: {}, 1005: {}}
	prunedUnconfirmed, err := mgr.PruneOrphanSlicesWithPolicy(context.Background(), fiveValid, "", func(_ uint32) bool {
		return false
	})
	if err != nil || prunedUnconfirmed != 0 {
		t.Fatalf("expected unconfirmed orphan to be retained, got pruned=%d err=%v", prunedUnconfirmed, err)
	}
	if _, err := os.Stat(mgr.SliceDropInPath(1006)); err != nil {
		t.Fatal("unconfirmed orphan 1006 must remain on disk")
	}

	prunedConfirmed, err := mgr.PruneOrphanSlicesWithPolicy(context.Background(), fiveValid, "", func(uid uint32) bool {
		return uid == 1006
	})
	if err != nil || prunedConfirmed != 1 {
		t.Fatalf("expected confirmed orphan 1006 to be pruned, got pruned=%d err=%v", prunedConfirmed, err)
	}
	if _, err := os.Stat(mgr.SliceDropInPath(1006)); !os.IsNotExist(err) {
		t.Fatalf("expected confirmed orphan 1006 to be removed, err=%v", err)
	}
}
