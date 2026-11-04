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

func TestApplyUserSliceAndStats(t *testing.T) {
	tmp := t.TempDir()
	systemdDir := filepath.Join(tmp, "systemd")
	cgRoot := filepath.Join(tmp, "cgroup")

	// Simulate Cgroups v2 unified root
	if err := os.MkdirAll(cgRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "cgroup.controllers"), []byte("cpu memory io pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	uid := uint32(1005)
	runner := &fakeRunner{
		onRun: func(name string, args ...string) error {
			// Simulate systemd creating user-1005.slice directory upon `systemctl start user-1005.slice`
			if name == "systemctl" && len(args) == 2 && args[0] == "start" && args[1] == "user-1005.slice" {
				return os.MkdirAll(filepath.Join(cgRoot, "user.slice", "user-1005.slice"), 0o755)
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

	if err := mgr.ApplyUserSlice(context.Background(), uid, limits); err != nil {
		t.Fatalf("ApplyUserSlice: %v", err)
	}

	// Verify drop-in file contents
	raw, err := os.ReadFile(mgr.SliceDropInPath(uid))
	if err != nil {
		t.Fatalf("read drop-in: %v", err)
	}
	content := string(raw)
	for _, expected := range []string{"CPUQuota=150%", "MemoryHigh=1536M", "MemoryMax=2048M", "MemorySwapMax=0M", "TasksMax=100"} {
		if !strings.Contains(content, expected) {
			t.Errorf("drop-in missing %q:\n%s", expected, content)
		}
	}

	// Verify da-php.scope was created under user-1005.slice
	if st, err := os.Stat(mgr.PHPScopeDir(uid)); err != nil || !st.IsDir() {
		t.Fatalf("expected da-php.scope directory to exist, err=%v", err)
	}

	// Re-applying identical limits must NOT invoke daemon-reload again
	prevCalls := len(runner.calls)
	if err := mgr.ApplyUserSlice(context.Background(), uid, limits); err != nil {
		t.Fatalf("idempotent ApplyUserSlice: %v", err)
	}
	if len(runner.calls) != prevCalls {
		t.Fatalf("expected 0 extra systemctl calls on unchanged slice, got %v", runner.calls[prevCalls:])
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
