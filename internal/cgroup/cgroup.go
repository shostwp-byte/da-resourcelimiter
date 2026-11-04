package cgroup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
)

const (
	DropInFileName = "50-da-limits.conf"
	PHPScopeName   = "da-php.scope"
)

// CommandRunner abstracts systemd CLI execution so slice operations are deterministic in tests.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SliceStats holds live Cgroups v2 telemetry for a single user-<UID>.slice.
type SliceStats struct {
	CPUPercent       float64
	MemoryCurrentMB  float64
	ActiveProcesses  int
	MemoryHighEvents uint64
	OOMKillEvents    uint64
}

type cpuSample struct {
	usageUsec uint64
	takenAt   time.Time
}

// Manager controls systemd slice drop-in configs, PHP sub-scopes, and live Cgroups v2 metrics.
type Manager struct {
	SystemdSystemDir string // Default: /etc/systemd/system
	CgroupRoot       string // Default: /sys/fs/cgroup
	Runner           CommandRunner

	mu         sync.Mutex
	cpuSamples map[uint32]cpuSample
}

func NewManager(systemdDir, cgroupRoot string, runner CommandRunner) *Manager {
	if systemdDir == "" {
		systemdDir = "/etc/systemd/system"
	}
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	if runner == nil {
		runner = OSCommandRunner{}
	}
	return &Manager{
		SystemdSystemDir: systemdDir,
		CgroupRoot:       cgroupRoot,
		Runner:           runner,
		cpuSamples:       make(map[uint32]cpuSample),
	}
}

// VerifyUnifiedHierarchy confirms that Linux Cgroups v2 is mounted at CgroupRoot.
func (m *Manager) VerifyUnifiedHierarchy() error {
	controllersPath := filepath.Join(m.CgroupRoot, "cgroup.controllers")
	if _, err := os.Stat(controllersPath); err != nil {
		return fmt.Errorf("cgroups v2 unified hierarchy not detected at %s (missing cgroup.controllers): %w", m.CgroupRoot, err)
	}
	return nil
}

func SliceUnitName(uid uint32) string {
	return fmt.Sprintf("user-%d.slice", uid)
}

func (m *Manager) SliceDropInDir(uid uint32) string {
	return filepath.Join(m.SystemdSystemDir, SliceUnitName(uid)+".d")
}

func (m *Manager) SliceDropInPath(uid uint32) string {
	return filepath.Join(m.SliceDropInDir(uid), DropInFileName)
}

func (m *Manager) SliceCgroupDir(uid uint32) string {
	return filepath.Join(m.CgroupRoot, "user.slice", SliceUnitName(uid))
}

func (m *Manager) PHPScopeDir(uid uint32) string {
	return filepath.Join(m.SliceCgroupDir(uid), PHPScopeName)
}

// RenderDropIn builds the systemd slice configuration matching Section 4.1.2 of the specification.
func RenderDropIn(limits config.ResourceLimits) string {
	var b strings.Builder
	b.WriteString("# Managed by DA-ResourceLimiter (do not edit manually)\n")
	b.WriteString("[Slice]\n")
	b.WriteString("CPUAccounting=yes\n")
	fmt.Fprintf(&b, "CPUWeight=%d\n", limits.CPUWeight)
	fmt.Fprintf(&b, "CPUQuota=%d%%\n", limits.CPUQuota)
	b.WriteString("MemoryAccounting=yes\n")
	fmt.Fprintf(&b, "MemoryHigh=%dM\n", limits.MemHighMB)
	fmt.Fprintf(&b, "MemoryMax=%dM\n", limits.MemMaxMB)
	b.WriteString("MemorySwapMax=0M\n")
	b.WriteString("IOAccounting=yes\n")
	fmt.Fprintf(&b, "IOWeight=%d\n", limits.IOWeight)
	b.WriteString("TasksAccounting=yes\n")
	fmt.Fprintf(&b, "TasksMax=%d\n", limits.TasksMax)
	return b.String()
}

// StageUserSlice writes or removes 50-da-limits.conf without calling daemon-reload yet (useful for batch apply).
func (m *Manager) StageUserSlice(uid uint32, limits config.ResourceLimits) (changed bool, err error) {
	if !limits.Enabled {
		return m.removeDropInFile(uid)
	}
	if err := limits.Validate(); err != nil {
		return false, err
	}

	desired := []byte(RenderDropIn(limits))
	dropInPath := m.SliceDropInPath(uid)

	if existing, err := os.ReadFile(dropInPath); err == nil && bytes.Equal(existing, desired) {
		return false, nil
	}

	if err := os.MkdirAll(m.SliceDropInDir(uid), 0o755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", m.SliceDropInDir(uid), err)
	}
	tmpPath := dropInPath + ".tmp"
	if err := os.WriteFile(tmpPath, desired, 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, dropInPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("rename %s: %w", dropInPath, err)
	}
	return true, nil
}

// ReloadSystemd triggers `systemctl daemon-reload`.
func (m *Manager) ReloadSystemd(ctx context.Context) error {
	return m.Runner.Run(ctx, "systemctl", "daemon-reload")
}

// EnsureSliceAndPHPScope starts user-<UID>.slice if not active and ensures da-php.scope exists.
func (m *Manager) EnsureSliceAndPHPScope(ctx context.Context, uid uint32) error {
	sliceDir := m.SliceCgroupDir(uid)
	if _, err := os.Stat(sliceDir); errors.Is(err, os.ErrNotExist) {
		if err := m.Runner.Run(ctx, "systemctl", "start", SliceUnitName(uid)); err != nil {
			return fmt.Errorf("start %s: %w", SliceUnitName(uid), err)
		}
	}

	// Only create da-php.scope if the parent slice cgroup exists on cgroup2fs
	if st, err := os.Stat(sliceDir); err == nil && st.IsDir() {
		if err := os.MkdirAll(m.PHPScopeDir(uid), 0o755); err != nil {
			return fmt.Errorf("create %s: %w", m.PHPScopeDir(uid), err)
		}
	}
	return nil
}

// ApplyUserSlice writes 50-da-limits.conf, reloads systemd if needed, starts the slice, and ensures da-php.scope.
func (m *Manager) ApplyUserSlice(ctx context.Context, uid uint32, limits config.ResourceLimits) error {
	changed, err := m.StageUserSlice(uid, limits)
	if err != nil {
		return err
	}
	if changed {
		if err := m.ReloadSystemd(ctx); err != nil {
			return err
		}
	}
	if !limits.Enabled {
		return nil
	}
	return m.EnsureSliceAndPHPScope(ctx, uid)
}

// RemoveUserSlice deletes user-<UID>.slice.d/50-da-limits.conf and reloads systemd.
func (m *Manager) RemoveUserSlice(ctx context.Context, uid uint32) error {
	changed, err := m.removeDropInFile(uid)
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.cpuSamples, uid)
	m.mu.Unlock()
	if changed {
		return m.ReloadSystemd(ctx)
	}
	return nil
}

func (m *Manager) removeDropInFile(uid uint32) (bool, error) {
	dropInPath := m.SliceDropInPath(uid)
	if err := os.Remove(dropInPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	// Clean up empty user-<UID>.slice.d directory if no other drop-ins exist
	_ = os.Remove(m.SliceDropInDir(uid))
	return true, nil
}

// ReadSliceStats reads live CPU, RAM, active process count, and OOM counters from Cgroups v2.
func (m *Manager) ReadSliceStats(uid uint32) (SliceStats, error) {
	var stats SliceStats
	sliceDir := m.SliceCgroupDir(uid)
	if _, err := os.Stat(sliceDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return stats, nil
		}
		return stats, err
	}

	if memBytes, err := readUint64File(filepath.Join(sliceDir, "memory.current")); err == nil {
		stats.MemoryCurrentMB = float64(memBytes) / (1024.0 * 1024.0)
	}

	if pidsCur, err := readUint64File(filepath.Join(sliceDir, "pids.current")); err == nil {
		stats.ActiveProcesses = int(pidsCur)
	}

	if evMap, err := readKeyUintFile(filepath.Join(sliceDir, "memory.events")); err == nil {
		stats.MemoryHighEvents = evMap["high"]
		stats.OOMKillEvents = evMap["oom_kill"]
	}

	if cpuMap, err := readKeyUintFile(filepath.Join(sliceDir, "cpu.stat")); err == nil {
		now := time.Now()
		usageUsec := cpuMap["usage_usec"]

		m.mu.Lock()
		prev, hasPrev := m.cpuSamples[uid]
		m.cpuSamples[uid] = cpuSample{usageUsec: usageUsec, takenAt: now}
		m.mu.Unlock()

		if hasPrev && usageUsec >= prev.usageUsec {
			wallUsec := float64(now.Sub(prev.takenAt).Microseconds())
			if wallUsec > 0 {
				stats.CPUPercent = (float64(usageUsec-prev.usageUsec) / wallUsec) * 100.0
			}
		}
	}

	return stats, nil
}

func readUint64File(path string) (uint64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(raw))
	if s == "max" || s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

func readKeyUintFile(path string) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]uint64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
			out[fields[0]] = v
		}
	}
	return out, scanner.Err()
}
