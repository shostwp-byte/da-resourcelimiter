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
	DropInFileName      = "50-da-limits.conf"
	PHPScopeName        = "da-php.scope"
	managedHeaderPrefix = "# Managed by DA-ResourceLimiter"
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
	return RenderDropInForAccount("", limits)
}

// RenderDropInForAccount builds the systemd slice configuration and records the owning username
// in a comment so orphan cleanup can still identify destroyed DirectAdmin users after /etc/passwd removal (R5).
func RenderDropInForAccount(username string, limits config.ResourceLimits) string {
	var b strings.Builder
	b.WriteString(managedHeaderPrefix + " (do not edit manually)\n")
	if username != "" {
		fmt.Fprintf(&b, "# DA-User=%s\n", username)
	}
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
	return m.StageUserSliceForAccount("", uid, limits)
}

// StageUserSliceForAccount writes or removes 50-da-limits.conf using a unique temporary file (R7)
// and embeds optional username metadata for post-deletion orphan cleanup (R5).
func (m *Manager) StageUserSliceForAccount(username string, uid uint32, limits config.ResourceLimits) (changed bool, err error) {
	if !limits.Enabled {
		return m.removeDropInFile(uid)
	}
	if err := limits.Validate(); err != nil {
		return false, err
	}

	desired := []byte(RenderDropInForAccount(username, limits))
	dropInDir := m.SliceDropInDir(uid)
	dropInPath := m.SliceDropInPath(uid)

	if existing, err := os.ReadFile(dropInPath); err == nil && bytes.Equal(existing, desired) {
		return false, nil
	}

	if err := os.MkdirAll(dropInDir, 0o755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", dropInDir, err)
	}

	tmp, err := os.CreateTemp(dropInDir, ".50-da-limits-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create temp in %s: %w", dropInDir, err)
	}
	tmpPath := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(desired); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("sync %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, dropInPath); err != nil {
		return false, fmt.Errorf("rename %s: %w", dropInPath, err)
	}
	cleanupTmp = false
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
	return m.ApplyUserSliceForAccount(ctx, "", uid, limits)
}

// ApplyUserSliceForAccount writes 50-da-limits.conf with owner metadata, reloads systemd if needed, and ensures da-php.scope.
func (m *Manager) ApplyUserSliceForAccount(ctx context.Context, username string, uid uint32, limits config.ResourceLimits) error {
	changed, err := m.StageUserSliceForAccount(username, uid, limits)
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

// PruneOrphanSlices scans SystemdSystemDir for managed user-<UID>.slice.d/50-da-limits.conf files
// whose UID is no longer present in validUIDs (or whose embedded DA-User matches destroyedUser),
// removes them, and triggers a single systemctl daemon-reload if any drop-in was deleted (R5, N2).
func (m *Manager) PruneOrphanSlices(ctx context.Context, validUIDs map[uint32]struct{}, destroyedUser string) (int, error) {
	return m.PruneOrphanSlicesWithPolicy(ctx, validUIDs, destroyedUser, nil)
}

// PruneOrphanSlicesWithPolicy enforces N2 anti-regression guards during periodic untargeted sweeps:
//  1. Never prunes when validUIDs is empty while managed drop-ins exist on disk.
//  2. Trips a mass-deletion circuit breaker if >= 2 and > 20% of managed drop-ins disappear at once.
//  3. Requires confirmOrphan(uid) (when provided) to verify absence from /etc/passwd or >= 2 reloads.
func (m *Manager) PruneOrphanSlicesWithPolicy(
	ctx context.Context,
	validUIDs map[uint32]struct{},
	destroyedUser string,
	confirmOrphan func(uid uint32) bool,
) (int, error) {
	entries, err := os.ReadDir(m.SystemdSystemDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}

	type managedSlice struct {
		uid  uint32
		text string
	}
	var managed []managedSlice

	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasPrefix(name, "user-") || !strings.HasSuffix(name, ".slice.d") {
			continue
		}
		uidStr := strings.TrimSuffix(strings.TrimPrefix(name, "user-"), ".slice.d")
		uid64, parseErr := strconv.ParseUint(uidStr, 10, 32)
		if parseErr != nil {
			continue
		}
		uid := uint32(uid64)

		dropInPath := m.SliceDropInPath(uid)
		raw, readErr := os.ReadFile(dropInPath)
		if readErr != nil {
			continue
		}
		text := string(raw)
		if !strings.HasPrefix(text, managedHeaderPrefix) {
			continue
		}
		managed = append(managed, managedSlice{uid: uid, text: text})
	}

	if len(managed) == 0 {
		return 0, nil
	}

	var toRemove []uint32
	if destroyedUser != "" {
		marker := "# DA-User=" + destroyedUser + "\n"
		for _, item := range managed {
			_, stillActive := validUIDs[item.uid]
			matchesDestroyed := strings.Contains(item.text, marker)
			if matchesDestroyed {
				toRemove = append(toRemove, item.uid)
				continue
			}
			if !stillActive && (confirmOrphan == nil || confirmOrphan(item.uid)) {
				toRemove = append(toRemove, item.uid)
			}
		}
	} else {
		if len(validUIDs) == 0 {
			return 0, fmt.Errorf("aborted orphan slice prune: active UID registry is empty while %d managed slice drop-in(s) exist", len(managed))
		}
		var missing []uint32
		for _, item := range managed {
			if _, stillActive := validUIDs[item.uid]; !stillActive {
				missing = append(missing, item.uid)
			}
		}
		if len(missing) >= 2 && len(missing)*5 > len(managed) {
			return 0, fmt.Errorf("aborted orphan slice prune: %d/%d (>20%%) managed slice drop-ins missing from registry", len(missing), len(managed))
		}
		for _, uid := range missing {
			if confirmOrphan == nil || confirmOrphan(uid) {
				toRemove = append(toRemove, uid)
			}
		}
	}

	removed := 0
	for _, uid := range toRemove {
		if changed, _ := m.removeDropInFile(uid); changed {
			m.mu.Lock()
			delete(m.cpuSamples, uid)
			m.mu.Unlock()
			removed++
		}
	}

	if removed > 0 {
		if err := m.ReloadSystemd(ctx); err != nil {
			return removed, err
		}
	}
	return removed, nil
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
