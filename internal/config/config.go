package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/shostwp-byte/da-resourcelimiter/internal/version"
)

var safeIdentifierRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// ResourceLimits holds per-package or per-user OS, PHP-FPM, and MariaDB limits.
type ResourceLimits struct {
	Enabled        bool   `json:"enabled"`
	CustomOverride bool   `json:"custom_override"`
	Package        string `json:"package,omitempty"`

	// OS Layer (Cgroups v2 / systemd slice)
	CPUQuota   int `json:"cpu_quota"`   // Percentage: 100 = 1 vCore, 150 = 1.5 vCores
	CPUWeight  int `json:"cpu_weight"`  // 1..10000 (default 100)
	MemHighMB  int `json:"mem_high_mb"` // Throttle threshold in MB
	MemMaxMB   int `json:"mem_max_mb"`  // Hard OOM limit in MB
	IOWeight   int `json:"io_weight"`   // 1..10000 (default 100)
	TasksMax   int `json:"tasks_max"`   // Max processes + threads (fork bomb guard)

	// PHP-FPM / LSPHP Layer
	PHPMaxChildren int `json:"php_max_children"`
	PHPMemLimitMB  int `json:"php_mem_limit_mb"`

	// MariaDB / MySQL Layer
	MySQLMaxConnections     int  `json:"mysql_max_connections"`
	MySQLMaxActiveQueries   int  `json:"mysql_max_active_queries"`
	MySQLMaxMemMB           int  `json:"mysql_max_mem_mb"`
	MySQLMaxStatementTime   int  `json:"mysql_max_statement_time_sec"`
	MySQLPenaltyEnabled     bool `json:"mysql_penalty_enabled"`
	MySQLPenaltyThreshold   int  `json:"mysql_penalty_threshold"`
	MySQLPenaltyWindowSec   int  `json:"mysql_penalty_window_sec"`
	MySQLPenaltyDurationSec int  `json:"mysql_penalty_duration_sec"`
	MySQLPenaltyConn        int  `json:"mysql_penalty_conn"`
	MySQLPenaltyTimeSec     int  `json:"mysql_penalty_time_sec"`
}

// DefaultLimits returns conservative production-safe defaults matching the specification.
func DefaultLimits() ResourceLimits {
	return ResourceLimits{
		Enabled:                 true,
		CustomOverride:          false,
		CPUQuota:                150,
		CPUWeight:               100,
		MemHighMB:               1536,
		MemMaxMB:                2048,
		IOWeight:                100,
		TasksMax:                100,
		PHPMaxChildren:          12,
		PHPMemLimitMB:           256,
		MySQLMaxConnections:     20,
		MySQLMaxActiveQueries:   4,
		MySQLMaxMemMB:           256,
		MySQLMaxStatementTime:   10,
		MySQLPenaltyEnabled:     true,
		MySQLPenaltyThreshold:   5,
		MySQLPenaltyWindowSec:   60,
		MySQLPenaltyDurationSec: 300,
		MySQLPenaltyConn:        2,
		MySQLPenaltyTimeSec:     2,
	}
}

// Validate checks bounds and cross-field constraints before applying limits to Kernel or MariaDB.
func (r ResourceLimits) Validate() error {
	if r.CPUQuota < 10 || r.CPUQuota > 12800 {
		return fmt.Errorf("CPU_QUOTA must be between 10 and 12800 (got %d)", r.CPUQuota)
	}
	if r.CPUWeight < 1 || r.CPUWeight > 10000 {
		return fmt.Errorf("CPU_WEIGHT must be between 1 and 10000 (got %d)", r.CPUWeight)
	}
	if r.MemMaxMB < 64 {
		return fmt.Errorf("MEM_MAX_MB must be at least 64 MB (got %d)", r.MemMaxMB)
	}
	if r.MemHighMB < 32 || r.MemHighMB > r.MemMaxMB {
		return fmt.Errorf("MEM_HIGH_MB (%d) must be >= 32 and <= MEM_MAX_MB (%d)", r.MemHighMB, r.MemMaxMB)
	}
	if r.IOWeight < 1 || r.IOWeight > 10000 {
		return fmt.Errorf("IO_WEIGHT must be between 1 and 10000 (got %d)", r.IOWeight)
	}
	if r.TasksMax < 10 || r.TasksMax > 100000 {
		return fmt.Errorf("TASKS_MAX must be between 10 and 100000 (got %d)", r.TasksMax)
	}
	if r.PHPMaxChildren < 1 || r.PHPMaxChildren > 2000 {
		return fmt.Errorf("PHP_MAX_CHILDREN must be between 1 and 2000 (got %d)", r.PHPMaxChildren)
	}
	if r.PHPMemLimitMB < 16 || r.PHPMemLimitMB > 65536 {
		return fmt.Errorf("PHP_MEM_LIMIT_MB must be between 16 and 65536 (got %d)", r.PHPMemLimitMB)
	}
	if r.MySQLMaxConnections < 1 || r.MySQLMaxConnections > 5000 {
		return fmt.Errorf("MYSQL_MAX_CONNECTIONS must be between 1 and 5000 (got %d)", r.MySQLMaxConnections)
	}
	if r.MySQLMaxActiveQueries < 1 || r.MySQLMaxActiveQueries > 1000 {
		return fmt.Errorf("MYSQL_MAX_ACTIVE_QUERIES must be between 1 and 1000 (got %d)", r.MySQLMaxActiveQueries)
	}
	if r.MySQLMaxMemMB < 16 || r.MySQLMaxMemMB > 65536 {
		return fmt.Errorf("MYSQL_MAX_MEM_MB must be between 16 and 65536 (got %d)", r.MySQLMaxMemMB)
	}
	if r.MySQLMaxStatementTime < 1 || r.MySQLMaxStatementTime > 86400 {
		return fmt.Errorf("MYSQL_MAX_STATEMENT_TIME_SEC must be between 1 and 86400 (got %d)", r.MySQLMaxStatementTime)
	}
	return nil
}

// UpdaterConfig stores GitHub Releases configuration (persisted at /etc/da-resourced/updater.conf with 0600).
type UpdaterConfig struct {
	GitHubRepo      string `json:"github_repo"`
	GitHubToken     string `json:"-"` // Never serialized raw in public JSON responses
	UpdateChannel   string `json:"update_channel"`
	BackupRetention int    `json:"backup_retention"`
}

func DefaultUpdaterConfig() UpdaterConfig {
	return UpdaterConfig{
		GitHubRepo:      version.DefaultGitHubRepo,
		GitHubToken:     "",
		UpdateChannel:   "stable",
		BackupRetention: 5,
	}
}

// MaskedToken returns a redacted representation suitable for Admin UI display.
func (u UpdaterConfig) MaskedToken() string {
	t := strings.TrimSpace(u.GitHubToken)
	if t == "" {
		return ""
	}
	if len(t) <= 8 {
		return "********"
	}
	return t[:4] + "****..." + t[len(t)-4:]
}

func ValidateIdentifier(name string) error {
	if !safeIdentifierRe.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid identifier %q", name)
	}
	return nil
}

// ParseKeyValueFile parses a DirectAdmin-style KEY=VALUE configuration file.
func ParseKeyValueFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kv := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"'`)
		kv[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return kv, nil
}

// ApplyKV overlays key-value pairs onto an existing ResourceLimits struct.
func ApplyKV(base ResourceLimits, kv map[string]string) ResourceLimits {
	out := base
	if v, ok := kv["ENABLED"]; ok {
		out.Enabled = parseBool(v, out.Enabled)
	}
	if v, ok := kv["CUSTOM_OVERRIDE"]; ok {
		out.CustomOverride = parseBool(v, out.CustomOverride)
	}
	if v, ok := kv["PACKAGE"]; ok {
		out.Package = v
	}
	if v, ok := kv["CPU_QUOTA"]; ok {
		out.CPUQuota = parseInt(v, out.CPUQuota)
	}
	if v, ok := kv["CPU_WEIGHT"]; ok {
		out.CPUWeight = parseInt(v, out.CPUWeight)
	}
	if v, ok := kv["MEM_HIGH_MB"]; ok {
		out.MemHighMB = parseInt(v, out.MemHighMB)
	}
	if v, ok := kv["MEM_MAX_MB"]; ok {
		out.MemMaxMB = parseInt(v, out.MemMaxMB)
	}
	if v, ok := kv["IO_WEIGHT"]; ok {
		out.IOWeight = parseInt(v, out.IOWeight)
	}
	if v, ok := kv["TASKS_MAX"]; ok {
		out.TasksMax = parseInt(v, out.TasksMax)
	}
	if v, ok := kv["PHP_MAX_CHILDREN"]; ok {
		out.PHPMaxChildren = parseInt(v, out.PHPMaxChildren)
	}
	if v, ok := kv["PHP_MEM_LIMIT_MB"]; ok {
		out.PHPMemLimitMB = parseInt(v, out.PHPMemLimitMB)
	}
	if v, ok := kv["MYSQL_MAX_CONNECTIONS"]; ok {
		out.MySQLMaxConnections = parseInt(v, out.MySQLMaxConnections)
	}
	if v, ok := kv["MYSQL_MAX_ACTIVE_QUERIES"]; ok {
		out.MySQLMaxActiveQueries = parseInt(v, out.MySQLMaxActiveQueries)
	}
	if v, ok := kv["MYSQL_MAX_MEM_MB"]; ok {
		out.MySQLMaxMemMB = parseInt(v, out.MySQLMaxMemMB)
	}
	if v, ok := kv["MYSQL_MAX_STATEMENT_TIME_SEC"]; ok {
		out.MySQLMaxStatementTime = parseInt(v, out.MySQLMaxStatementTime)
	}
	if v, ok := kv["MYSQL_PENALTY_ENABLED"]; ok {
		out.MySQLPenaltyEnabled = parseBool(v, out.MySQLPenaltyEnabled)
	}
	if v, ok := kv["MYSQL_PENALTY_THRESHOLD"]; ok {
		out.MySQLPenaltyThreshold = parseInt(v, out.MySQLPenaltyThreshold)
	}
	if v, ok := kv["MYSQL_PENALTY_WINDOW_SEC"]; ok {
		out.MySQLPenaltyWindowSec = parseInt(v, out.MySQLPenaltyWindowSec)
	}
	if v, ok := kv["MYSQL_PENALTY_DURATION_SEC"]; ok {
		out.MySQLPenaltyDurationSec = parseInt(v, out.MySQLPenaltyDurationSec)
	}
	if v, ok := kv["MYSQL_PENALTY_CONN"]; ok {
		out.MySQLPenaltyConn = parseInt(v, out.MySQLPenaltyConn)
	}
	if v, ok := kv["MYSQL_PENALTY_TIME_SEC"]; ok {
		out.MySQLPenaltyTimeSec = parseInt(v, out.MySQLPenaltyTimeSec)
	}
	return out
}

// FormatLimits renders ResourceLimits in DirectAdmin Key=Value format.
func FormatLimits(r ResourceLimits) string {
	var b strings.Builder
	b.WriteString("# Generated by DA-ResourceLimiter\n")
	fmt.Fprintf(&b, "ENABLED=%s\n", formatBool(r.Enabled))
	fmt.Fprintf(&b, "CUSTOM_OVERRIDE=%s\n", formatBool(r.CustomOverride))
	if r.Package != "" {
		fmt.Fprintf(&b, "PACKAGE=%s\n", r.Package)
	}
	b.WriteString("\n# OS Limits (Cgroups v2)\n")
	fmt.Fprintf(&b, "CPU_QUOTA=%d\n", r.CPUQuota)
	fmt.Fprintf(&b, "CPU_WEIGHT=%d\n", r.CPUWeight)
	fmt.Fprintf(&b, "MEM_HIGH_MB=%d\n", r.MemHighMB)
	fmt.Fprintf(&b, "MEM_MAX_MB=%d\n", r.MemMaxMB)
	fmt.Fprintf(&b, "IO_WEIGHT=%d\n", r.IOWeight)
	fmt.Fprintf(&b, "TASKS_MAX=%d\n", r.TasksMax)
	b.WriteString("\n# PHP-FPM / LSPHP Limits\n")
	fmt.Fprintf(&b, "PHP_MAX_CHILDREN=%d\n", r.PHPMaxChildren)
	fmt.Fprintf(&b, "PHP_MEM_LIMIT_MB=%d\n", r.PHPMemLimitMB)
	b.WriteString("\n# MariaDB / MySQL Limits\n")
	fmt.Fprintf(&b, "MYSQL_MAX_CONNECTIONS=%d\n", r.MySQLMaxConnections)
	fmt.Fprintf(&b, "MYSQL_MAX_ACTIVE_QUERIES=%d\n", r.MySQLMaxActiveQueries)
	fmt.Fprintf(&b, "MYSQL_MAX_MEM_MB=%d\n", r.MySQLMaxMemMB)
	fmt.Fprintf(&b, "MYSQL_MAX_STATEMENT_TIME_SEC=%d\n", r.MySQLMaxStatementTime)
	fmt.Fprintf(&b, "MYSQL_PENALTY_ENABLED=%s\n", formatBool(r.MySQLPenaltyEnabled))
	fmt.Fprintf(&b, "MYSQL_PENALTY_THRESHOLD=%d\n", r.MySQLPenaltyThreshold)
	fmt.Fprintf(&b, "MYSQL_PENALTY_WINDOW_SEC=%d\n", r.MySQLPenaltyWindowSec)
	fmt.Fprintf(&b, "MYSQL_PENALTY_DURATION_SEC=%d\n", r.MySQLPenaltyDurationSec)
	fmt.Fprintf(&b, "MYSQL_PENALTY_CONN=%d\n", r.MySQLPenaltyConn)
	fmt.Fprintf(&b, "MYSQL_PENALTY_TIME_SEC=%d\n", r.MySQLPenaltyTimeSec)
	return b.String()
}

// Store manages reading/writing default, package, and user override configurations.
type Store struct {
	DataDir        string
	UpdaterCfgPath string
}

func NewStore(dataDir, updaterCfgPath string) *Store {
	return &Store{
		DataDir:        dataDir,
		UpdaterCfgPath: updaterCfgPath,
	}
}

func (s *Store) DefaultConfPath() string {
	return filepath.Join(s.DataDir, "default.conf")
}

func (s *Store) PackageConfPath(pkg string) (string, error) {
	if err := ValidateIdentifier(pkg); err != nil {
		return "", err
	}
	return filepath.Join(s.DataDir, "packages", pkg+".conf"), nil
}

func (s *Store) UserConfPath(username string) (string, error) {
	if err := ValidateIdentifier(username); err != nil {
		return "", err
	}
	return filepath.Join(s.DataDir, "users", username+".conf"), nil
}

// ResolveUserLimits resolves effective limits using Default -> Package -> User Override hierarchy.
func (s *Store) ResolveUserLimits(username, packageName string) (ResourceLimits, error) {
	limits := DefaultLimits()

	if kv, err := ParseKeyValueFile(s.DefaultConfPath()); err == nil {
		limits = ApplyKV(limits, kv)
	} else if !errors.Is(err, os.ErrNotExist) {
		return limits, fmt.Errorf("read default.conf: %w", err)
	}

	if packageName != "" {
		if pkgPath, err := s.PackageConfPath(packageName); err == nil {
			if kv, err := ParseKeyValueFile(pkgPath); err == nil {
				limits = ApplyKV(limits, kv)
				limits.Package = packageName
			} else if !errors.Is(err, os.ErrNotExist) {
				return limits, fmt.Errorf("read package %s: %w", packageName, err)
			}
		}
	}

	userPath, err := s.UserConfPath(username)
	if err != nil {
		return limits, err
	}
	if kv, err := ParseKeyValueFile(userPath); err == nil {
		limits = ApplyKV(limits, kv)
	} else if !errors.Is(err, os.ErrNotExist) {
		return limits, fmt.Errorf("read user %s: %w", username, err)
	}

	return limits, nil
}

func (s *Store) SaveDefaultLimits(r ResourceLimits) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return atomicWriteFile(s.DefaultConfPath(), []byte(FormatLimits(r)), 0o640)
}

func (s *Store) SavePackageLimits(pkg string, r ResourceLimits) error {
	if err := r.Validate(); err != nil {
		return err
	}
	p, err := s.PackageConfPath(pkg)
	if err != nil {
		return err
	}
	return atomicWriteFile(p, []byte(FormatLimits(r)), 0o640)
}

func (s *Store) SaveUserLimits(username string, r ResourceLimits) error {
	if err := r.Validate(); err != nil {
		return err
	}
	p, err := s.UserConfPath(username)
	if err != nil {
		return err
	}
	return atomicWriteFile(p, []byte(FormatLimits(r)), 0o640)
}

func (s *Store) DeleteUserLimits(username string) error {
	p, err := s.UserConfPath(username)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// MigrateDefaultKeys appends newly added config keys to an existing default.conf without overwriting user edits.
func (s *Store) MigrateDefaultKeys() error {
	path := s.DefaultConfPath()
	existingKV, err := ParseKeyValueFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s.SaveDefaultLimits(DefaultLimits())
	}
	if err != nil {
		return err
	}

	def := DefaultLimits()
	canonicalLines := strings.Split(FormatLimits(def), "\n")
	var missing []string
	for _, line := range canonicalLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		idx := strings.IndexByte(trimmed, '=')
		if idx <= 0 {
			continue
		}
		key := trimmed[:idx]
		if _, exists := existingKV[key]; !exists {
			missing = append(missing, trimmed)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := strings.TrimRight(string(raw), "\n") + "\n\n# Migrated keys\n" + strings.Join(missing, "\n") + "\n"
	return atomicWriteFile(path, []byte(content), 0o640)
}

func (s *Store) LoadUpdaterConfig() (UpdaterConfig, error) {
	cfg := DefaultUpdaterConfig()
	if s.UpdaterCfgPath == "" {
		return cfg, nil
	}
	kv, err := ParseKeyValueFile(s.UpdaterCfgPath)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if v := strings.TrimSpace(kv["GITHUB_REPO"]); v != "" {
		cfg.GitHubRepo = v
	}
	if v, ok := kv["GITHUB_TOKEN"]; ok {
		cfg.GitHubToken = strings.TrimSpace(v)
	}
	if v := strings.ToLower(strings.TrimSpace(kv["UPDATE_CHANNEL"])); v == "stable" || v == "beta" {
		cfg.UpdateChannel = v
	}
	if v, ok := kv["BACKUP_RETENTION"]; ok {
		if n := parseInt(v, cfg.BackupRetention); n >= 1 && n <= 30 {
			cfg.BackupRetention = n
		}
	}
	return cfg, nil
}

func (s *Store) SaveUpdaterConfig(cfg UpdaterConfig) error {
	if s.UpdaterCfgPath == "" {
		return errors.New("updater config path not configured")
	}
	repo := strings.TrimSpace(cfg.GitHubRepo)
	if !strings.Contains(repo, "/") || strings.Contains(repo, "..") || strings.ContainsAny(repo, " \t\r\n") {
		return fmt.Errorf("invalid GitHub repository format %q (expected owner/repo)", repo)
	}
	channel := strings.ToLower(strings.TrimSpace(cfg.UpdateChannel))
	if channel != "stable" && channel != "beta" {
		channel = "stable"
	}
	retention := cfg.BackupRetention
	if retention < 1 || retention > 30 {
		retention = 5
	}

	var b strings.Builder
	b.WriteString("# DA-ResourceLimiter GitHub Updater Configuration (0600 root:root)\n")
	fmt.Fprintf(&b, "GITHUB_REPO=%s\n", repo)
	fmt.Fprintf(&b, "GITHUB_TOKEN=%s\n", strings.TrimSpace(cfg.GitHubToken))
	fmt.Fprintf(&b, "UPDATE_CHANNEL=%s\n", channel)
	fmt.Fprintf(&b, "BACKUP_RETENTION=%d\n", retention)

	return atomicWriteFile(s.UpdaterCfgPath, []byte(b.String()), 0o600)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func parseInt(s string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return n
}

func parseBool(s string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true", "1", "on":
		return true
	case "no", "false", "0", "off":
		return false
	default:
		return fallback
	}
}

func formatBool(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
