package ipc

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
)

// Supported IPC Socket actions over /var/run/da-resourced.sock (Admin) and /var/run/da-resourced-user.sock (User).
const (
	ActionPing               = "ping"
	ActionGetRealtimeStats   = "get_realtime_stats"
	ActionGetUserStats       = "get_user_stats"
	ActionGetPackages        = "get_packages"
	ActionSaveDefaultLimits  = "save_default_limits"
	ActionSavePackageLimits  = "save_package_limits"
	ActionSaveUserLimits     = "save_user_limits"
	ActionResetUserLimits    = "reset_user_limits"
	ActionApplyUserLimits    = "apply_user_limits"
	ActionApplyPackageLimits = "apply_package_limits"
	ActionApplyDBUser        = "apply_db_user"
	ActionRemoveUser         = "remove_user"
	ActionUnblockPenalty     = "unblock_penalty"
	ActionGetLogs            = "get_logs"
	ActionGetUpdaterStatus   = "get_updater_status"
	ActionSaveUpdaterConfig  = "save_updater_config"
	ActionCheckUpdate        = "check_update"
	ActionTriggerUpdate      = "trigger_update"
	ActionRollbackUpdate     = "rollback_update"
)

// Default socket paths on DirectAdmin Linux hosts.
const (
	DefaultAdminSocketPath = "/var/run/da-resourced.sock"
	DefaultUserSocketPath  = "/var/run/da-resourced-user.sock"
)

// Request is the JSON command envelope sent by DirectAdmin CGI/Hooks/CLI to da-resourced.
type Request struct {
	Action        string                 `json:"action"`
	Username      string                 `json:"username,omitempty"`
	Package       string                 `json:"package,omitempty"`
	DBUser        string                 `json:"db_user,omitempty"`
	SyncUsers     bool                   `json:"sync_users,omitempty"`
	Limits        *config.ResourceLimits `json:"limits,omitempty"`
	Limit         int                    `json:"limit,omitempty"`
	ViolationType string                 `json:"violation_type,omitempty"`

	// GitHub Updater fields (Admin Level only)
	TargetVersion   string `json:"target_version,omitempty"`
	GitHubRepo      string `json:"github_repo,omitempty"`
	GitHubToken     string `json:"github_token,omitempty"`
	KeepStoredToken bool   `json:"keep_stored_token,omitempty"`
	UpdateChannel   string `json:"update_channel,omitempty"`
	BackupRetention int    `json:"backup_retention,omitempty"`
}

// UnmarshalJSON decodes Request and gracefully coerces string-encoded CGI query parameters
// (such as "limit": "100" or "sync_users": "true") into strongly typed Go fields.
func (r *Request) UnmarshalJSON(data []byte) error {
	type rawRequest Request
	var fast rawRequest
	if err := json.Unmarshal(data, &fast); err == nil {
		*r = Request(fast)
		return nil
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for _, intKey := range []string{"limit", "backup_retention"} {
		if s, ok := m[intKey].(string); ok {
			trimmed := strings.TrimSpace(s)
			if trimmed == "" {
				delete(m, intKey)
			} else if v, err := strconv.Atoi(trimmed); err == nil {
				m[intKey] = v
			}
		}
	}
	for _, boolKey := range []string{"sync_users", "keep_stored_token"} {
		if s, ok := m[boolKey].(string); ok {
			v := strings.ToLower(strings.TrimSpace(s))
			m[boolKey] = (v == "1" || v == "true" || v == "yes" || v == "on")
		}
	}

	normalized, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var coerced rawRequest
	if err := json.Unmarshal(normalized, &coerced); err != nil {
		return err
	}
	*r = Request(coerced)
	return nil
}

// Response is the standard JSON reply returned by da-resourced.
type Response struct {
	OK      bool        `json:"ok"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// PingData reports daemon health and build metadata.
type PingData struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	BuildTime       string `json:"build_time"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
	ManagedUsers    int    `json:"managed_users"`
	ActivePenalties int    `json:"active_penalties"`
}

// UserUsageSnapshot combines real-time Cgroups v2 and MariaDB resource usage for a single DirectAdmin user.
type UserUsageSnapshot struct {
	Username           string                `json:"username"`
	UID                uint32                `json:"uid"`
	Package            string                `json:"package,omitempty"`
	CPUPercent         float64               `json:"cpu_percent"`
	MemoryCurrentMB    float64               `json:"memory_current_mb"`
	ActiveProcesses    int                   `json:"active_processes"`
	MemoryHighEvents   uint64                `json:"memory_high_events"`
	OOMKillEvents      uint64                `json:"oom_kill_events"`
	MySQLMemoryMB      float64               `json:"mysql_memory_mb"`
	MySQLActiveQueries int                   `json:"mysql_active_queries"`
	MySQLTotalConns    int                   `json:"mysql_total_conns"`
	OOMKills24h        int                   `json:"oom_kills_24h"`
	MySQLKills24h      int                   `json:"mysql_kills_24h"`
	PenaltyActive      bool                  `json:"penalty_active"`
	PenaltyExpiresUnix int64                 `json:"penalty_expires_unix,omitempty"`
	PenaltyReason      string                `json:"penalty_reason,omitempty"`
	Limits             config.ResourceLimits `json:"limits"`
}

// RealtimeDashboardData is returned to Admin Tab 1 (Realtime Monitor).
type RealtimeDashboardData struct {
	Daemon PingData            `json:"daemon"`
	Users  []UserUsageSnapshot `json:"users"`
}

// UserPortalData is returned to the User Level Plugin UI (/CMD_PLUGINS/da_resource_limiter).
type UserPortalData struct {
	Snapshot         UserUsageSnapshot `json:"snapshot"`
	TopKilledQueries []ViolationEntry  `json:"top_killed_queries"`
}

// PackageConfigItem pairs a DirectAdmin package name with its effective ResourceLimits.
type PackageConfigItem struct {
	Package       string                `json:"package"`
	HasCustomFile bool                  `json:"has_custom_file"`
	UserCount     int                   `json:"user_count"`
	Limits        config.ResourceLimits `json:"limits"`
}

// PackagesData is returned to Admin Tab 2 (Package Limits).
type PackagesData struct {
	DefaultLimits config.ResourceLimits `json:"default_limits"`
	Packages      []PackageConfigItem   `json:"packages"`
}

// ViolationEntry represents an OOM Kill, MySQL Killed Query, or Penalty Box trigger event.
type ViolationEntry struct {
	TimestampUnix int64   `json:"timestamp_unix"`
	TimestampISO  string  `json:"timestamp_iso"`
	Username      string  `json:"username"`
	Type          string  `json:"type"`
	MemoryMB      float64 `json:"memory_mb,omitempty"`
	DurationMS    int64   `json:"duration_ms,omitempty"`
	Detail        string  `json:"detail"`
}

// UpdaterStatusData exposes safe GitHub Updater settings & latest release info to Admin UI Tab 5.
type UpdaterStatusData struct {
	CurrentVersion    string `json:"current_version"`
	GitHubRepo        string `json:"github_repo"`
	RepoPinned        bool   `json:"repo_pinned"`
	SignatureRequired bool   `json:"signature_required"`
	RootOnlyActions   bool   `json:"root_only_actions"`
	HasToken          bool   `json:"has_token"`
	MaskedToken       string `json:"masked_token"`
	UpdateChannel     string `json:"update_channel"`
	BackupRetention   int    `json:"backup_retention"`
	LatestVersion     string `json:"latest_version,omitempty"`
	UpdateAvailable   bool   `json:"update_available"`
	ReleaseNotes      string `json:"release_notes,omitempty"`
	PublishedAt       string `json:"published_at,omitempty"`
	LastJobState      string `json:"last_job_state,omitempty"`
	LastJobMessage    string `json:"last_job_message,omitempty"`
}
