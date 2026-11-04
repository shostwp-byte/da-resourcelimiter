package ipc

import "github.com/shostwp-byte/da-resourcelimiter/internal/config"

// Supported IPC Socket actions over /var/run/da-resourced.sock.
const (
	ActionPing               = "ping"
	ActionGetRealtimeStats   = "get_realtime_stats"
	ActionGetUserStats       = "get_user_stats"
	ActionApplyUserLimits    = "apply_user_limits"
	ActionApplyPackageLimits = "apply_package_limits"
	ActionUnblockPenalty     = "unblock_penalty"
	ActionGetLogs            = "get_logs"
	ActionGetUpdaterStatus   = "get_updater_status"
	ActionSaveUpdaterConfig  = "save_updater_config"
	ActionCheckUpdate        = "check_update"
	ActionTriggerUpdate      = "trigger_update"
	ActionRollbackUpdate     = "rollback_update"
)

// Request is the JSON command envelope sent by DirectAdmin CGI/Hooks to da-resourced.
type Request struct {
	Action        string `json:"action"`
	Username      string `json:"username,omitempty"`
	Package       string `json:"package,omitempty"`
	Limit         int    `json:"limit,omitempty"`
	ViolationType string `json:"violation_type,omitempty"`

	// GitHub Updater fields (Admin Level only)
	TargetVersion   string `json:"target_version,omitempty"`
	GitHubRepo      string `json:"github_repo,omitempty"`
	GitHubToken     string `json:"github_token,omitempty"`
	KeepStoredToken bool   `json:"keep_stored_token,omitempty"`
	UpdateChannel   string `json:"update_channel,omitempty"`
	BackupRetention int    `json:"backup_retention,omitempty"`
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
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	BuildTime     string `json:"build_time"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	ManagedUsers  int    `json:"managed_users"`
}

// UserUsageSnapshot combines real-time Cgroups v2 and MariaDB resource usage for a single DirectAdmin user.
type UserUsageSnapshot struct {
	Username          string                `json:"username"`
	UID               uint32                `json:"uid"`
	Package           string                `json:"package,omitempty"`
	CPUPercent        float64               `json:"cpu_percent"`
	MemoryCurrentMB   float64               `json:"memory_current_mb"`
	ActiveProcesses   int                   `json:"active_processes"`
	MemoryHighEvents  uint64                `json:"memory_high_events"`
	OOMKillEvents     uint64                `json:"oom_kill_events"`
	MySQLMemoryMB     float64               `json:"mysql_memory_mb"`
	MySQLActiveConns  int                   `json:"mysql_active_conns"`
	PenaltyActive     bool                  `json:"penalty_active"`
	PenaltyExpiresUnix int64                `json:"penalty_expires_unix,omitempty"`
	Limits            config.ResourceLimits `json:"limits"`
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
	CurrentVersion  string `json:"current_version"`
	GitHubRepo      string `json:"github_repo"`
	HasToken        bool   `json:"has_token"`
	MaskedToken     string `json:"masked_token"`
	UpdateChannel   string `json:"update_channel"`
	BackupRetention int    `json:"backup_retention"`
	LatestVersion   string `json:"latest_version,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseNotes    string `json:"release_notes,omitempty"`
	PublishedAt     string `json:"published_at,omitempty"`
	LastJobState    string `json:"last_job_state,omitempty"`
	LastJobMessage  string `json:"last_job_message,omitempty"`
}
