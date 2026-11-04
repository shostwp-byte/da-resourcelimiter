package mysqlgov

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
	"github.com/shostwp-byte/da-resourcelimiter/internal/ipc"
	"github.com/shostwp-byte/da-resourcelimiter/internal/logger"
)

const DefaultPenaltyStatePath = "/var/lib/da-resourced/penalty_state.json"

// LiveUserMySQLUsage stores the latest real-time MariaDB snapshot for a single DirectAdmin user.
type LiveUserMySQLUsage struct {
	MemoryBytes      uint64
	ActiveQueries    int
	TotalConnections int
}

// PenaltyEntry tracks an active MySQL throttling penalty for a DirectAdmin user.
type PenaltyEntry struct {
	Username    string `json:"username"`
	StartedUnix int64  `json:"started_unix"`
	ExpiresUnix int64  `json:"expires_unix"`
	Reason      string `json:"reason"`
}

type processRow struct {
	ID          uint64
	DBUser      string
	Command     string
	TimeMS      int64
	MemoryBytes uint64
	Info        string
}

// LimitsResolver resolves effective ResourceLimits for a DirectAdmin account.
type LimitsResolver func(acct dausers.Account) (config.ResourceLimits, error)

// Governor implements Tier-2 (ALTER USER limits) and Tier-3 (Real-time PROCESSLIST Watchdog + Penalty Box).
type Governor struct {
	Runner           SQLRunner
	Registry         *dausers.Registry
	ResolveLimits    LimitsResolver
	Logger           *logger.ViolationLogger
	PenaltyStatePath string
	NowFunc          func() time.Time

	mu                  sync.RWMutex
	hasMemoryUsedColumn bool
	capabilitiesChecked bool
	liveUsage           map[string]LiveUserMySQLUsage
	violationTimestamps map[string][]int64
	penalties           map[string]PenaltyEntry
}

func NewGovernor(
	runner SQLRunner,
	reg *dausers.Registry,
	resolver LimitsResolver,
	vlog *logger.ViolationLogger,
	penaltyStatePath string,
) *Governor {
	if penaltyStatePath == "" {
		penaltyStatePath = DefaultPenaltyStatePath
	}
	g := &Governor{
		Runner:              runner,
		Registry:            reg,
		ResolveLimits:       resolver,
		Logger:              vlog,
		PenaltyStatePath:    penaltyStatePath,
		NowFunc:             time.Now,
		hasMemoryUsedColumn: true,
		liveUsage:           make(map[string]LiveUserMySQLUsage),
		violationTimestamps: make(map[string][]int64),
		penalties:           make(map[string]PenaltyEntry),
	}
	_ = g.loadPenaltyState()
	return g
}

// DetectCapabilities probes MariaDB 10.5+ PROCESSLIST columns (MEMORY_USED, TIME_MS) once on startup.
func (g *Governor) DetectCapabilities(ctx context.Context) error {
	_, err := g.Runner.QueryTSV(ctx, "SELECT ID, TIME_MS, MEMORY_USED FROM information_schema.PROCESSLIST LIMIT 1;")
	g.mu.Lock()
	defer g.mu.Unlock()
	g.capabilitiesChecked = true
	if err != nil {
		g.hasMemoryUsedColumn = false
		return err
	}
	g.hasMemoryUsedColumn = true
	return nil
}

// GetLiveUsage returns the latest cached MariaDB usage & penalty status for a DirectAdmin user.
func (g *Governor) GetLiveUsage(username string) (LiveUserMySQLUsage, PenaltyEntry, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	u := g.liveUsage[username]
	p, penalized := g.penalties[username]
	if penalized && g.NowFunc().Unix() >= p.ExpiresUnix {
		penalized = false
	}
	return u, p, penalized
}

// ActivePenalties returns all currently active Penalty Box entries.
func (g *Governor) ActivePenalties() []PenaltyEntry {
	now := g.NowFunc().Unix()
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []PenaltyEntry
	for _, p := range g.penalties {
		if now < p.ExpiresUnix {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Username < out[j].Username
	})
	return out
}

// ApplyUserAccountLimits (Tier 2) enforces MAX_USER_CONNECTIONS and MAX_STATEMENT_TIME on all DB users owned by daUsername.
func (g *Governor) ApplyUserAccountLimits(ctx context.Context, daUsername string, limits config.ResourceLimits) error {
	if err := config.ValidateIdentifier(daUsername); err != nil {
		return err
	}

	maxConn := 0
	maxTime := 0
	if limits.Enabled {
		maxConn = limits.MySQLMaxConnections
		maxTime = limits.MySQLMaxStatementTime

		g.mu.RLock()
		p, penalized := g.penalties[daUsername]
		g.mu.RUnlock()
		if penalized && g.NowFunc().Unix() < p.ExpiresUnix {
			maxConn = limits.MySQLPenaltyConn
			maxTime = limits.MySQLPenaltyTimeSec
		}
	}

	return g.alterAllDBUsersForSystemUser(ctx, daUsername, maxConn, maxTime)
}

// RemoveUserAccountLimits resets MariaDB per-user limits back to unlimited (0) when a user is disabled or uninstalled.
func (g *Governor) RemoveUserAccountLimits(ctx context.Context, daUsername string) error {
	if err := config.ValidateIdentifier(daUsername); err != nil {
		return err
	}
	return g.alterAllDBUsersForSystemUser(ctx, daUsername, 0, 0)
}

// ApplySingleDBUserLimits immediately enforces Tier-2 limits on a newly created MariaDB user (database_user_create_post hook).
func (g *Governor) ApplySingleDBUserLimits(ctx context.Context, dbUser string, limits config.ResourceLimits) error {
	dbUser = strings.TrimSpace(dbUser)
	if dbUser == "" || strings.ContainsAny(dbUser, "';\"\\\r\n\t") {
		return fmt.Errorf("invalid db username %q", dbUser)
	}

	maxConn := 0
	maxTime := 0
	if limits.Enabled {
		maxConn = limits.MySQLMaxConnections
		maxTime = limits.MySQLMaxStatementTime
	}

	escapedUser := escapeSQLString(dbUser)
	rows, err := g.Runner.QueryTSV(ctx, fmt.Sprintf(
		"SELECT User, Host FROM mysql.user WHERE User = '%s';", escapedUser,
	))
	if err != nil {
		return err
	}
	return g.execAlterForUserHostRows(ctx, rows, maxConn, maxTime)
}

func (g *Governor) alterAllDBUsersForSystemUser(ctx context.Context, daUsername string, maxConn, maxTime int) error {
	escapedExact := escapeSQLString(daUsername)
	escapedLikePrefix := escapeSQLLikeBang(daUsername) + "!_%"

	query := fmt.Sprintf(
		"SELECT User, Host FROM mysql.user WHERE User = '%s' OR User LIKE '%s' ESCAPE '!';",
		escapedExact, escapedLikePrefix,
	)
	rows, err := g.Runner.QueryTSV(ctx, query)
	if err != nil {
		return err
	}
	return g.execAlterForUserHostRows(ctx, rows, maxConn, maxTime)
}

func (g *Governor) execAlterForUserHostRows(ctx context.Context, rows []string, maxConn, maxTime int) error {
	if len(rows) == 0 {
		return nil
	}

	var batch strings.Builder
	count := 0
	for _, line := range rows {
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		u := strings.TrimSpace(parts[0])
		h := strings.TrimSpace(parts[1])
		if u == "" || h == "" {
			continue
		}
		fmt.Fprintf(&batch,
			"ALTER USER '%s'@'%s' WITH MAX_USER_CONNECTIONS %d MAX_STATEMENT_TIME %d;\n",
			escapeSQLString(u), escapeSQLString(h), maxConn, maxTime,
		)
		count++
	}
	if count == 0 {
		return nil
	}
	batch.WriteString("FLUSH USER_RESOURCES;\n")
	return g.Runner.ExecBatch(ctx, batch.String())
}

// UnblockUser immediately removes a user from the Penalty Box and restores their configured DB limits.
func (g *Governor) UnblockUser(ctx context.Context, daUsername string) error {
	if err := config.ValidateIdentifier(daUsername); err != nil {
		return err
	}

	g.mu.Lock()
	_, existed := g.penalties[daUsername]
	delete(g.penalties, daUsername)
	delete(g.violationTimestamps, daUsername)
	_ = g.savePenaltyStateLocked()
	g.mu.Unlock()

	acct, ok := g.Registry.LookupByName(daUsername)
	if !ok {
		if !existed {
			return fmt.Errorf("user %q not found", daUsername)
		}
		return nil
	}

	limits, err := g.ResolveLimits(acct)
	if err != nil {
		return err
	}
	return g.ApplyUserAccountLimits(ctx, daUsername, limits)
}

// PollOnce executes one cycle of the Tier-3 MariaDB Watchdog:
//  1. Restores any expired Penalty Box entries.
//  2. Queries information_schema.PROCESSLIST.
//  3. Aggregates connections, active threads, and MEMORY_USED per DirectAdmin system user.
//  4. Kills heaviest offending queries and triggers Penalty Box if repeated violations exceed threshold.
func (g *Governor) PollOnce(ctx context.Context) (killedCount int, err error) {
	now := g.NowFunc()
	g.expirePenalties(ctx, now)

	g.mu.RLock()
	hasMemCol := g.hasMemoryUsedColumn
	g.mu.RUnlock()

	var selectSQL string
	if hasMemCol {
		selectSQL = "SELECT ID, USER, COMMAND, CAST(IFNULL(TIME_MS, TIME * 1000) AS SIGNED), IFNULL(MEMORY_USED, 0), " +
			"REPLACE(REPLACE(LEFT(IFNULL(INFO, ''), 512), '\\n', ' '), '\\t', ' ') " +
			"FROM information_schema.PROCESSLIST " +
			"WHERE USER NOT IN ('root', 'da_admin', 'system user', 'event_scheduler', 'mariadb.sys');"
	} else {
		selectSQL = "SELECT ID, USER, COMMAND, CAST(TIME * 1000 AS SIGNED), 0, " +
			"REPLACE(REPLACE(LEFT(IFNULL(INFO, ''), 512), '\\n', ' '), '\\t', ' ') " +
			"FROM information_schema.PROCESSLIST " +
			"WHERE USER NOT IN ('root', 'da_admin', 'system user', 'event_scheduler', 'mariadb.sys');"
	}

	lines, err := g.Runner.QueryTSV(ctx, selectSQL)
	if err != nil {
		return 0, err
	}

	type userBucket struct {
		acct             dausers.Account
		totalConnections int
		totalMemBytes    uint64
		activeQueries    []processRow
	}

	buckets := make(map[string]*userBucket)
	for _, line := range lines {
		row, ok := parseProcessRow(line)
		if !ok {
			continue
		}
		acct, matched := g.Registry.ResolveDBUser(row.DBUser)
		if !matched {
			continue
		}

		b, exists := buckets[acct.Username]
		if !exists {
			b = &userBucket{acct: acct}
			buckets[acct.Username] = b
		}
		b.totalConnections++

		if isActiveQueryCommand(row.Command) {
			b.totalMemBytes += row.MemoryBytes
			b.activeQueries = append(b.activeQueries, row)
		}
	}

	// Atomically refresh live usage snapshot for UI consumers
	nextLive := make(map[string]LiveUserMySQLUsage, len(buckets))
	for uname, b := range buckets {
		nextLive[uname] = LiveUserMySQLUsage{
			MemoryBytes:      b.totalMemBytes,
			ActiveQueries:    len(b.activeQueries),
			TotalConnections: b.totalConnections,
		}
	}
	g.mu.Lock()
	g.liveUsage = nextLive
	g.mu.Unlock()

	var killSQL strings.Builder
	type pendingViolation struct {
		acct   dausers.Account
		limits config.ResourceLimits
		entry  ipc.ViolationEntry
	}
	var violations []pendingViolation

	for _, b := range buckets {
		if len(b.activeQueries) == 0 {
			continue
		}
		limits, err := g.ResolveLimits(b.acct)
		if err != nil || !limits.Enabled {
			continue
		}

		maxMemBytes := uint64(limits.MySQLMaxMemMB) * 1024 * 1024
		maxTimeMS := int64(limits.MySQLMaxStatementTime) * 1000
		killedIDs := make(map[uint64]bool)

		// 1. Kill individual queries exceeding max_statement_time (defense-in-depth if client bypassed session var)
		for _, q := range b.activeQueries {
			if maxTimeMS > 0 && q.TimeMS > maxTimeMS {
				fmt.Fprintf(&killSQL, "KILL QUERY %d;\n", q.ID)
				killedIDs[q.ID] = true
				if b.totalMemBytes >= q.MemoryBytes {
					b.totalMemBytes -= q.MemoryBytes
				}
				violations = append(violations, pendingViolation{
					acct:   b.acct,
					limits: limits,
					entry: ipc.ViolationEntry{
						TimestampUnix: now.Unix(),
						Username:      b.acct.Username,
						Type:          logger.TypeMySQLSlowQuery,
						MemoryMB:      bytesToMB(q.MemoryBytes),
						DurationMS:    q.TimeMS,
						Detail:        formatQueryDetail(q, "exceeded max statement time"),
					},
				})
			}
		}

		// 2. If aggregate user MySQL RAM still exceeds MYSQL_MAX_MEM_MB, kill heaviest memory queries first
		if hasMemCol && maxMemBytes > 0 && b.totalMemBytes > maxMemBytes {
			remaining := filterUnkilled(b.activeQueries, killedIDs)
			sort.Slice(remaining, func(i, j int) bool {
				if remaining[i].MemoryBytes != remaining[j].MemoryBytes {
					return remaining[i].MemoryBytes > remaining[j].MemoryBytes
				}
				return remaining[i].TimeMS > remaining[j].TimeMS
			})

			for _, q := range remaining {
				if b.totalMemBytes <= maxMemBytes {
					break
				}
				fmt.Fprintf(&killSQL, "KILL QUERY %d;\n", q.ID)
				killedIDs[q.ID] = true
				totalBefore := b.totalMemBytes
				if b.totalMemBytes >= q.MemoryBytes {
					b.totalMemBytes -= q.MemoryBytes
				} else {
					b.totalMemBytes = 0
				}
				violations = append(violations, pendingViolation{
					acct:   b.acct,
					limits: limits,
					entry: ipc.ViolationEntry{
						TimestampUnix: now.Unix(),
						Username:      b.acct.Username,
						Type:          logger.TypeMySQLHighMemory,
						MemoryMB:      bytesToMB(totalBefore),
						DurationMS:    q.TimeMS,
						Detail:        formatQueryDetail(q, fmt.Sprintf("user MySQL RAM %.1fMB > %dMB limit", bytesToMB(totalBefore), limits.MySQLMaxMemMB)),
					},
				})
			}
		}

		// 3. If concurrent active queries still exceed MYSQL_MAX_ACTIVE_QUERIES, kill longest-running excess queries
		remaining := filterUnkilled(b.activeQueries, killedIDs)
		if limits.MySQLMaxActiveQueries > 0 && len(remaining) > limits.MySQLMaxActiveQueries {
			sort.Slice(remaining, func(i, j int) bool {
				if remaining[i].TimeMS != remaining[j].TimeMS {
					return remaining[i].TimeMS > remaining[j].TimeMS
				}
				return remaining[i].MemoryBytes > remaining[j].MemoryBytes
			})

			excess := len(remaining) - limits.MySQLMaxActiveQueries
			for i := 0; i < excess; i++ {
				q := remaining[i]
				fmt.Fprintf(&killSQL, "KILL QUERY %d;\n", q.ID)
				killedIDs[q.ID] = true
				violations = append(violations, pendingViolation{
					acct:   b.acct,
					limits: limits,
					entry: ipc.ViolationEntry{
						TimestampUnix: now.Unix(),
						Username:      b.acct.Username,
						Type:          logger.TypeMySQLSlowQuery,
						MemoryMB:      bytesToMB(q.MemoryBytes),
						DurationMS:    q.TimeMS,
						Detail:        formatQueryDetail(q, fmt.Sprintf("active queries %d > %d limit", len(remaining), limits.MySQLMaxActiveQueries)),
					},
				})
			}
		}
	}

	if killSQL.Len() > 0 {
		// Execute all KILL QUERY statements in one batch; ignore benign race if a query finished milliseconds ago
		_ = g.Runner.ExecBatch(ctx, killSQL.String())
	}

	for _, v := range violations {
		killedCount++
		if g.Logger != nil {
			_ = g.Logger.Log(v.entry)
		}
		g.recordViolationAndMaybePenalize(ctx, now, v.acct, v.limits)
	}

	return killedCount, nil
}

func (g *Governor) recordViolationAndMaybePenalize(ctx context.Context, now time.Time, acct dausers.Account, limits config.ResourceLimits) {
	if !limits.MySQLPenaltyEnabled {
		return
	}

	nowUnix := now.Unix()
	cutoff := nowUnix - int64(limits.MySQLPenaltyWindowSec)

	g.mu.Lock()
	if existing, ok := g.penalties[acct.Username]; ok && nowUnix < existing.ExpiresUnix {
		g.mu.Unlock()
		return
	}

	history := g.violationTimestamps[acct.Username]
	pruned := history[:0]
	for _, ts := range history {
		if ts >= cutoff {
			pruned = append(pruned, ts)
		}
	}
	pruned = append(pruned, nowUnix)
	g.violationTimestamps[acct.Username] = pruned

	if len(pruned) < limits.MySQLPenaltyThreshold {
		g.mu.Unlock()
		return
	}

	entry := PenaltyEntry{
		Username:    acct.Username,
		StartedUnix: nowUnix,
		ExpiresUnix: nowUnix + int64(limits.MySQLPenaltyDurationSec),
		Reason:      fmt.Sprintf("%d killed queries within %ds", len(pruned), limits.MySQLPenaltyWindowSec),
	}
	g.penalties[acct.Username] = entry
	delete(g.violationTimestamps, acct.Username)
	_ = g.savePenaltyStateLocked()
	g.mu.Unlock()

	_ = g.alterAllDBUsersForSystemUser(ctx, acct.Username, limits.MySQLPenaltyConn, limits.MySQLPenaltyTimeSec)

	if g.Logger != nil {
		_ = g.Logger.Log(ipc.ViolationEntry{
			TimestampUnix: nowUnix,
			Username:      acct.Username,
			Type:          logger.TypeMySQLPenaltyBox,
			DurationMS:    int64(limits.MySQLPenaltyDurationSec) * 1000,
			Detail: fmt.Sprintf("Throttled for %ds (MAX_USER_CONNECTIONS=%d, MAX_STATEMENT_TIME=%ds): %s",
				limits.MySQLPenaltyDurationSec, limits.MySQLPenaltyConn, limits.MySQLPenaltyTimeSec, entry.Reason),
		})
	}
}

func (g *Governor) expirePenalties(ctx context.Context, now time.Time) {
	nowUnix := now.Unix()
	var expiredUsers []string

	g.mu.Lock()
	for uname, p := range g.penalties {
		if nowUnix >= p.ExpiresUnix {
			expiredUsers = append(expiredUsers, uname)
			delete(g.penalties, uname)
		}
	}
	if len(expiredUsers) > 0 {
		_ = g.savePenaltyStateLocked()
	}
	g.mu.Unlock()

	for _, uname := range expiredUsers {
		acct, ok := g.Registry.LookupByName(uname)
		if !ok {
			continue
		}
		limits, err := g.ResolveLimits(acct)
		if err != nil {
			continue
		}
		_ = g.ApplyUserAccountLimits(ctx, uname, limits)
	}
}

func (g *Governor) loadPenaltyState() error {
	raw, err := os.ReadFile(g.PenaltyStatePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var list []PenaltyEntry
	if err := json.Unmarshal(raw, &list); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, p := range list {
		if p.Username != "" {
			g.penalties[p.Username] = p
		}
	}
	return nil
}

func (g *Governor) savePenaltyStateLocked() error {
	if g.PenaltyStatePath == "" {
		return nil
	}
	list := make([]PenaltyEntry, 0, len(g.penalties))
	for _, p := range g.penalties {
		list = append(list, p)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(g.PenaltyStatePath), 0o750); err != nil {
		return err
	}
	tmp := g.PenaltyStatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, g.PenaltyStatePath)
}

func parseProcessRow(line string) (processRow, bool) {
	parts := strings.SplitN(line, "\t", 6)
	if len(parts) < 6 {
		return processRow{}, false
	}
	id, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return processRow{}, false
	}
	timeMS, _ := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)
	memBytes, _ := strconv.ParseUint(strings.TrimSpace(parts[4]), 10, 64)
	info := strings.TrimSpace(parts[5])
	if info == "NULL" {
		info = ""
	}
	return processRow{
		ID:          id,
		DBUser:      strings.TrimSpace(parts[1]),
		Command:     strings.TrimSpace(parts[2]),
		TimeMS:      timeMS,
		MemoryBytes: memBytes,
		Info:        info,
	}, true
}

func isActiveQueryCommand(cmd string) bool {
	switch cmd {
	case "", "Sleep", "Daemon", "Binlog Dump", "Binlog Dump GTID":
		return false
	default:
		return true
	}
}

func filterUnkilled(rows []processRow, killed map[uint64]bool) []processRow {
	out := make([]processRow, 0, len(rows))
	for _, r := range rows {
		if !killed[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

func bytesToMB(b uint64) float64 {
	return float64(b) / (1024.0 * 1024.0)
}

func formatQueryDetail(q processRow, reason string) string {
	sqlSnippet := q.Info
	if sqlSnippet == "" {
		sqlSnippet = "(" + q.Command + ")"
	}
	return fmt.Sprintf("[PID %d | DBUser %s | %.1fMB | %dms | %s] %s",
		q.ID, q.DBUser, bytesToMB(q.MemoryBytes), q.TimeMS, reason, sqlSnippet)
}

func escapeSQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}

func escapeSQLLikeBang(s string) string {
	s = escapeSQLString(s)
	s = strings.ReplaceAll(s, "!", "!!")
	s = strings.ReplaceAll(s, "%", "!%")
	s = strings.ReplaceAll(s, "_", "!_")
	return s
}
