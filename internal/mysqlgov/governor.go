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

var protectedMySQLAccounts = map[string]struct{}{
	"root":             {},
	"da_admin":         {},
	"mysql":            {},
	"mariadb.sys":      {},
	"mysql.sys":        {},
	"mysql.session":    {},
	"mysql.infoschema": {},
	"system user":      {},
	"event_scheduler":  {},
	"public":           {},
}

func isProtectedDBUser(dbUser string) bool {
	_, blocked := protectedMySQLAccounts[strings.ToLower(strings.TrimSpace(dbUser))]
	return blocked
}

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

func (g *Governor) effectiveMySQLCaps(daUsername string, limits config.ResourceLimits) (maxConn int, maxTime int) {
	if !limits.Enabled {
		return 0, 0
	}
	maxConn = limits.MySQLMaxConnections
	maxTime = limits.MySQLMaxStatementTime

	g.mu.RLock()
	p, penalized := g.penalties[daUsername]
	g.mu.RUnlock()
	if penalized && g.NowFunc().Unix() < p.ExpiresUnix {
		maxConn = limits.MySQLPenaltyConn
		maxTime = limits.MySQLPenaltyTimeSec
	}

	// Defense-in-depth: never pass 0 (MariaDB "unlimited") when limits.Enabled is true (R2)
	if maxConn < 1 {
		maxConn = 1
	}
	if maxTime < 1 {
		maxTime = 1
	}
	return maxConn, maxTime
}

// ApplyUserAccountLimits (Tier 2) enforces MAX_USER_CONNECTIONS and MAX_STATEMENT_TIME on all DB users owned by daUsername.
func (g *Governor) ApplyUserAccountLimits(ctx context.Context, daUsername string, limits config.ResourceLimits) error {
	if err := config.ValidateIdentifier(daUsername); err != nil {
		return err
	}
	if isProtectedDBUser(daUsername) {
		return fmt.Errorf("refusing to apply MariaDB limits to protected account %q", daUsername)
	}
	maxConn, maxTime := g.effectiveMySQLCaps(daUsername, limits)
	return g.alterAllDBUsersForSystemUser(ctx, daUsername, maxConn, maxTime)
}

// ApplyBatchUserLimits synchronizes MariaDB Tier-2 limits for all supplied DirectAdmin accounts
// in a single SELECT + single batched ALTER USER execution instead of 2*N mysql invocations (R4).
func (g *Governor) ApplyBatchUserLimits(ctx context.Context, limitsByUser map[string]config.ResourceLimits) error {
	if len(limitsByUser) == 0 || g.Registry == nil {
		return nil
	}

	rows, err := g.Runner.QueryTSV(ctx,
		"SELECT User, Host FROM mysql.user WHERE User NOT IN ('root', 'da_admin', 'mysql', 'mariadb.sys', 'mysql.sys', 'mysql.session', 'mysql.infoschema', 'PUBLIC');",
	)
	if err != nil {
		return err
	}
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
		if u == "" || h == "" || isProtectedDBUser(u) {
			continue
		}
		acct, matched := g.Registry.ResolveDBUser(u)
		if !matched {
			continue
		}
		limits, wantSync := limitsByUser[acct.Username]
		if !wantSync {
			continue
		}
		maxConn, maxTime := g.effectiveMySQLCaps(acct.Username, limits)
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

// RemoveUserAccountLimits resets MariaDB per-user limits back to unlimited (0) when a user is disabled or uninstalled.
func (g *Governor) RemoveUserAccountLimits(ctx context.Context, daUsername string) error {
	if err := config.ValidateIdentifier(daUsername); err != nil {
		return err
	}
	if isProtectedDBUser(daUsername) {
		return nil
	}
	return g.alterAllDBUsersForSystemUser(ctx, daUsername, 0, 0)
}

// ApplySingleOwnedDBUserLimits verifies dbUser is not a system account and strictly belongs to daUsername
// before applying Tier-2 MariaDB limits (S9).
func (g *Governor) ApplySingleOwnedDBUserLimits(ctx context.Context, daUsername, dbUser string, limits config.ResourceLimits) error {
	if err := config.ValidateIdentifier(daUsername); err != nil {
		return err
	}
	dbUser = strings.TrimSpace(dbUser)
	if dbUser == "" || strings.ContainsAny(dbUser, "';\"\\\r\n\t") {
		return fmt.Errorf("invalid db username %q", dbUser)
	}
	if isProtectedDBUser(dbUser) || isProtectedDBUser(daUsername) {
		return fmt.Errorf("refusing to modify protected MariaDB system account %q", dbUser)
	}
	if g.Registry != nil {
		owner, matched := g.Registry.ResolveDBUser(dbUser)
		if !matched || owner.Username != daUsername {
			return fmt.Errorf("db user %q does not belong to DirectAdmin user %q", dbUser, daUsername)
		}
	}

	maxConn, maxTime := g.effectiveMySQLCaps(daUsername, limits)
	escapedUser := escapeSQLString(dbUser)
	rows, err := g.Runner.QueryTSV(ctx, fmt.Sprintf(
		"SELECT User, Host FROM mysql.user WHERE User = '%s';", escapedUser,
	))
	if err != nil {
		return err
	}
	return g.execAlterForUserHostRows(ctx, rows, maxConn, maxTime)
}

// ApplySingleDBUserLimits enforces Tier-2 limits on a single DB user after blocking protected accounts
// and validating ownership against Registry if available (S9).
func (g *Governor) ApplySingleDBUserLimits(ctx context.Context, dbUser string, limits config.ResourceLimits) error {
	dbUser = strings.TrimSpace(dbUser)
	if dbUser == "" || strings.ContainsAny(dbUser, "';\"\\\r\n\t") {
		return fmt.Errorf("invalid db username %q", dbUser)
	}
	if isProtectedDBUser(dbUser) {
		return fmt.Errorf("refusing to modify protected MariaDB system account %q", dbUser)
	}
	ownerName := dbUser
	if g.Registry != nil {
		owner, matched := g.Registry.ResolveDBUser(dbUser)
		if !matched {
			return fmt.Errorf("db user %q is not owned by any managed DirectAdmin hosting user", dbUser)
		}
		ownerName = owner.Username
	}
	return g.ApplySingleOwnedDBUserLimits(ctx, ownerName, dbUser, limits)
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
		if u == "" || h == "" || isProtectedDBUser(u) {
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

// PollOnce executes one cycle of the Tier-3 MariaDB Watchdog.
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

	threshold := limits.MySQLPenaltyThreshold
	if threshold < 1 {
		threshold = 5
	}
	windowSec := limits.MySQLPenaltyWindowSec
	if windowSec < 5 {
		windowSec = 60
	}
	durationSec := limits.MySQLPenaltyDurationSec
	if durationSec < 10 {
		durationSec = 300
	}
	penConn := limits.MySQLPenaltyConn
	if penConn < 1 {
		penConn = 1
	}
	penTime := limits.MySQLPenaltyTimeSec
	if penTime < 1 {
		penTime = 1
	}

	nowUnix := now.Unix()
	cutoff := nowUnix - int64(windowSec)

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

	if len(pruned) < threshold {
		g.mu.Unlock()
		return
	}

	entry := PenaltyEntry{
		Username:    acct.Username,
		StartedUnix: nowUnix,
		ExpiresUnix: nowUnix + int64(durationSec),
		Reason:      fmt.Sprintf("%d killed queries within %ds", len(pruned), windowSec),
	}
	g.penalties[acct.Username] = entry
	delete(g.violationTimestamps, acct.Username)
	_ = g.savePenaltyStateLocked()
	g.mu.Unlock()

	_ = g.alterAllDBUsersForSystemUser(ctx, acct.Username, penConn, penTime)

	if g.Logger != nil {
		_ = g.Logger.Log(ipc.ViolationEntry{
			TimestampUnix: nowUnix,
			Username:      acct.Username,
			Type:          logger.TypeMySQLPenaltyBox,
			DurationMS:    int64(durationSec) * 1000,
			Detail: fmt.Sprintf("Throttled for %ds (MAX_USER_CONNECTIONS=%d, MAX_STATEMENT_TIME=%ds): %s",
				durationSec, penConn, penTime, entry.Reason),
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
	dir := filepath.Dir(g.PenaltyStatePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".penalty-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, g.PenaltyStatePath); err != nil {
		return err
	}
	cleanupTmp = false
	return nil
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

	return processRow{
		ID:          id,
		DBUser:      strings.TrimSpace(parts[1]),
		Command:     strings.TrimSpace(parts[2]),
		TimeMS:      timeMS,
		MemoryBytes: memBytes,
		Info:        strings.TrimSpace(parts[5]),
	}, true
}

func isActiveQueryCommand(cmd string) bool {
	switch cmd {
	case "Query", "Execute":
		return true
	default:
		return false
	}
}

func filterUnkilled(rows []processRow, killed map[uint64]bool) []processRow {
	var out []processRow
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
	if len(sqlSnippet) > 300 {
		sqlSnippet = sqlSnippet[:300] + "..."
	}
	return fmt.Sprintf("[%s] db_user=%s thread=%d mem=%.1fMB time=%dms | SQL: %s",
		reason, q.DBUser, q.ID, bytesToMB(q.MemoryBytes), q.TimeMS, sqlSnippet)
}

func escapeSQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return s
}

func escapeSQLLikeBang(s string) string {
	s = escapeSQLString(s)
	s = strings.ReplaceAll(s, `!`, `!!`)
	s = strings.ReplaceAll(s, `%`, `!%`)
	s = strings.ReplaceAll(s, `_`, `!_`)
	return s
}
