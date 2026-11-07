package mysqlgov

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
	"github.com/shostwp-byte/da-resourcelimiter/internal/logger"
)

type mockSQLRunner struct {
	processRows []string
	mysqlUsers  []string
	executedSQL []string
	queryCalls  int
	failExecErr error
}

func (m *mockSQLRunner) QueryTSV(_ context.Context, sql string) ([]string, error) {
	m.queryCalls++
	if strings.Contains(sql, "FROM information_schema.PROCESSLIST") {
		return m.processRows, nil
	}
	if strings.Contains(sql, "FROM mysql.user") {
		return filterMockMySQLUsers(m.mysqlUsers, sql), nil
	}
	return nil, nil
}

// filterMockMySQLUsers emulates MariaDB WHERE User = / LIKE / NOT IN clauses so unit tests catch cross-tenant bugs (N20e).
func filterMockMySQLUsers(rows []string, sql string) []string {
	var exactUser, prefix string
	if idx := strings.Index(sql, "WHERE (User = '"); idx >= 0 {
		rest := sql[idx+len("WHERE (User = '"):]
		if end := strings.IndexByte(rest, '\''); end >= 0 {
			exactUser = rest[:end]
			prefix = exactUser + "_"
		}
	}

	out := make([]string, 0, len(rows))
	for _, r := range rows {
		parts := strings.SplitN(r, "\t", 2)
		if len(parts) < 2 {
			continue
		}
		u := parts[0]
		if isProtectedDBUser(u) && strings.Contains(sql, "NOT IN") {
			continue
		}
		if exactUser != "" && u != exactUser && !strings.HasPrefix(u, prefix) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (m *mockSQLRunner) ExecBatch(_ context.Context, sql string) error {
	if m.failExecErr != nil {
		return m.failExecErr
	}
	m.executedSQL = append(m.executedSQL, sql)
	return nil
}

func TestGovernorMemoryFloodKillAndPenaltyBoxLifecycle(t *testing.T) {
	tmp := t.TempDir()
	passwdFile := filepath.Join(tmp, "passwd")
	daDir := filepath.Join(tmp, "users")
	logPath := filepath.Join(tmp, "violations.jsonl")
	penaltyPath := filepath.Join(tmp, "penalty_state.json")

	_ = os.WriteFile(passwdFile, []byte("vina_host:x:1005:1005::/home/vina_host:/bin/bash\nalice:x:1006:1006::/home/alice:/bin/bash\n"), 0o644)
	for _, u := range []string{"vina_host", "alice"} {
		_ = os.MkdirAll(filepath.Join(daDir, u), 0o755)
		_ = os.WriteFile(filepath.Join(daDir, u, "user.conf"), []byte("usertype=user\npackage=gold\n"), 0o600)
	}

	reg := dausers.NewRegistry(daDir, passwdFile)
	if err := reg.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	limits := config.DefaultLimits()
	limits.MySQLMaxMemMB = 256
	limits.MySQLMaxActiveQueries = 4
	limits.MySQLMaxConnections = 20
	limits.MySQLMaxStatementTime = 10
	limits.MySQLPenaltyEnabled = true
	limits.MySQLPenaltyThreshold = 3
	limits.MySQLPenaltyWindowSec = 60
	limits.MySQLPenaltyDurationSec = 300
	limits.MySQLPenaltyConn = 2
	limits.MySQLPenaltyTimeSec = 2

	runner := &mockSQLRunner{
		mysqlUsers: []string{
			"vina_host_wp\tlocalhost",
			"alice_shop\tlocalhost",
			"da_admin\tlocalhost",
		},
	}
	vlog := logger.NewViolationLogger(logPath, 1024*1024, 2)

	now := time.Unix(1700000000, 0)
	gov := NewGovernor(runner, reg, func(_ dausers.Account) (config.ResourceLimits, error) {
		return limits, nil
	}, vlog, penaltyPath)
	gov.NowFunc = func() time.Time { return now }

	// Verify batched ApplyBatchUserLimits executes 1 SELECT + 1 batched ALTER USER and skips da_admin (R4, S9)
	if err := gov.ApplyBatchUserLimits(context.Background(), map[string]config.ResourceLimits{
		"vina_host": limits,
		"alice":     limits,
	}); err != nil {
		t.Fatalf("ApplyBatchUserLimits: %v", err)
	}
	if runner.queryCalls != 1 || len(runner.executedSQL) != 1 {
		t.Fatalf("expected 1 SELECT and 1 batched ExecBatch for 2 accounts, got queries=%d execs=%d", runner.queryCalls, len(runner.executedSQL))
	}
	if strings.Contains(runner.executedSQL[0], "da_admin") {
		t.Fatalf("protected account da_admin must NEVER appear in ALTER USER batch:\n%s", runner.executedSQL[0])
	}
	runner.executedSQL = nil

	// Simulate TC-05: 2 queries totaling 330 MB (> 256 MB limit); PID 902 is heaviest (200 MB)
	mb := uint64(1024 * 1024)
	runner.processRows = []string{
		fmt.Sprintf("901\tvina_host_wp\tQuery\t1200\t%d\tSELECT * FROM wp_posts", 130*mb),
		fmt.Sprintf("902\tvina_host_wp\tQuery\t2500\t%d\tSELECT * FROM wp_postmeta JOIN wp_options", 200*mb),
		"903\tvina_host_wp\tSleep\t5000\t0\tNULL",
	}

	for i := 0; i < 3; i++ {
		now = now.Add(2 * time.Second)
		killed, err := gov.PollOnce(context.Background())
		if err != nil {
			t.Fatalf("PollOnce #%d: %v", i+1, err)
		}
		if killed != 1 {
			t.Fatalf("expected heaviest query PID 902 killed on poll #%d, got %d", i+1, killed)
		}
	}

	allSQL := strings.Join(runner.executedSQL, "\n")
	if !strings.Contains(allSQL, "KILL QUERY 902;") {
		t.Fatalf("expected KILL QUERY 902 in executed SQL:\n%s", allSQL)
	}
	if !strings.Contains(allSQL, "ALTER USER 'vina_host_wp'@'localhost' WITH MAX_USER_CONNECTIONS 2 MAX_STATEMENT_TIME 2;") {
		t.Fatalf("expected Penalty Box ALTER USER in executed SQL:\n%s", allSQL)
	}

	usage, pen, penalized := gov.GetLiveUsage("vina_host")
	if !penalized || usage.TotalConnections != 3 || usage.ActiveQueries != 2 {
		t.Fatalf("unexpected live usage or penalty state: usage=%+v pen=%+v penalized=%v", usage, pen, penalized)
	}

	govRestarted := NewGovernor(runner, reg, func(_ dausers.Account) (config.ResourceLimits, error) {
		return limits, nil
	}, vlog, penaltyPath)
	govRestarted.NowFunc = func() time.Time { return now }

	if _, _, stillPenalized := govRestarted.GetLiveUsage("vina_host"); !stillPenalized {
		t.Fatal("expected penalty state to survive daemon restart")
	}

	runner.executedSQL = nil
	runner.processRows = nil
	now = now.Add(305 * time.Second)
	if _, err := govRestarted.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce after expiry: %v", err)
	}

	restoredSQL := strings.Join(runner.executedSQL, "\n")
	if !strings.Contains(restoredSQL, "MAX_USER_CONNECTIONS 20 MAX_STATEMENT_TIME 10") {
		t.Fatalf("expected automatic restoration of normal limits after 300s penalty, got:\n%s", restoredSQL)
	}
}

func TestMySQLOptionEscapingAndIdempotentWrite(t *testing.T) {
	tmp := t.TempDir()
	mysqlConf := filepath.Join(tmp, "mysql.conf")
	genCnf := filepath.Join(tmp, "mysql-client.cnf")

	_ = os.WriteFile(mysqlConf, []byte("user=da_admin\npasswd=p\\ass\"word\n"), 0o600)
	cli := NewCLIMySQLRunner(filepath.Join(tmp, "missing_my.cnf"), mysqlConf, genCnf)

	resolved, err := cli.ensureDefaultsFile()
	if err != nil || resolved != genCnf {
		t.Fatalf("ensureDefaultsFile: path=%q err=%v", resolved, err)
	}
	raw, err := os.ReadFile(genCnf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `password="p\\ass\"word"`) {
		t.Fatalf("expected escaped backslash and quote in mysql-client.cnf (R8), got:\n%s", string(raw))
	}
}

func TestBatchStderrClassificationChunkingProtectedDebianAndPenaltyRetry(t *testing.T) {
	// 1. N4: classifyMySQLBatchStderr ignores benign race ERROR 1094 (Unknown thread id) while catching real SQL errors
	if nonBenign, onlyBenign := classifyMySQLBatchStderr("ERROR 1094 (HY000) at line 1: Unknown thread id: 902\n"); len(nonBenign) != 0 || !onlyBenign {
		t.Fatalf("expected benign ERROR 1094 to be ignored (N4), got nonBenign=%v onlyBenign=%v", nonBenign, onlyBenign)
	}
	if nonBenign, onlyBenign := classifyMySQLBatchStderr("ERROR 1396 (HY000) at line 2: Operation ALTER USER failed for 'gone'@'localhost'\n"); len(nonBenign) == 0 || onlyBenign {
		t.Fatalf("expected ERROR 1396 to be surfaced as a batch failure (N4), got nonBenign=%v onlyBenign=%v", nonBenign, onlyBenign)
	}

	// 2. N20a: debian-sys-maint is strictly protected alongside root, mysql, and da_admin
	if !isProtectedDBUser("debian-sys-maint") || !isProtectedDBUser("da_admin") {
		t.Fatal("expected debian-sys-maint and da_admin to be protected MySQL accounts (N20a)")
	}

	// 3. N5: >200 ALTER USER statements are split into chunks of MaxAlterStatementsPerBatch (200)
	tmp := t.TempDir()
	passwdFile := filepath.Join(tmp, "passwd")
	daDir := filepath.Join(tmp, "users")
	_ = os.WriteFile(passwdFile, []byte("bigacct:x:1010:1010::/home/bigacct:/bin/bash\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(daDir, "bigacct"), 0o755)
	_ = os.WriteFile(filepath.Join(daDir, "bigacct", "user.conf"), []byte("usertype=user\npackage=vip\n"), 0o600)

	reg := dausers.NewRegistry(daDir, passwdFile)
	_ = reg.Reload()

	var manyUsers []string
	manyUsers = append(manyUsers, "debian-sys-maint\tlocalhost")
	for i := 0; i < 450; i++ {
		manyUsers = append(manyUsers, fmt.Sprintf("bigacct_db%d\tlocalhost", i))
	}

	runner := &mockSQLRunner{mysqlUsers: manyUsers}
	lim := config.DefaultLimits()
	lim.MySQLPenaltyEnabled = true
	lim.MySQLPenaltyThreshold = 1
	lim.MySQLPenaltyDurationSec = 60

	now := time.Unix(1700005000, 0)
	gov := NewGovernor(runner, reg, func(_ dausers.Account) (config.ResourceLimits, error) {
		return lim, nil
	}, nil, filepath.Join(tmp, "penalties.json"))
	gov.NowFunc = func() time.Time { return now }

	if err := gov.ApplyBatchUserLimits(context.Background(), map[string]config.ResourceLimits{"bigacct": lim}); err != nil {
		t.Fatalf("ApplyBatchUserLimits 450 DB users: %v", err)
	}
	if len(runner.executedSQL) != 3 {
		t.Fatalf("expected 450 ALTER USER statements to be chunked into 3 batches (200+200+50) (N5), got %d", len(runner.executedSQL))
	}

	// 4. N14: Penalty expiry & UnblockUser MUST retain penalty state if MariaDB ExecBatch fails, and clear ONLY after restore succeeds!
	mb := uint64(1024 * 1024)
	runner.processRows = []string{fmt.Sprintf("777\tbigacct_db0\tQuery\t1000\t%d\tSELECT 1", 400*mb)}
	if _, err := gov.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce trigger penalty: %v", err)
	}
	if _, _, penalized := gov.GetLiveUsage("bigacct"); !penalized {
		t.Fatal("expected bigacct to enter Penalty Box")
	}

	// Advance past expiry while MariaDB fails to execute ALTER USER
	runner.processRows = nil
	runner.failExecErr = errors.New("mariadb connection refused")
	now = now.Add(120 * time.Second)

	if err := gov.UnblockUser(context.Background(), "bigacct"); err == nil {
		t.Fatal("expected UnblockUser to return error when MariaDB restore fails (N14)")
	}
	if _, _, stillPenalized := gov.GetLiveUsage("bigacct"); !stillPenalized {
		t.Fatal("expected penalty to remain active when UnblockUser restore failed (N14)")
	}

	_, _ = gov.PollOnce(context.Background())
	if _, _, stillPenalized := gov.GetLiveUsage("bigacct"); !stillPenalized {
		t.Fatal("expected expirePenalties to retain penalty for retry when MariaDB restore failed (N14)")
	}

	// Restore MariaDB connectivity -> next PollOnce restores normal limits and clears penalty!
	runner.failExecErr = nil
	if _, err := gov.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce retry restore: %v", err)
	}
	if _, _, stillPenalized := gov.GetLiveUsage("bigacct"); stillPenalized {
		t.Fatal("expected penalty to lift once MariaDB restore succeeded (N14)")
	}
}
