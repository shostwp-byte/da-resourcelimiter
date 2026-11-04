package mysqlgov

import (
	"context"
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
}

func (m *mockSQLRunner) QueryTSV(_ context.Context, sql string) ([]string, error) {
	if strings.Contains(sql, "FROM information_schema.PROCESSLIST") {
		return m.processRows, nil
	}
	if strings.Contains(sql, "FROM mysql.user") {
		return m.mysqlUsers, nil
	}
	return nil, nil
}

func (m *mockSQLRunner) ExecBatch(_ context.Context, sql string) error {
	m.executedSQL = append(m.executedSQL, sql)
	return nil
}

func TestGovernorMemoryFloodKillAndPenaltyBoxLifecycle(t *testing.T) {
	tmp := t.TempDir()
	passwdFile := filepath.Join(tmp, "passwd")
	daDir := filepath.Join(tmp, "users")
	logPath := filepath.Join(tmp, "violations.jsonl")
	penaltyPath := filepath.Join(tmp, "penalty_state.json")

	_ = os.WriteFile(passwdFile, []byte("vina_host:x:1005:1005::/home/vina_host:/bin/bash\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(daDir, "vina_host"), 0o755)
	_ = os.WriteFile(filepath.Join(daDir, "vina_host", "user.conf"), []byte("usertype=user\npackage=gold\n"), 0o600)

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
	limits.MySQLPenaltyThreshold = 3 // Trigger penalty after 3 kills in window
	limits.MySQLPenaltyWindowSec = 60
	limits.MySQLPenaltyDurationSec = 300
	limits.MySQLPenaltyConn = 2
	limits.MySQLPenaltyTimeSec = 2

	runner := &mockSQLRunner{
		mysqlUsers: []string{"vina_host_wp\tlocalhost"},
	}
	vlog := logger.NewViolationLogger(logPath, 1024*1024, 2)

	now := time.Unix(1700000000, 0)
	gov := NewGovernor(runner, reg, func(_ dausers.Account) (config.ResourceLimits, error) {
		return limits, nil
	}, vlog, penaltyPath)
	gov.NowFunc = func() time.Time { return now }

	// Simulate TC-05: 2 queries totaling 330 MB (> 256 MB limit); PID 902 is heaviest (200 MB)
	mb := uint64(1024 * 1024)
	runner.processRows = []string{
		fmt.Sprintf("901\tvina_host_wp\tQuery\t1200\t%d\tSELECT * FROM wp_posts", 130*mb),
		fmt.Sprintf("902\tvina_host_wp\tQuery\t2500\t%d\tSELECT * FROM wp_postmeta JOIN wp_options", 200*mb),
		"903\tvina_host_wp\tSleep\t5000\t0\tNULL",
	}

	// Poll 3 times across 10 seconds to trigger 3 kills -> automatic Penalty Box
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

	// Verify KILL QUERY 902 and Penalty Box ALTER USER were executed
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

	// Simulate daemon restart: a fresh Governor instance must reload penalty_state.json
	govRestarted := NewGovernor(runner, reg, func(_ dausers.Account) (config.ResourceLimits, error) {
		return limits, nil
	}, vlog, penaltyPath)
	govRestarted.NowFunc = func() time.Time { return now }

	if _, _, stillPenalized := govRestarted.GetLiveUsage("vina_host"); !stillPenalized {
		t.Fatal("expected penalty state to survive daemon restart")
	}

	// Advance clock past 300s penalty duration -> next PollOnce must automatically restore normal limits (20 conns, 10s)
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
