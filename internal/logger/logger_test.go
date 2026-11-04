package logger

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/ipc"
)

func TestViolationLoggerRotationAndQuery(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "violations.jsonl")

	// Tiny maxBytes (450 bytes) to trigger automatic file rotation
	vlog := NewViolationLogger(logPath, 450, 2)

	baseTS := time.Now().Add(-1 * time.Hour).Unix()
	for i := 1; i <= 8; i++ {
		user := "vinahost"
		vtype := TypeMySQLHighMemory
		if i%2 == 0 {
			user = "alice"
			vtype = TypeMySQLSlowQuery
		}
		err := vlog.Log(ipc.ViolationEntry{
			TimestampUnix: baseTS + int64(i),
			Username:      user,
			Type:          vtype,
			MemoryMB:      float64(256 + i),
			Detail:        fmt.Sprintf("SELECT * FROM big_table WHERE id=%d", i),
		})
		if err != nil {
			t.Fatalf("Log #%d: %v", i, err)
		}
	}

	// Query filtered by user "vinahost" -> newest first
	res, err := vlog.Query("vinahost", "", 10)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected logged entries for vinahost across rotated files")
	}
	if res[0].TimestampUnix != baseTS+7 {
		t.Fatalf("expected newest vinahost entry (i=7) first, got ts=%d", res[0].TimestampUnix)
	}
	for _, r := range res {
		if r.Username != "vinahost" {
			t.Fatalf("unexpected username in filtered query: %+v", r)
		}
	}

	_, sqlKills, _ := vlog.CountSince("vinahost", baseTS)
	if sqlKills == 0 {
		t.Fatal("expected positive sqlKills count in CountSince")
	}
}

func TestMultiChunkReverseTailReadAndTimestampCutoff(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "large.jsonl")
	vlog := NewViolationLogger(logPath, 5*1024*1024, 1)

	padding := strings.Repeat("X", 400)
	baseTS := int64(1700000000)
	// Write ~120 KB (> 3 x 32 KB reverse chunks)
	for i := 1; i <= 240; i++ {
		if err := vlog.Log(ipc.ViolationEntry{
			TimestampUnix: baseTS + int64(i),
			Username:      "alice",
			Type:          TypeCgroupOOMKill,
			Detail:        fmt.Sprintf("entry-%d-%s", i, padding),
		}); err != nil {
			t.Fatalf("Log #%d: %v", i, err)
		}
	}

	top5, err := vlog.Query("alice", "", 5)
	if err != nil {
		t.Fatalf("Query top5: %v", err)
	}
	if len(top5) != 5 || top5[0].TimestampUnix != baseTS+240 || top5[4].TimestampUnix != baseTS+236 {
		t.Fatalf("unexpected reverse chunked top5: first=%+v last=%+v", top5[0], top5[len(top5)-1])
	}

	oomCount, _, _ := vlog.CountSince("alice", baseTS+201)
	if oomCount != 40 {
		t.Fatalf("expected 40 entries with ts >= baseTS+201, got %d", oomCount)
	}
}
