package logger

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/ipc"
)

// Standard violation event type constants.
const (
	TypeCgroupOOMKill   = "cgroup_oom_kill"
	TypeMySQLHighMemory = "mysql_high_memory"
	TypeMySQLSlowQuery  = "mysql_slow_query"
	TypeMySQLPenaltyBox = "mysql_penalty_box"
)

const (
	DefaultLogPath    = "/var/log/da-resourced/violations.jsonl"
	DefaultMaxBytes   = 10 * 1024 * 1024 // 10 MB per file
	DefaultMaxBackups = 3
)

// ViolationLogger appends structured JSONL violation events with automatic size-based rotation.
type ViolationLogger struct {
	path       string
	maxBytes   int64
	maxBackups int
	mu         sync.Mutex
}

func NewViolationLogger(path string, maxBytes int64, maxBackups int) *ViolationLogger {
	if path == "" {
		path = DefaultLogPath
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxBackups <= 0 {
		maxBackups = DefaultMaxBackups
	}
	return &ViolationLogger{
		path:       path,
		maxBytes:   maxBytes,
		maxBackups: maxBackups,
	}
}

func (l *ViolationLogger) Path() string {
	return l.path
}

// Log appends a violation entry to the JSONL log and rotates files when maxBytes is exceeded.
func (l *ViolationLogger) Log(entry ipc.ViolationEntry) error {
	now := time.Now().UTC()
	if entry.TimestampUnix == 0 {
		entry.TimestampUnix = now.Unix()
	}
	if entry.TimestampISO == "" {
		entry.TimestampISO = time.Unix(entry.TimestampUnix, 0).UTC().Format(time.RFC3339)
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
		return err
	}

	if st, err := os.Stat(l.path); err == nil && st.Size()+int64(len(line)) > l.maxBytes {
		_ = l.rotateLocked()
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(line)
	return err
}

func (l *ViolationLogger) rotateLocked() error {
	oldest := fmt.Sprintf("%s.%d", l.path, l.maxBackups)
	_ = os.Remove(oldest)

	for i := l.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", l.path, i)
		dst := fmt.Sprintf("%s.%d", l.path, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	return os.Rename(l.path, l.path+".1")
}

// Query returns recent violation entries in newest-first order, optionally filtered by username and/or type.
func (l *ViolationLogger) Query(username, violationType string, limit int) ([]ipc.ViolationEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	username = strings.TrimSpace(username)
	violationType = strings.TrimSpace(violationType)

	l.mu.Lock()
	files := []string{l.path}
	for i := 1; i <= l.maxBackups; i++ {
		files = append(files, fmt.Sprintf("%s.%d", l.path, i))
	}
	l.mu.Unlock()

	var collected []ipc.ViolationEntry
	for _, filePath := range files {
		entries, err := readMatchingFileReverse(filePath, username, violationType, limit-len(collected))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return collected, err
		}
		collected = append(collected, entries...)
		if len(collected) >= limit {
			break
		}
	}
	return collected, nil
}

// CountSince counts violations for a specific user since unixCutoff (used for 24h User UI summary).
func (l *ViolationLogger) CountSince(username string, unixCutoff int64) (oomCount int, sqlKillCount int, penaltyCount int) {
	entries, err := l.Query(username, "", 1000)
	if err != nil {
		return 0, 0, 0
	}
	for _, e := range entries {
		if e.TimestampUnix < unixCutoff {
			continue
		}
		switch e.Type {
		case TypeCgroupOOMKill:
			oomCount++
		case TypeMySQLHighMemory, TypeMySQLSlowQuery:
			sqlKillCount++
		case TypeMySQLPenaltyBox:
			penaltyCount++
		}
	}
	return oomCount, sqlKillCount, penaltyCount
}

func readMatchingFileReverse(path, username, violationType string, needed int) ([]ipc.ViolationEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var allLines []string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			allLines = append(allLines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	out := make([]ipc.ViolationEntry, 0, minInt(needed, len(allLines)))
	for i := len(allLines) - 1; i >= 0 && len(out) < needed; i-- {
		var entry ipc.ViolationEntry
		if err := json.Unmarshal([]byte(allLines[i]), &entry); err != nil {
			continue
		}
		if username != "" && entry.Username != username {
			continue
		}
		if violationType != "" && entry.Type != violationType {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
