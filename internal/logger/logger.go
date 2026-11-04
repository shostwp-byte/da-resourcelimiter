package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	reverseChunkBytes = 32 * 1024 // Read 32 KB blocks from end of file instead of loading full 10 MB into RAM (S5)
	maxLineSafetyCap  = 1024 * 1024
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
	return l.querySince(username, violationType, limit, 0)
}

func (l *ViolationLogger) querySince(username, violationType string, limit int, minTimestampUnix int64) ([]ipc.ViolationEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	username = strings.TrimSpace(username)
	violationType = strings.TrimSpace(violationType)

	l.mu.Lock()
	files := make([]string, 0, l.maxBackups+1)
	files = append(files, l.path)
	for i := 1; i <= l.maxBackups; i++ {
		files = append(files, fmt.Sprintf("%s.%d", l.path, i))
	}
	l.mu.Unlock()

	var collected []ipc.ViolationEntry
	for _, filePath := range files {
		entries, reachedCutoff, err := readMatchingFileReverseChunked(filePath, username, violationType, limit-len(collected), minTimestampUnix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return collected, err
		}
		collected = append(collected, entries...)
		if len(collected) >= limit || reachedCutoff {
			break
		}
	}
	return collected, nil
}

// CountSince counts violations for a specific user since unixCutoff (used for 24h User UI summary).
func (l *ViolationLogger) CountSince(username string, unixCutoff int64) (oomCount int, sqlKillCount int, penaltyCount int) {
	entries, err := l.querySince(username, "", 1000, unixCutoff)
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

// readMatchingFileReverseChunked reads JSONL files backwards from EOF in 32 KB blocks so
// large 10 MB log files are never buffered wholly in memory (S5).
func readMatchingFileReverseChunked(path, username, violationType string, needed int, minTimestampUnix int64) ([]ipc.ViolationEntry, bool, error) {
	if needed <= 0 {
		return nil, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	pos := st.Size()
	if pos == 0 {
		return nil, false, nil
	}

	var (
		out           []ipc.ViolationEntry
		trailing      []byte
		reachedCutoff bool
		buf           = make([]byte, reverseChunkBytes)
	)

	processLine := func(rawLine []byte) bool {
		trimmed := bytes.TrimSpace(rawLine)
		if len(trimmed) == 0 {
			return false
		}
		// Fast substring pre-check before JSON unmarshal when filtering by a specific username
		if username != "" && !bytes.Contains(trimmed, []byte(username)) {
			return false
		}
		var entry ipc.ViolationEntry
		if err := json.Unmarshal(trimmed, &entry); err != nil {
			return false
		}
		if minTimestampUnix > 0 && entry.TimestampUnix > 0 && entry.TimestampUnix < minTimestampUnix {
			reachedCutoff = true
			return true
		}
		if username != "" && entry.Username != username {
			return false
		}
		if violationType != "" && entry.Type != violationType {
			return false
		}
		out = append(out, entry)
		return len(out) >= needed
	}

	for pos > 0 && len(out) < needed && !reachedCutoff {
		readSize := int64(reverseChunkBytes)
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize

		n, readErr := f.ReadAt(buf[:readSize], pos)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return out, reachedCutoff, readErr
		}
		chunk := buf[:n]

		combined := make([]byte, len(chunk)+len(trailing))
		copy(combined, chunk)
		copy(combined[len(chunk):], trailing)

		for {
			nl := bytes.LastIndexByte(combined, '\n')
			if nl < 0 {
				break
			}
			line := combined[nl+1:]
			combined = combined[:nl]
			if processLine(line) {
				return out, reachedCutoff, nil
			}
		}

		if len(combined) > maxLineSafetyCap {
			// Discard corrupted oversized single line without newline
			trailing = nil
		} else {
			trailing = combined
		}
	}

	if len(trailing) > 0 && len(out) < needed && !reachedCutoff {
		_ = processLine(trailing)
	}
	return out, reachedCutoff, nil
}
