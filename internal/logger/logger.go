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
	countCacheTTL     = 3 * time.Second
)

type countCacheKey struct {
	username string
	bucket   int64 // unixCutoff rounded to 3-second bucket
}

type countCacheEntry struct {
	oomCount     int
	sqlKillCount int
	penaltyCount int
	expiresAt    time.Time
}

// ViolationLogger appends structured JSONL violation events with automatic size-based rotation.
type ViolationLogger struct {
	path       string
	maxBytes   int64
	maxBackups int
	mu         sync.Mutex

	countMu    sync.Mutex
	countCache map[countCacheKey]countCacheEntry
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
		countCache: make(map[countCacheKey]countCacheEntry),
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
	if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
		l.mu.Unlock()
		return err
	}

	if st, err := os.Stat(l.path); err == nil && st.Size()+int64(len(line)) > l.maxBytes {
		_ = l.rotateLocked()
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		l.mu.Unlock()
		return err
	}
	_, writeErr := f.Write(line)
	_ = f.Close()
	l.mu.Unlock()

	if writeErr == nil && entry.Username != "" {
		l.invalidateCountCache(entry.Username)
	}
	return writeErr
}

func (l *ViolationLogger) invalidateCountCache(username string) {
	l.countMu.Lock()
	for k := range l.countCache {
		if k.username == username {
			delete(l.countCache, k)
		}
	}
	l.countMu.Unlock()
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

func (l *ViolationLogger) openSnapshotFiles() []*os.File {
	l.mu.Lock()
	defer l.mu.Unlock()

	paths := make([]string, 0, l.maxBackups+1)
	paths = append(paths, l.path)
	for i := 1; i <= l.maxBackups; i++ {
		paths = append(paths, fmt.Sprintf("%s.%d", l.path, i))
	}

	opened := make([]*os.File, 0, len(paths))
	for _, p := range paths {
		if f, err := os.Open(p); err == nil {
			opened = append(opened, f)
		}
	}
	return opened
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
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

	// Open all log file descriptors under l.mu so concurrent rotation cannot cause duplicate inode reads (N16).
	files := l.openSnapshotFiles()
	defer closeFiles(files)

	var collected []ipc.ViolationEntry
	for _, f := range files {
		entries, reachedCutoff, err := readMatchingOpenFileReverseChunked(f, username, violationType, limit-len(collected), minTimestampUnix)
		if err != nil {
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
	username = strings.TrimSpace(username)
	now := time.Now()
	key := countCacheKey{
		username: username,
		bucket:   unixCutoff / 3,
	}

	l.countMu.Lock()
	if l.countCache != nil {
		if ent, ok := l.countCache[key]; ok && now.Before(ent.expiresAt) {
			l.countMu.Unlock()
			return ent.oomCount, ent.sqlKillCount, ent.penaltyCount
		}
	}
	l.countMu.Unlock()

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

	l.countMu.Lock()
	if l.countCache == nil {
		l.countCache = make(map[countCacheKey]countCacheEntry)
	} else if len(l.countCache) > 512 {
		for k, v := range l.countCache {
			if !now.Before(v.expiresAt) {
				delete(l.countCache, k)
			}
		}
	}
	l.countCache[key] = countCacheEntry{
		oomCount:     oomCount,
		sqlKillCount: sqlKillCount,
		penaltyCount: penaltyCount,
		expiresAt:    now.Add(countCacheTTL),
	}
	l.countMu.Unlock()

	return oomCount, sqlKillCount, penaltyCount
}

var tsUnixFieldPrefix = []byte(`"timestamp_unix":`)

// extractTimestampUnixFast parses "timestamp_unix":<int64> directly from raw JSONL bytes without heap allocation.
func extractTimestampUnixFast(line []byte) (int64, bool) {
	idx := bytes.Index(line, tsUnixFieldPrefix)
	if idx < 0 {
		return 0, false
	}
	rest := line[idx+len(tsUnixFieldPrefix):]
	for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	if len(rest) == 0 || rest[0] < '0' || rest[0] > '9' {
		return 0, false
	}
	var val int64
	for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		val = val*10 + int64(rest[0]-'0')
		rest = rest[1:]
	}
	return val, val > 0
}

// readMatchingOpenFileReverseChunked reads an open JSONL file backwards from EOF in 32 KB blocks so
// large 10 MB log files are never buffered wholly in memory (S5, N16).
func readMatchingOpenFileReverseChunked(f *os.File, username, violationType string, needed int, minTimestampUnix int64) ([]ipc.ViolationEntry, bool, error) {
	if needed <= 0 {
		return nil, false, nil
	}

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
		// Check minTimestampUnix BEFORE filtering by username so 24h scans stop immediately at the cutoff
		// even when the queried user has zero violations in multi-file rotated logs (N16).
		if minTimestampUnix > 0 {
			if ts, ok := extractTimestampUnixFast(trimmed); ok && ts < minTimestampUnix {
				reachedCutoff = true
				return true
			}
		}
		// Fast substring pre-check before full JSON unmarshal when filtering by a specific username
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
