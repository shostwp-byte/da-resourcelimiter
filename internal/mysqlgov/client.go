package mysqlgov

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
)

const (
	DefaultDAMyCnf      = "/usr/local/directadmin/conf/my.cnf"
	DefaultDAMySQLConf  = "/usr/local/directadmin/conf/mysql.conf"
	DefaultRuntimeCnf   = "/run/da-resourced/mysql-client.cnf"
	DefaultQueryTimeout = 5 * time.Second
)

// SQLRunner abstracts SQL query and batch execution so MariaDB Governor logic is 100% unit-testable.
type SQLRunner interface {
	QueryTSV(ctx context.Context, sql string) ([]string, error)
	ExecBatch(ctx context.Context, sql string) error
}

// CLIMySQLRunner executes SQL via the local `mysql` binary using a root-only 0600 defaults-extra-file
// and stdin piping, ensuring neither credentials nor SQL statements ever appear in /proc/<pid>/cmdline.
type CLIMySQLRunner struct {
	MySQLBin      string
	DAMyCnfPath   string
	DAMySQLConf   string
	RuntimeCnf    string
	QueryTimeout  time.Duration
	mu            sync.Mutex
	preparedExtra string
}

func NewCLIMySQLRunner(daMyCnfPath, daMySQLConf, runtimeCnf string) *CLIMySQLRunner {
	if daMyCnfPath == "" {
		daMyCnfPath = DefaultDAMyCnf
	}
	if daMySQLConf == "" {
		daMySQLConf = DefaultDAMySQLConf
	}
	if runtimeCnf == "" {
		runtimeCnf = DefaultRuntimeCnf
	}
	return &CLIMySQLRunner{
		MySQLBin:     "mysql",
		DAMyCnfPath:  daMyCnfPath,
		DAMySQLConf:  daMySQLConf,
		RuntimeCnf:   runtimeCnf,
		QueryTimeout: DefaultQueryTimeout,
	}
}

// escapeMyCnfDoubleQuoted escapes backslashes BEFORE double quotes and strips newlines
// so passwords containing '\' or '"' in mysql.conf never corrupt the option file (R8).
func escapeMyCnfDoubleQuoted(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func (c *CLIMySQLRunner) ensureDefaultsFile() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Prefer DirectAdmin's native my.cnf if it exists on disk
	if st, err := os.Stat(c.DAMyCnfPath); err == nil && !st.IsDir() {
		c.preparedExtra = c.DAMyCnfPath
		return c.preparedExtra, nil
	}

	kv, err := config.ParseKeyValueFile(c.DAMySQLConf)
	if err != nil {
		return "", fmt.Errorf("read DirectAdmin mysql credentials (%s): %w", c.DAMySQLConf, err)
	}
	user := strings.TrimSpace(kv["user"])
	pass := strings.TrimSpace(kv["passwd"])
	if user == "" {
		return "", errors.New("missing 'user' in DirectAdmin mysql.conf")
	}

	var b strings.Builder
	b.WriteString("[client]\n")
	fmt.Fprintf(&b, "user=\"%s\"\n", escapeMyCnfDoubleQuoted(user))
	fmt.Fprintf(&b, "password=\"%s\"\n", escapeMyCnfDoubleQuoted(pass))
	if sock := strings.TrimSpace(kv["socket"]); sock != "" {
		fmt.Fprintf(&b, "socket=\"%s\"\n", escapeMyCnfDoubleQuoted(sock))
	} else if host := strings.TrimSpace(kv["host"]); host != "" && host != "localhost" {
		fmt.Fprintf(&b, "host=\"%s\"\n", escapeMyCnfDoubleQuoted(host))
		if port := strings.TrimSpace(kv["port"]); port != "" {
			fmt.Fprintf(&b, "port=\"%s\"\n", escapeMyCnfDoubleQuoted(port))
		}
	}

	desired := []byte(b.String())
	if existing, readErr := os.ReadFile(c.RuntimeCnf); readErr == nil && bytes.Equal(existing, desired) {
		_ = os.Chmod(c.RuntimeCnf, 0o600)
		c.preparedExtra = c.RuntimeCnf
		return c.preparedExtra, nil
	}

	runtimeDir := filepath.Dir(c.RuntimeCnf)
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", runtimeDir, err)
	}
	tmp, err := os.CreateTemp(runtimeDir, ".mysql-client-*.cnf")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(desired); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, c.RuntimeCnf); err != nil {
		return "", err
	}
	cleanupTmp = false
	c.preparedExtra = c.RuntimeCnf
	return c.preparedExtra, nil
}

func (c *CLIMySQLRunner) QueryTSV(ctx context.Context, sql string) ([]string, error) {
	extraFile, err := c.ensureDefaultsFile()
	if err != nil {
		return nil, err
	}

	timeout := c.QueryTimeout
	if timeout <= 0 {
		timeout = DefaultQueryTimeout
	}
	qCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"--defaults-extra-file=" + extraFile,
		"--connect-timeout=3",
		"--batch",
		"--skip-column-names",
	}
	cmd := exec.CommandContext(qCtx, c.MySQLBin, args...)
	cmd.Stdin = strings.NewReader(sql)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mysql query failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}

	raw := strings.TrimRight(stdout.String(), "\r\n")
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

func (c *CLIMySQLRunner) ExecBatch(ctx context.Context, sql string) error {
	if strings.TrimSpace(sql) == "" {
		return nil
	}
	_, err := c.QueryTSV(ctx, sql)
	return err
}
