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

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
)

const (
	DefaultDAMyCnf     = "/usr/local/directadmin/conf/my.cnf"
	DefaultDAMySQLConf = "/usr/local/directadmin/conf/mysql.conf"
	DefaultRuntimeCnf  = "/run/da-resourced/mysql-client.cnf"
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
		MySQLBin:    "mysql",
		DAMyCnfPath: daMyCnfPath,
		DAMySQLConf: daMySQLConf,
		RuntimeCnf:  runtimeCnf,
	}
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
	fmt.Fprintf(&b, "user=%s\n", user)
	fmt.Fprintf(&b, "password=\"%s\"\n", strings.ReplaceAll(pass, `"`, `\"`))
	if sock := strings.TrimSpace(kv["socket"]); sock != "" {
		fmt.Fprintf(&b, "socket=%s\n", sock)
	} else if host := strings.TrimSpace(kv["host"]); host != "" && host != "localhost" {
		fmt.Fprintf(&b, "host=%s\n", host)
		if port := strings.TrimSpace(kv["port"]); port != "" {
			fmt.Fprintf(&b, "port=%s\n", port)
		}
	}

	if err := os.MkdirAll(filepath.Dir(c.RuntimeCnf), 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(c.RuntimeCnf), err)
	}
	tmp := c.RuntimeCnf + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, c.RuntimeCnf); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	c.preparedExtra = c.RuntimeCnf
	return c.preparedExtra, nil
}

func (c *CLIMySQLRunner) QueryTSV(ctx context.Context, sql string) ([]string, error) {
	extraFile, err := c.ensureDefaultsFile()
	if err != nil {
		return nil, err
	}

	args := []string{
		"--defaults-extra-file=" + extraFile,
		"--connect-timeout=3",
		"--batch",
		"--skip-column-names",
	}
	cmd := exec.CommandContext(ctx, c.MySQLBin, args...)
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
