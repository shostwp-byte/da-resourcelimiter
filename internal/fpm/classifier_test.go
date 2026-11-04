package fpm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shostwp-byte/da-resourcelimiter/internal/cgroup"
	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
)

type noopRunner struct {
	cgRoot string
}

func (n noopRunner) Run(_ context.Context, name string, args ...string) error {
	if name == "systemctl" && len(args) == 2 && args[0] == "start" {
		return os.MkdirAll(filepath.Join(n.cgRoot, "user.slice", args[1]), 0o755)
	}
	return nil
}

func TestClassifierMigratesCustomerPHPAndIgnoresRootAndNobody(t *testing.T) {
	tmp := t.TempDir()
	procRoot := filepath.Join(tmp, "proc")
	cgRoot := filepath.Join(tmp, "cgroup")
	systemdDir := filepath.Join(tmp, "systemd")
	passwdFile := filepath.Join(tmp, "passwd")
	daDir := filepath.Join(tmp, "da_users")

	passwd := "" +
		"root:x:0:0:root:/root:/bin/bash\n" +
		"vinahost:x:1005:1005:VinaHost:/home/vinahost:/bin/bash\n" +
		"olsuser:x:1006:1006:OLSUser:/home/olsuser:/bin/bash\n" +
		"nobody:x:65534:65534:Nobody:/:/sbin/nologin\n"
	if err := os.WriteFile(passwdFile, []byte(passwd), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, u := range []string{"vinahost", "olsuser"} {
		d := filepath.Join(daDir, u)
		_ = os.MkdirAll(d, 0o755)
		_ = os.WriteFile(filepath.Join(d, "user.conf"), []byte("usertype=user\npackage=gold\n"), 0o600)
	}

	reg := dausers.NewRegistry(daDir, passwdFile)
	if err := reg.Reload(); err != nil {
		t.Fatalf("Reload registry: %v", err)
	}

	cgMgr := cgroup.NewManager(systemdDir, cgRoot, noopRunner{cgRoot: cgRoot})

	// Create mock /proc processes:
	// PID 100: php-fpm master (UID 0) -> must NOT move
	// PID 201: php-fpm worker (UID 1005) in system.slice -> MUST move to user-1005.slice/da-php.scope
	// PID 202: lsphp worker (UID 1006) in system.slice -> MUST move to user-1006.slice/da-php.scope
	// PID 203: php-fpm worker (UID 65534 nobody) -> must NOT move
	uidTable := map[string]uint32{
		filepath.Join(procRoot, "100"): 0,
		filepath.Join(procRoot, "201"): 1005,
		filepath.Join(procRoot, "202"): 1006,
		filepath.Join(procRoot, "203"): 65534,
	}

	makeProc := func(pid, comm, cg string) {
		p := filepath.Join(procRoot, pid)
		_ = os.MkdirAll(p, 0o755)
		_ = os.WriteFile(filepath.Join(p, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(p, "cgroup"), []byte(cg+"\n"), 0o644)
	}

	makeProc("100", "php-fpm82", "0::/system.slice/php-fpm82.service")
	makeProc("201", "php-fpm82", "0::/system.slice/php-fpm82.service")
	makeProc("202", "lsphp", "0::/system.slice/lsws.service")
	makeProc("203", "php-fpm82", "0::/system.slice/php-fpm82.service")

	cls := NewClassifier(procRoot, reg, cgMgr, nil)
	cls.ReadUID = func(procPIDPath string) (uint32, error) {
		return uidTable[procPIDPath], nil
	}

	moved, err := cls.ScanOnce(context.Background(), 0)
	if err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	if moved != 2 {
		t.Fatalf("expected exactly 2 customer PHP workers migrated, got %d", moved)
	}

	procs1005, err := os.ReadFile(filepath.Join(cgMgr.PHPScopeDir(1005), "cgroup.procs"))
	if err != nil || strings.TrimSpace(string(procs1005)) != "201" {
		t.Fatalf("expected PID 201 in user-1005 da-php.scope, got %q (err=%v)", string(procs1005), err)
	}

	procs1006, err := os.ReadFile(filepath.Join(cgMgr.PHPScopeDir(1006), "cgroup.procs"))
	if err != nil || strings.TrimSpace(string(procs1006)) != "202" {
		t.Fatalf("expected PID 202 in user-1006 da-php.scope, got %q (err=%v)", string(procs1006), err)
	}

	// Second scan must skip already cached/classified PIDs
	moved2, err := cls.ScanOnce(context.Background(), 0)
	if err != nil {
		t.Fatalf("ScanOnce #2: %v", err)
	}
	if moved2 != 0 {
		t.Fatalf("expected 0 migrations on second steady scan, got %d", moved2)
	}
}

func TestSyncDAUserPHPConfPreservesFields(t *testing.T) {
	tmp := t.TempDir()
	userDir := filepath.Join(tmp, "vinahost")
	_ = os.MkdirAll(userDir, 0o755)
	confPath := filepath.Join(userDir, "user.conf")
	_ = os.WriteFile(confPath, []byte("usertype=user\npackage=gold\ndomain=example.com\n"), 0o600)

	limits := config.DefaultLimits()
	limits.PHPMaxChildren = 18
	limits.PHPMemLimitMB = 512

	if err := SyncDAUserPHPConf(tmp, "vinahost", limits); err != nil {
		t.Fatalf("SyncDAUserPHPConf: %v", err)
	}

	raw, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"domain=example.com", "DA_PHP_MAX_CHILDREN=18", "DA_PHP_MEM_LIMIT=512M"} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected %q in user.conf, got:\n%s", want, s)
		}
	}
}
