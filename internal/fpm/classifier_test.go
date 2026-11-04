package fpm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestClassifierMigratesCustomerPHPAndConcurrentScanRaceFree(t *testing.T) {
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

	uidTable := map[string]uint32{
		filepath.Join(procRoot, "100"): 0,
		filepath.Join(procRoot, "201"): 1005,
		filepath.Join(procRoot, "202"): 1006,
		filepath.Join(procRoot, "203"): 65534,
	}

	makeProc := func(pid, comm, cg string, startTicks uint64) {
		p := filepath.Join(procRoot, pid)
		_ = os.MkdirAll(p, 0o755)
		_ = os.WriteFile(filepath.Join(p, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(p, "cgroup"), []byte(cg+"\n"), 0o644)
		// /proc/<pid>/stat: pid (comm) state + 19 fields where field 22 (index 19 after ')') is starttime
		statLine := fmt.Sprintf("%s (%s) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 %d 1024 10\n", pid, comm, startTicks)
		_ = os.WriteFile(filepath.Join(p, "stat"), []byte(statLine), 0o644)
	}

	makeProc("100", "php-fpm82", "0::/system.slice/php-fpm82.service", 1000)
	makeProc("201", "php-fpm82", "0::/system.slice/php-fpm82.service", 2010)
	makeProc("202", "lsphp", "0::/system.slice/lsws.service", 2020)
	makeProc("203", "php-fpm82", "0::/system.slice/php-fpm82.service", 2030)

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
	if err != nil || moved2 != 0 {
		t.Fatalf("expected 0 migrations on second steady scan, got moved=%d err=%v", moved2, err)
	}

	// Simulate PID 201 respawning with a new starttime -> must re-classify instead of trusting stale cache (R10)
	makeProc("201", "php-fpm82", "0::/system.slice/php-fpm82.service", 9999)
	movedRespawn, err := cls.ScanOnce(context.Background(), 0)
	if err != nil || movedRespawn != 1 {
		t.Fatalf("expected respawned PID 201 with new starttime to be re-migrated, got moved=%d err=%v", movedRespawn, err)
	}

	// Concurrent stress test for R1: run 12 goroutines calling ScanOnce(0) and ScanOnce(1005) simultaneously
	var wg sync.WaitGroup
	for g := 0; g < 12; g++ {
		wg.Add(1)
		target := uint32(0)
		if g%2 == 1 {
			target = 1005
		}
		go func(uid uint32) {
			defer wg.Done()
			for iter := 0; iter < 25; iter++ {
				_, _ = cls.ScanOnce(context.Background(), uid)
			}
		}(target)
	}
	wg.Wait()
}

func TestSyncDAUserPHPConfPreservesFieldsAndConcurrentSafety(t *testing.T) {
	tmp := t.TempDir()
	userDir := filepath.Join(tmp, "vinahost")
	_ = os.MkdirAll(userDir, 0o755)
	confPath := filepath.Join(userDir, "user.conf")
	_ = os.WriteFile(confPath, []byte("usertype=user\npackage=gold\ndomain=example.com\n"), 0o600)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		children := 12 + i
		go func(c int) {
			defer wg.Done()
			lim := config.DefaultLimits()
			lim.PHPMaxChildren = c
			lim.PHPMemLimitMB = 512
			if err := SyncDAUserPHPConf(tmp, "vinahost", lim); err != nil {
				t.Errorf("SyncDAUserPHPConf: %v", err)
			}
		}(children)
	}
	wg.Wait()

	raw, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"domain=example.com", "DA_PHP_MAX_CHILDREN=", "DA_PHP_MEM_LIMIT=512M"} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected %q in user.conf, got:\n%s", want, s)
		}
	}
}
