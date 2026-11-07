package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveUserLimitsHierarchy(t *testing.T) {
	tmp := t.TempDir()
	store := NewStore(tmp, filepath.Join(tmp, "updater.conf"))

	def := DefaultLimits()
	def.CPUQuota = 100
	def.MemHighMB = 768
	def.MemMaxMB = 1024
	if err := store.SaveDefaultLimits(def); err != nil {
		t.Fatalf("SaveDefaultLimits: %v", err)
	}

	pkg := def
	pkg.CPUQuota = 200
	pkg.MemHighMB = 1536
	pkg.MemMaxMB = 2048
	if err := store.SavePackageLimits("gold", pkg); err != nil {
		t.Fatalf("SavePackageLimits: %v", err)
	}

	// User without override inherits package limits
	resolved, err := store.ResolveUserLimits("vinahost", "gold")
	if err != nil {
		t.Fatalf("ResolveUserLimits: %v", err)
	}
	if resolved.CPUQuota != 200 || resolved.MemMaxMB != 2048 || resolved.Package != "gold" {
		t.Fatalf("unexpected package inheritance: %+v", resolved)
	}

	// User with custom override overrides specific fields
	overrideContent := "CUSTOM_OVERRIDE=yes\nCPU_QUOTA=400\nMEM_HIGH_MB=3072\nMEM_MAX_MB=4096\n"
	userPath, err := store.UserConfPath("vinahost")
	if err != nil {
		t.Fatalf("UserConfPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(userPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(overrideContent), 0o640); err != nil {
		t.Fatal(err)
	}

	resolvedOverride, err := store.ResolveUserLimits("vinahost", "gold")
	if err != nil {
		t.Fatalf("ResolveUserLimits with override: %v", err)
	}
	if !resolvedOverride.CustomOverride || resolvedOverride.CPUQuota != 400 || resolvedOverride.MemMaxMB != 4096 {
		t.Fatalf("unexpected user override result: %+v", resolvedOverride)
	}
}

func TestPenaltyValidationAndFileLoadGuard(t *testing.T) {
	lim := DefaultLimits()
	lim.MySQLPenaltyConn = 0
	if err := lim.Validate(); err == nil {
		t.Fatal("expected Validate() to reject MYSQL_PENALTY_CONN=0 (which would mean unlimited in MariaDB)")
	}

	lim = DefaultLimits()
	lim.MySQLPenaltyThreshold = 0
	if err := lim.Validate(); err == nil {
		t.Fatal("expected Validate() to reject MYSQL_PENALTY_THRESHOLD=0")
	}

	lim = DefaultLimits()
	lim.MySQLPenaltyTimeSec = 0
	if err := lim.Validate(); err == nil {
		t.Fatal("expected Validate() to reject MYSQL_PENALTY_TIME_SEC=0")
	}

	// Verify ResolveUserLimits also validates hand-edited files on disk (R2)
	tmp := t.TempDir()
	store := NewStore(tmp, "")
	badConf := "ENABLED=yes\nMYSQL_PENALTY_CONN=0\n"
	if err := os.WriteFile(store.DefaultConfPath(), []byte(badConf), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveUserLimits("alice", ""); err == nil {
		t.Fatal("expected ResolveUserLimits to reject MYSQL_PENALTY_CONN=0 from hand-edited default.conf")
	}
}

func TestMigrateDefaultKeysPreservesExistingValues(t *testing.T) {
	tmp := t.TempDir()
	store := NewStore(tmp, "")

	legacy := "ENABLED=yes\nCPU_QUOTA=250\nMEM_HIGH_MB=2048\nMEM_MAX_MB=3072\n"
	if err := os.WriteFile(store.DefaultConfPath(), []byte(legacy), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := store.MigrateDefaultKeys(); err != nil {
		t.Fatalf("MigrateDefaultKeys: %v", err)
	}

	resolved, err := store.ResolveUserLimits("alice", "")
	if err != nil {
		t.Fatalf("ResolveUserLimits: %v", err)
	}
	if resolved.CPUQuota != 250 || resolved.MemMaxMB != 3072 {
		t.Fatalf("migration overwrote existing custom values: %+v", resolved)
	}

	raw, err := os.ReadFile(store.DefaultConfPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "MYSQL_PENALTY_DURATION_SEC=") {
		t.Fatalf("expected missing keys to be appended, got:\n%s", string(raw))
	}
}

func TestUpdaterConfigRepoPinningAndValidation(t *testing.T) {
	tmp := t.TempDir()
	updaterPath := filepath.Join(tmp, "etc", "updater.conf")
	store := NewStore(tmp, updaterPath)

	cfg, err := store.LoadUpdaterConfig()
	if err != nil {
		t.Fatalf("LoadUpdaterConfig default: %v", err)
	}
	if cfg.GitHubRepo != "shostwp-byte/da-resourcelimiter" {
		t.Fatalf("unexpected default repo: %s", cfg.GitHubRepo)
	}

	cfg.GitHubToken = "github_pat_1234567890abcdef"
	cfg.UpdateChannel = "beta"
	if err := store.SaveUpdaterConfig(cfg); err != nil {
		t.Fatalf("SaveUpdaterConfig: %v", err)
	}

	loaded, err := store.LoadUpdaterConfig()
	if err != nil {
		t.Fatalf("LoadUpdaterConfig: %v", err)
	}
	if loaded.GitHubToken != cfg.GitHubToken || loaded.UpdateChannel != "beta" {
		t.Fatalf("unexpected loaded updater config: %+v", loaded)
	}
	if masked := loaded.MaskedToken(); masked != "gith****...cdef" {
		t.Fatalf("unexpected masked token: %s", masked)
	}

	// Repo pinning (S1): without ALLOW_CUSTOM_REPO=yes, GITHUB_REPO in file is ignored and pinned to official repo
	_ = os.WriteFile(updaterPath, []byte("GITHUB_REPO=attacker/evilrepo\nUPDATE_CHANNEL=stable\n"), 0o600)
	pinnedLoaded, err := store.LoadUpdaterConfig()
	if err != nil {
		t.Fatalf("LoadUpdaterConfig pinned: %v", err)
	}
	if pinnedLoaded.GitHubRepo != "shostwp-byte/da-resourcelimiter" {
		t.Fatalf("expected repo to stay pinned to official repo, got %q", pinnedLoaded.GitHubRepo)
	}

	// ValidateGitHubRepo and ValidateReleaseTag (S6)
	for _, badRepo := range []string{"", "onlyowner", "a/b/c", "a/b?foo=1", "../evil/repo", "a/%2e%2e"} {
		if err := ValidateGitHubRepo(badRepo); err == nil {
			t.Errorf("expected ValidateGitHubRepo(%q) to fail", badRepo)
		}
	}
	for _, goodTag := range []string{"v1.0.0", "v1.0.4.1", "v1.2.0-beta.1", "1.0.4.1"} {
		if err := ValidateReleaseTag(goodTag); err != nil {
			t.Errorf("expected ValidateReleaseTag(%q) to pass, got %v", goodTag, err)
		}
	}
	for _, badTag := range []string{"", "..", "v1.0;rm -rf /", "v1.0/../../etc", "v1.0?x=1"} {
		if err := ValidateReleaseTag(badTag); err == nil {
			t.Errorf("expected ValidateReleaseTag(%q) to fail", badTag)
		}
	}
}

func TestIdentifierValidationBlocksTraversal(t *testing.T) {
	for _, bad := range []string{"", "../root", "user/evil", "user;rm -rf", "-bad"} {
		if err := ValidateIdentifier(bad); err == nil {
			t.Errorf("expected error for invalid identifier %q", bad)
		}
	}
}

func TestClampPenaltyUpperBoundsDisabledSaveAndLargeKVLine(t *testing.T) {
	tmp := t.TempDir()
	store := NewStore(tmp, "")

	// 1. N3: Legacy/strict package with MYSQL_MAX_CONNECTIONS=1 while default.conf has MYSQL_PENALTY_CONN=2
	// must clamp penalty ceiling down to 1 instead of breaking ResolveUserLimits / ApplyUser.
	if err := os.WriteFile(store.DefaultConfPath(), []byte("ENABLED=yes\nMYSQL_MAX_CONNECTIONS=1\nMYSQL_PENALTY_CONN=2\nMYSQL_MAX_STATEMENT_TIME_SEC=1\nMYSQL_PENALTY_TIME_SEC=2\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.ResolveUserLimits("alice", "")
	if err != nil {
		t.Fatalf("expected ClampPenaltyUpperBounds to resolve cleanly (N3), got err=%v", err)
	}
	if resolved.MySQLPenaltyConn != 1 || resolved.MySQLPenaltyTimeSec != 1 {
		t.Fatalf("expected penalty conn/time clamped to 1/1, got conn=%d time=%d", resolved.MySQLPenaltyConn, resolved.MySQLPenaltyTimeSec)
	}

	if err := store.MigrateDefaultKeys(); err != nil {
		t.Fatalf("MigrateDefaultKeys on legacy low-ceiling default.conf: %v", err)
	}

	// 2. N3: Saving ENABLED=no must succeed even if MySQL fields on the form are 0 or unconfigured.
	disabled := ResourceLimits{
		Enabled:             false,
		MySQLMaxConnections: 0,
		MySQLPenaltyConn:    5,
	}
	if err := store.SaveUserLimits("alice", disabled); err != nil {
		t.Fatalf("expected SaveUserLimits with ENABLED=no to succeed (N3), got: %v", err)
	}

	// 3. N2: ParseKeyValueFile handles lines > 64 KB (up to 1 MB) without bufio.Scanner ErrTooLong.
	hugePath := filepath.Join(tmp, "huge_user.conf")
	hugeVal := strings.Repeat("d", 120*1024)
	if err := os.WriteFile(hugePath, []byte("domains="+hugeVal+"\nusertype=user\npackage=vip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kv, err := ParseKeyValueFile(hugePath)
	if err != nil {
		t.Fatalf("ParseKeyValueFile >64KB line failed (N2): %v", err)
	}
	if kv["package"] != "vip" || len(kv["domains"]) != len(hugeVal) {
		t.Fatalf("unexpected parsed huge_user.conf: pkg=%q len(domains)=%d", kv["package"], len(kv["domains"]))
	}
}
