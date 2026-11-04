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

func TestUpdaterConfigAndMaskedToken(t *testing.T) {
	tmp := t.TempDir()
	store := NewStore(tmp, filepath.Join(tmp, "etc", "updater.conf"))

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
}

func TestIdentifierValidationBlocksTraversal(t *testing.T) {
	for _, bad := range []string{"", "../root", "user/evil", "user;rm -rf", "-bad"} {
		if err := ValidateIdentifier(bad); err == nil {
			t.Errorf("expected error for invalid identifier %q", bad)
		}
	}
}
