package dausers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryReloadFiltersSystemUIDsAndResolvesDBUsers(t *testing.T) {
	tmp := t.TempDir()
	passwdFile := filepath.Join(tmp, "passwd")
	daDir := filepath.Join(tmp, "users")

	passwdContent := "" +
		"root:x:0:0:root:/root:/bin/bash\n" +
		"diradmin:x:995:995:DirectAdmin:/usr/local/directadmin:/bin/false\n" +
		"admin:x:1000:1000:Admin:/home/admin:/bin/bash\n" +
		"vina:x:1001:1001:Vina:/home/vina:/bin/bash\n" +
		"vina_host:x:1002:1002:VinaHost:/home/vina_host:/bin/bash\n" +
		"lveuser:x:60005:60005:LVEUser:/home/lveuser:/bin/bash\n" +
		"nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin\n"

	if err := os.WriteFile(passwdFile, []byte(passwdContent), 0o644); err != nil {
		t.Fatal(err)
	}

	writeDAUser := func(name, content string) {
		dir := filepath.Join(daDir, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "user.conf"), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	writeDAUser("admin", "usertype=admin\npackage=admin\n")
	writeDAUser("vina", "usertype=user\npackage=silver\n")
	writeDAUser("vina_host", "usertype=user\npackage=gold\n")
	writeDAUser("lveuser", "usertype=user\npackage=gold\n")
	writeDAUser("nobody", "usertype=user\npackage=default\n")

	reg := NewRegistry(daDir, passwdFile)
	if err := reg.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if reg.Count() != 3 {
		t.Fatalf("expected 3 managed hosting accounts (vina, vina_host, lveuser), got %d", reg.Count())
	}
	if _, ok := reg.LookupByUID(60005); !ok {
		t.Fatal("expected high UID 60005 (< 65534) to be managed (R11)")
	}

	if _, ok := reg.LookupByUID(65534); ok {
		t.Fatal("nobody (UID 65534) must never be managed")
	}
	if _, ok := reg.LookupByName("admin"); ok {
		t.Fatal("admin account should be excluded")
	}

	// Longest-prefix match test: "vina_host_wp" must match "vina_host", NOT "vina"
	acct, ok := reg.ResolveDBUser("vina_host_wp")
	if !ok || acct.Username != "vina_host" {
		t.Fatalf("expected vina_host_wp -> vina_host, got %+v (ok=%v)", acct, ok)
	}

	acct2, ok := reg.ResolveDBUser("vina_shop")
	if !ok || acct2.Username != "vina" {
		t.Fatalf("expected vina_shop -> vina, got %+v (ok=%v)", acct2, ok)
	}

	if _, ok := reg.ResolveDBUser("da_admin"); ok {
		t.Fatal("expected da_admin to not resolve to a customer user")
	}
}

func TestRegistryMissingDirRetainsSnapshotOrphanConfirmationAndConcurrency(t *testing.T) {
	tmp := t.TempDir()
	passwdFile := filepath.Join(tmp, "passwd")
	daDir := filepath.Join(tmp, "users")

	passwdContent := "" +
		"alice:x:1005:1005:Alice:/home/alice:/bin/bash\n" +
		"bob:x:1006:1006:Bob:/home/bob:/bin/bash\n"
	if err := os.WriteFile(passwdFile, []byte(passwdContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Include >64KB line in alice/user.conf to verify 1 MB scanner buffer (N2)
	_ = os.MkdirAll(filepath.Join(daDir, "alice"), 0o755)
	_ = os.WriteFile(filepath.Join(daDir, "alice", "user.conf"), []byte("domains="+string(make([]byte, 80*1024))+"\nusertype=user\npackage=gold\n"), 0o640)
	// Clean printable >64KB value
	hugeDomains := make([]byte, 80*1024)
	for i := range hugeDomains {
		hugeDomains[i] = 'a'
	}
	_ = os.WriteFile(filepath.Join(daDir, "alice", "user.conf"), []byte("domains="+string(hugeDomains)+"\nusertype=user\npackage=gold\n"), 0o640)

	_ = os.MkdirAll(filepath.Join(daDir, "bob"), 0o755)
	_ = os.WriteFile(filepath.Join(daDir, "bob", "user.conf"), []byte("usertype=user\npackage=silver\n"), 0o640)

	reg := NewRegistry(daDir, passwdFile)
	if err := reg.Reload(); err != nil {
		t.Fatalf("initial Reload: %v", err)
	}
	if reg.Count() != 2 {
		t.Fatalf("expected 2 users, got %d", reg.Count())
	}

	// 1. N2: Transient disappearance of daUsersDir MUST return error AND preserve in-memory accounts!
	movedDir := filepath.Join(tmp, "users_unmounted")
	if err := os.Rename(daDir, movedDir); err != nil {
		t.Fatal(err)
	}
	if err := reg.Reload(); err == nil {
		t.Fatal("expected Reload() to return error when daUsersDir is missing (N2)")
	}
	if reg.Count() != 2 {
		t.Fatalf("expected Registry to retain 2 accounts on failed Reload (N2), got %d", reg.Count())
	}
	if err := os.Rename(movedDir, daDir); err != nil {
		t.Fatal(err)
	}

	// 2. N2: Removing bob/user.conf while bob is STILL in /etc/passwd requires 2 consecutive reloads before CanPruneOrphanUID(1006) == true.
	_ = os.RemoveAll(filepath.Join(daDir, "bob"))
	if err := reg.Reload(); err != nil {
		t.Fatalf("Reload #1 after bob dir removal: %v", err)
	}
	if reg.CanPruneOrphanUID(1006) {
		t.Fatal("expected single missing reload while still in /etc/passwd to NOT allow orphan prune yet (N2)")
	}
	if err := reg.Reload(); err != nil {
		t.Fatalf("Reload #2 after bob dir removal: %v", err)
	}
	if !reg.CanPruneOrphanUID(1006) {
		t.Fatal("expected 2 consecutive missing reloads to confirm orphan UID 1006 (N2)")
	}
}
