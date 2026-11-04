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
