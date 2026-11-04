package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
)

func buildMockReleaseTarGz(t *testing.T) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	addFile := func(name string, mode int64, body string) {
		hdr := &tar.Header{
			Name: name,
			Mode: mode,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}

	addFile("da-resource-limiter/bin/da-resourced", 0o755, "#!/bin/sh\necho v1.2.0\n")
	addFile("da-resource-limiter/scripts/update.sh", 0o755, "#!/bin/sh\nexit 0\n")
	addFile("da-resource-limiter/plugin/plugin.conf", 0o644, "version=1.2.0\n")

	_ = tw.Close()
	_ = gz.Close()

	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func TestSemVerComparison(t *testing.T) {
	if !IsNewerVersion("v0.1.0-dev", "v1.0.0") {
		t.Fatal("expected v1.0.0 > v0.1.0-dev")
	}
	if !IsNewerVersion("v1.2.0", "v1.10.0") {
		t.Fatal("expected v1.10.0 > v1.2.0")
	}
	if !IsNewerVersion("v1.0.0-beta.1", "v1.0.0") {
		t.Fatal("expected stable v1.0.0 > pre-release v1.0.0-beta.1")
	}
	if IsNewerVersion("v1.2.0", "v1.2.0") {
		t.Fatal("same version must not be newer")
	}
}

func TestPrivateRepoAssetDownloadAndCorruptedSHA256Rejection(t *testing.T) {
	archiveBytes, validSHA := buildMockReleaseTarGz(t)
	const secretToken = "github_pat_secret_test_token"
	corruptChecksumMode := false

	// Simulate S3 / objects.githubusercontent.com signed storage server:
	// Rejects requests if Authorization header is leaked across cross-host 302 redirect!
	cdnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "S3 error: Authorization header must not be forwarded on redirect", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/blob/archive":
			_, _ = w.Write(archiveBytes)
		case "/blob/checksums":
			shaToServe := validSHA
			if corruptChecksumMode {
				shaToServe = strings.Repeat("0", 64)
			}
			fmt.Fprintf(w, "%s  da-resource-limiter-linux-amd64.tar.gz\n", shaToServe)
		default:
			http.NotFound(w, r)
		}
	}))
	defer cdnSrv.Close()

	// Simulate Private GitHub REST API Server requiring Bearer token + Accept: application/octet-stream
	var apiSrv *httptest.Server
	apiSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secretToken {
			http.Error(w, "401 Unauthorized private repo", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/repos/shostwp-byte/da-resourcelimiter/releases/latest":
			rel := githubRelease{
				TagName:     "v1.2.0",
				PublishedAt: "2026-11-04T12:00:00Z",
				Body:        "Security & performance improvements",
				Assets: []githubAsset{
					{
						ID:   101,
						Name: "da-resource-limiter-linux-amd64.tar.gz",
						URL:  apiSrv.URL + "/repos/shostwp-byte/da-resourcelimiter/releases/assets/101",
					},
					{
						ID:   102,
						Name: "checksums.txt",
						URL:  apiSrv.URL + "/repos/shostwp-byte/da-resourcelimiter/releases/assets/102",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(rel)

		case "/repos/shostwp-byte/da-resourcelimiter/releases/assets/101":
			if r.Header.Get("Accept") != "application/octet-stream" {
				http.Error(w, "expected octet-stream header", http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, cdnSrv.URL+"/blob/archive", http.StatusFound)

		case "/repos/shostwp-byte/da-resourcelimiter/releases/assets/102":
			http.Redirect(w, r, cdnSrv.URL+"/blob/checksums", http.StatusFound)

		default:
			http.NotFound(w, r)
		}
	}))
	defer apiSrv.Close()

	tmp := t.TempDir()
	store := config.NewStore(filepath.Join(tmp, "data"), filepath.Join(tmp, "updater.conf"))
	if err := store.SaveUpdaterConfig(config.UpdaterConfig{
		GitHubRepo:      "shostwp-byte/da-resourcelimiter",
		GitHubToken:     secretToken,
		UpdateChannel:   "stable",
		BackupRetention: 5,
	}); err != nil {
		t.Fatal(err)
	}

	var launchedArgs []string
	svc := NewService(store)
	svc.APIBaseURL = apiSrv.URL
	svc.StagingRoot = filepath.Join(tmp, "staging")
	svc.JobStatusPath = filepath.Join(tmp, "update_status.json")
	svc.Arch = "amd64"
	svc.LaunchDetached = func(scriptPath string, args ...string) error {
		launchedArgs = append([]string{scriptPath}, args...)
		return nil
	}

	// TC-06: Private Repo Check + TriggerUpdate succeeds with verified SHA-256
	st, err := svc.CheckLatest(context.Background())
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if !st.UpdateAvailable || st.LatestVersion != "v1.2.0" {
		t.Fatalf("unexpected CheckLatest status: %+v", st)
	}

	if _, err := svc.TriggerUpdate(context.Background(), ""); err != nil {
		t.Fatalf("TriggerUpdate: %v", err)
	}
	if len(launchedArgs) < 4 || launchedArgs[1] != "apply" || launchedArgs[3] != "v1.2.0" {
		t.Fatalf("unexpected LaunchDetached invocation: %v", launchedArgs)
	}
	if _, err := os.Stat(filepath.Join(launchedArgs[2], "bin", "da-resourced")); err != nil {
		t.Fatalf("expected extracted binary in staging dir: %v", err)
	}

	// TC-07: Corrupted SHA-256 must be rejected before launching update.sh
	corruptChecksumMode = true
	launchedArgs = nil
	if _, err := svc.TriggerUpdate(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "SHA-256 verification failed") {
		t.Fatalf("expected SHA-256 verification failure, got err=%v", err)
	}
	if len(launchedArgs) != 0 {
		t.Fatalf("update.sh must NEVER be launched when SHA-256 check fails, got %v", launchedArgs)
	}
}
