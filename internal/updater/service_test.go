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
	"sync"
	"testing"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
)

func buildMockReleaseTarGzWithVersion(t *testing.T, verTag string) ([]byte, string) {
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

	bare := strings.TrimPrefix(verTag, "v")
	addFile("da-resource-limiter/bin/da-resourced", 0o755, "#!/bin/sh\necho "+verTag+"\n")
	addFile("da-resource-limiter/scripts/update.sh", 0o755, "#!/bin/sh\nexit 0\n")
	addFile("da-resource-limiter/plugin/plugin.conf", 0o644, "version="+bare+"\n")
	addFile("da-resource-limiter/manifest.json", 0o644, fmt.Sprintf("{\n  \"version\": %q,\n  \"arch\": \"amd64\"\n}\n", verTag))

	_ = tw.Close()
	_ = gz.Close()

	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func buildMockReleaseTarGz(t *testing.T) ([]byte, string) {
	return buildMockReleaseTarGzWithVersion(t, "v1.2.0")
}

func TestSemVerComparisonIncludingFourPartTags(t *testing.T) {
	if !IsNewerVersion("v0.1.0-dev", "v1.0.0") {
		t.Fatal("expected v1.0.0 > v0.1.0-dev")
	}
	if !IsNewerVersion("v1.2.0", "v1.10.0") {
		t.Fatal("expected v1.10.0 > v1.2.0")
	}
	if !IsNewerVersion("v1.0.4", "v1.0.4.1") {
		t.Fatal("expected v1.0.4.1 > v1.0.4")
	}
	if !IsNewerVersion("v1.0.4.1", "v1.0.5") {
		t.Fatal("expected v1.0.5 > v1.0.4.1")
	}
	if !IsNewerVersion("v1.0.4.2", "v1.0.4.10") {
		t.Fatal("expected v1.0.4.10 > v1.0.4.2")
	}
	if !IsNewerVersion("v1.0.0-beta.2", "v1.0.0-beta.10") {
		t.Fatal("expected v1.0.0-beta.10 > v1.0.0-beta.2")
	}
	if !IsNewerVersion("v1.0.0-beta.1", "v1.0.0") {
		t.Fatal("expected stable v1.0.0 > pre-release v1.0.0-beta.1")
	}
	if IsNewerVersion("v1.0.4.1", "v1.0.4.1") {
		t.Fatal("same version must not be newer")
	}
}

func TestSanitizeTagRejectsDotTraversal(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "...", "////"} {
		if got := sanitizeTag(bad); got != "release" {
			t.Fatalf("sanitizeTag(%q) = %q, want 'release'", bad, got)
		}
	}
}

func TestPrivateRepoEd25519SignatureSHA256AndConcurrencyGuard(t *testing.T) {
	archiveBytes, validSHA := buildMockReleaseTarGz(t)
	pubHex, privHex, err := GenerateKeypairHex()
	if err != nil {
		t.Fatalf("GenerateKeypairHex: %v", err)
	}
	otherPubHex, otherPrivHex, err := GenerateKeypairHex()
	if err != nil || otherPubHex == pubHex {
		t.Fatalf("GenerateKeypairHex #2: %v", err)
	}

	const secretToken = "github_pat_secret_test_token"
	var modeMu sync.Mutex
	corruptChecksumMode := false
	forgedSigMode := false
	omitSigAsset := false

	currentChecksumsContent := func() string {
		modeMu.Lock()
		corrupt := corruptChecksumMode
		modeMu.Unlock()
		shaToServe := validSHA
		if corrupt {
			shaToServe = strings.Repeat("0", 64)
		}
		return fmt.Sprintf("%s  da-resource-limiter-linux-amd64.tar.gz\n", shaToServe)
	}

	cdnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "S3 error: Authorization header must not be forwarded on redirect", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/blob/archive":
			_, _ = w.Write(archiveBytes)
		case "/blob/checksums":
			_, _ = w.Write([]byte(currentChecksumsContent()))
		case "/blob/checksums.sig":
			body := []byte(currentChecksumsContent())
			modeMu.Lock()
			forged := forgedSigMode
			modeMu.Unlock()
			signingKey := privHex
			if forged {
				signingKey = otherPrivHex
			}
			sig, signErr := SignDataHex(signingKey, body)
			if signErr != nil {
				http.Error(w, signErr.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "%s  checksums.txt\n", sig)
		default:
			http.NotFound(w, r)
		}
	}))
	defer cdnSrv.Close()

	var apiSrv *httptest.Server
	apiSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secretToken {
			http.Error(w, "401 Unauthorized private repo", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/repos/shostwp-byte/da-resourcelimiter/releases/latest":
			assets := []githubAsset{
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
			}
			modeMu.Lock()
			noSig := omitSigAsset
			modeMu.Unlock()
			if !noSig {
				assets = append(assets, githubAsset{
					ID:   103,
					Name: "checksums.txt.sig",
					URL:  apiSrv.URL + "/repos/shostwp-byte/da-resourcelimiter/releases/assets/103",
				})
			}
			rel := githubRelease{
				TagName:     "v1.2.0",
				PublishedAt: "2026-11-04T12:00:00Z",
				Body:        "Security & performance improvements",
				Assets:      assets,
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

		case "/repos/shostwp-byte/da-resourcelimiter/releases/assets/103":
			http.Redirect(w, r, cdnSrv.URL+"/blob/checksums.sig", http.StatusFound)

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
	svc.ReleasePublicKeyHex = pubHex
	svc.LaunchDetached = func(scriptPath string, args ...string) error {
		launchedArgs = append([]string{scriptPath}, args...)
		return nil
	}

	// 1. CheckLatest + Valid Ed25519 + SHA-256 TriggerUpdate succeeds
	st, err := svc.CheckLatest(context.Background())
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if !st.UpdateAvailable || st.LatestVersion != "v1.2.0" || !st.RepoPinned || !st.SignatureRequired {
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

	// 2. Concurrent TriggerUpdate while job status is "running" must be rejected (R3)
	if _, err := svc.TriggerUpdate(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "currently running") {
		t.Fatalf("expected concurrent TriggerUpdate while job is running to fail, got err=%v", err)
	}

	// Mark previous job finished before testing signature/checksum rejection cases
	svc.writeJobStatus("idle", "ready", "")

	// 3. Forged Ed25519 signature must fail closed before downloading/launching update.sh (S1)
	modeMu.Lock()
	forgedSigMode = true
	modeMu.Unlock()
	launchedArgs = nil
	if _, err := svc.TriggerUpdate(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Fatalf("expected forged Ed25519 signature rejection, got err=%v", err)
	}
	if len(launchedArgs) != 0 {
		t.Fatalf("update.sh must NEVER run on forged Ed25519 signature")
	}

	// 4. Missing checksums.txt.sig asset must fail closed (S1)
	modeMu.Lock()
	forgedSigMode = false
	omitSigAsset = true
	modeMu.Unlock()
	svc.mu.Lock()
	svc.cachedRel = nil
	svc.mu.Unlock()
	if _, err := svc.TriggerUpdate(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "missing checksums.txt.sig") {
		t.Fatalf("expected missing checksums.txt.sig rejection, got err=%v", err)
	}

	// 5. Valid Ed25519 signature over mismatched archive SHA-256 must fail closed (TC-07)
	modeMu.Lock()
	omitSigAsset = false
	corruptChecksumMode = true
	modeMu.Unlock()
	svc.mu.Lock()
	svc.cachedRel = nil
	svc.mu.Unlock()
	if _, err := svc.TriggerUpdate(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "SHA-256 verification failed") {
		t.Fatalf("expected SHA-256 verification failure, got err=%v", err)
	}
	if len(launchedArgs) != 0 {
		t.Fatalf("update.sh must NEVER be launched when SHA-256 check fails, got %v", launchedArgs)
	}

	// 6. Anti-downgrade guard (N13): if running v1.5.0, staging v1.2.0 fails closed without --allow-downgrade
	modeMu.Lock()
	corruptChecksumMode = false
	modeMu.Unlock()
	svc.CurrentVersion = "v1.5.0"
	svc.writeJobStatus("idle", "ready", "")
	if _, err := svc.TriggerUpdate(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "refusing downgrade") {
		t.Fatalf("expected downgrade from v1.5.0 to v1.2.0 to be rejected (N13), got err=%v", err)
	}
}

func TestSignedOldArchiveTagReplayRejected(t *testing.T) {
	// Build a genuinely signed v1.1.0 archive + checksums.txt + checksums.txt.sig,
	// then serve it under GitHub Release tag "v1.2.0" to simulate a tag-replay attack (N13).
	replayedArchive, replayedSHA := buildMockReleaseTarGzWithVersion(t, "v1.1.0")
	pubHex, privHex, err := GenerateKeypairHex()
	if err != nil {
		t.Fatal(err)
	}
	checksumsBody := fmt.Sprintf("%s  da-resource-limiter-linux-amd64.tar.gz\n", replayedSHA)
	sigHex, err := SignDataHex(privHex, []byte(checksumsBody))
	if err != nil {
		t.Fatal(err)
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/shostwp-byte/da-resourcelimiter/releases/latest":
			_ = json.NewEncoder(w).Encode(githubRelease{
				TagName: "v1.2.0", // Attacker claims v1.2.0 while serving signed v1.1.0 assets!
				Assets: []githubAsset{
					{ID: 1, Name: "da-resource-limiter-linux-amd64.tar.gz", BrowserDownloadURL: srv.URL + "/dl/archive"},
					{ID: 2, Name: "checksums.txt", BrowserDownloadURL: srv.URL + "/dl/checksums"},
					{ID: 3, Name: "checksums.txt.sig", BrowserDownloadURL: srv.URL + "/dl/sig"},
				},
			})
		case "/dl/archive":
			_, _ = w.Write(replayedArchive)
		case "/dl/checksums":
			_, _ = w.Write([]byte(checksumsBody))
		case "/dl/sig":
			fmt.Fprintf(w, "%s  checksums.txt\n", sigHex)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	store := config.NewStore(filepath.Join(tmp, "data"), filepath.Join(tmp, "updater.conf"))
	svc := NewService(store)
	svc.APIBaseURL = srv.URL
	svc.StagingRoot = filepath.Join(tmp, "staging")
	svc.JobStatusPath = filepath.Join(tmp, "status.json")
	svc.Arch = "amd64"
	svc.CurrentVersion = "v1.0.4.2"
	svc.ReleasePublicKeyHex = pubHex

	if _, _, _, err := svc.StageRelease(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "release tag mismatch") {
		t.Fatalf("expected signed-old-archive replay to fail closed with release tag mismatch (N13), got err=%v", err)
	}
}
