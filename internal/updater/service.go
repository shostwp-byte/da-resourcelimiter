package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/ipc"
	"github.com/shostwp-byte/da-resourcelimiter/internal/version"
)

const (
	DefaultAPIBaseURL      = "https://api.github.com"
	DefaultStagingRoot     = "/var/lib/da-resourced/staging"
	DefaultJobStatusPath   = "/var/lib/da-resourced/update_status.json"
	DefaultUpdateScript    = "/usr/local/directadmin/plugins/da_resource_limiter/scripts/update.sh"
	checkCacheTTL          = 15 * time.Minute
	activeJobTTL           = 15 * time.Minute
	maxArchiveDownloadSize = 150 * 1024 * 1024 // 150 MB safety cap
	maxTotalExtractBytes   = 250 * 1024 * 1024 // 250 MB cumulative extraction cap
)

// JobStatus tracks live progress written by Service and scripts/update.sh.
type JobStatus struct {
	State       string `json:"state"` // idle | staging | running | success | rolled_back | failed
	Message     string `json:"message"`
	TargetVer   string `json:"target_version,omitempty"`
	UpdatedUnix int64  `json:"updated_unix"`
}

type githubAsset struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	URL                string `json:"url"` // API endpoint /repos/{owner}/{repo}/releases/assets/{id}
	Size               int64  `json:"size"`
}

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	PublishedAt string        `json:"published_at"`
	Body        string        `json:"body"`
	Assets      []githubAsset `json:"assets"`
}

// DetachedLauncher executes scripts/update.sh asynchronously (defaults to systemd-run on production Linux).
type DetachedLauncher func(scriptPath string, args ...string) error

// Service manages GitHub Releases checks, Ed25519 + SHA-256 verification, and atomic update jobs.
type Service struct {
	Store               *config.Store
	APIBaseURL          string
	HTTPClient          *http.Client
	StagingRoot         string
	JobStatusPath       string
	UpdateScript        string
	Arch                string
	CurrentVersion      string
	ReleasePublicKeyHex string
	LaunchDetached      DetachedLauncher

	mu          sync.Mutex
	cachedRel   *githubRelease
	cachedRepo  string
	cachedChan  string
	cachedUntil time.Time

	opMu     sync.Mutex
	inFlight bool
}

func NewService(store *config.Store) *Service {
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			// Never forward Bearer tokens when redirected to a different host:port (e.g. GitHub API -> S3/CDN)
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				req.Header.Del("Authorization")
			}
			return nil
		},
	}
	s := &Service{
		Store:               store,
		APIBaseURL:          DefaultAPIBaseURL,
		HTTPClient:          httpClient,
		StagingRoot:         DefaultStagingRoot,
		JobStatusPath:       DefaultJobStatusPath,
		UpdateScript:        DefaultUpdateScript,
		Arch:                runtime.GOARCH,
		CurrentVersion:      version.Version,
		ReleasePublicKeyHex: version.DefaultReleasePublicKeyHex,
	}
	s.LaunchDetached = defaultSystemdRunLauncher
	return s
}

func (s *Service) effectiveCurrentVersion() string {
	if v := strings.TrimSpace(s.CurrentVersion); v != "" {
		return v
	}
	return version.Version
}

func defaultSystemdRunLauncher(scriptPath string, args ...string) error {
	unitName := fmt.Sprintf("da-resourced-updater-%d", time.Now().UTC().UnixNano())
	cmdArgs := append([]string{"--unit=" + unitName, "--collect", scriptPath}, args...)
	cmd := exec.Command("systemd-run", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *Service) acquireUpdateOp() (func(), error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	if s.inFlight {
		return nil, errors.New("another update or rollback operation is already in progress")
	}

	job := s.readJobStatus()
	if (job.State == "staging" || job.State == "running") && job.UpdatedUnix > 0 {
		age := time.Since(time.Unix(job.UpdatedUnix, 0))
		if age >= 0 && age < activeJobTTL {
			return nil, fmt.Errorf("an update or rollback job is currently %s (%s)", job.State, job.Message)
		}
	}

	s.inFlight = true
	return func() {
		s.opMu.Lock()
		s.inFlight = false
		s.opMu.Unlock()
	}, nil
}

// GetStatus returns current configuration, cached release info (if any), and the latest update job state.
func (s *Service) GetStatus(_ context.Context) (ipc.UpdaterStatusData, error) {
	cfg, err := s.Store.LoadUpdaterConfig()
	if err != nil {
		return ipc.UpdaterStatusData{}, err
	}

	curVer := s.effectiveCurrentVersion()
	job := s.readJobStatus()
	data := ipc.UpdaterStatusData{
		CurrentVersion:    curVer,
		GitHubRepo:        cfg.GitHubRepo,
		RepoPinned:        !cfg.AllowCustomRepo,
		SignatureRequired: strings.TrimSpace(s.ReleasePublicKeyHex) != "",
		RootOnlyActions:   true,
		HasToken:          cfg.GitHubToken != "",
		MaskedToken:       cfg.MaskedToken(),
		UpdateChannel:     cfg.UpdateChannel,
		BackupRetention:   cfg.BackupRetention,
		LastJobState:      job.State,
		LastJobMessage:    job.Message,
	}

	s.mu.Lock()
	rel := s.cachedRel
	sameTarget := s.cachedRepo == cfg.GitHubRepo && s.cachedChan == cfg.UpdateChannel
	s.mu.Unlock()

	if rel != nil && sameTarget {
		data.LatestVersion = rel.TagName
		data.UpdateAvailable = IsNewerVersion(curVer, rel.TagName)
		data.ReleaseNotes = rel.Body
		data.PublishedAt = rel.PublishedAt
	}
	return data, nil
}

// CheckLatest queries the GitHub Releases API (supporting both Public & Private repositories) and refreshes cache.
func (s *Service) CheckLatest(ctx context.Context) (ipc.UpdaterStatusData, error) {
	cfg, err := s.Store.LoadUpdaterConfig()
	if err != nil {
		return ipc.UpdaterStatusData{}, err
	}

	rel, err := s.fetchTargetRelease(ctx, cfg, "", true)
	if err != nil {
		return ipc.UpdaterStatusData{}, err
	}

	s.mu.Lock()
	s.cachedRel = rel
	s.cachedRepo = cfg.GitHubRepo
	s.cachedChan = cfg.UpdateChannel
	s.cachedUntil = time.Now().Add(checkCacheTTL)
	s.mu.Unlock()

	return s.GetStatus(ctx)
}

// StageRelease downloads the release archive + checksums.txt (+ checksums.txt.sig), verifies Ed25519 & SHA-256,
// and extracts into an isolated per-invocation staging directory.
func (s *Service) StageRelease(ctx context.Context, targetVersion string) (unpackedRoot string, resolvedTag string, retention int, err error) {
	releaseOp, err := s.acquireUpdateOp()
	if err != nil {
		return "", "", 0, err
	}
	defer releaseOp()

	return s.stageReleaseLocked(ctx, targetVersion, false)
}

func (s *Service) stageReleaseLocked(ctx context.Context, targetVersion string, allowDowngrade bool) (unpackedRoot string, resolvedTag string, retention int, err error) {
	cfg, err := s.Store.LoadUpdaterConfig()
	if err != nil {
		return "", "", 0, err
	}

	s.writeJobStatus("staging", "Checking GitHub Release metadata...", targetVersion)

	rel, err := s.fetchTargetRelease(ctx, cfg, targetVersion, false)
	if err != nil {
		s.writeJobStatus("failed", "GitHub Release lookup failed: "+err.Error(), targetVersion)
		return "", "", 0, err
	}
	if err := config.ValidateReleaseTag(rel.TagName); err != nil {
		s.writeJobStatus("failed", "Invalid release tag from GitHub: "+err.Error(), rel.TagName)
		return "", "", 0, err
	}

	curVer := s.effectiveCurrentVersion()
	if !allowDowngrade && CompareSemVer(rel.TagName, curVer) < 0 {
		err = fmt.Errorf("refusing downgrade from %s to %s (use 'da-resourced rollback' or '--allow-downgrade')", curVer, rel.TagName)
		s.writeJobStatus("failed", err.Error(), rel.TagName)
		return "", "", 0, err
	}

	archiveName := fmt.Sprintf("da-resource-limiter-linux-%s.tar.gz", s.Arch)
	var archiveAsset, checksumAsset, sigAsset, manifestAsset *githubAsset
	for i := range rel.Assets {
		a := &rel.Assets[i]
		switch a.Name {
		case archiveName:
			archiveAsset = a
		case "checksums.txt":
			checksumAsset = a
		case "checksums.txt.sig":
			sigAsset = a
		case "manifest.json":
			manifestAsset = a
		}
	}
	if archiveAsset == nil {
		err = fmt.Errorf("release %s does not contain asset %q", rel.TagName, archiveName)
		s.writeJobStatus("failed", err.Error(), rel.TagName)
		return "", "", 0, err
	}
	if checksumAsset == nil {
		err = fmt.Errorf("release %s is missing checksums.txt (refusing unverified update)", rel.TagName)
		s.writeJobStatus("failed", err.Error(), rel.TagName)
		return "", "", 0, err
	}

	pubKeyHex := strings.TrimSpace(s.ReleasePublicKeyHex)
	if pubKeyHex != "" && sigAsset == nil {
		err = fmt.Errorf("release %s is missing checksums.txt.sig (refusing unsigned release)", rel.TagName)
		s.writeJobStatus("failed", err.Error(), rel.TagName)
		return "", "", 0, err
	}

	stageDir := filepath.Join(s.StagingRoot, fmt.Sprintf("%s-%d", sanitizeTag(rel.TagName), time.Now().UTC().UnixNano()))
	if mkErr := os.MkdirAll(stageDir, 0o700); mkErr != nil {
		return "", "", 0, fmt.Errorf("create staging dir: %w", mkErr)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(stageDir)
		}
	}()

	checksumPath := filepath.Join(stageDir, "checksums.txt")
	if err = s.downloadAsset(ctx, cfg, *checksumAsset, checksumPath); err != nil {
		s.writeJobStatus("failed", "Download checksums.txt failed: "+err.Error(), rel.TagName)
		return "", "", 0, err
	}

	if pubKeyHex != "" {
		sigPath := filepath.Join(stageDir, "checksums.txt.sig")
		if err = s.downloadAsset(ctx, cfg, *sigAsset, sigPath); err != nil {
			s.writeJobStatus("failed", "Download checksums.txt.sig failed: "+err.Error(), rel.TagName)
			return "", "", 0, err
		}
		checksumBytes, readErr := os.ReadFile(checksumPath)
		if readErr != nil {
			err = readErr
			return "", "", 0, err
		}
		sigBytes, readErr := os.ReadFile(sigPath)
		if readErr != nil {
			err = readErr
			return "", "", 0, err
		}
		if err = VerifyDataHex(pubKeyHex, checksumBytes, string(sigBytes)); err != nil {
			s.writeJobStatus("failed", err.Error(), rel.TagName)
			return "", "", 0, err
		}
	}

	if manifestAsset != nil {
		if manifestExpectedSHA, mLookupErr := lookupChecksum(checksumPath, "manifest.json"); mLookupErr == nil {
			manifestPath := filepath.Join(stageDir, "release-manifest.json")
			if err = s.downloadAsset(ctx, cfg, *manifestAsset, manifestPath); err != nil {
				s.writeJobStatus("failed", "Download manifest.json failed: "+err.Error(), rel.TagName)
				return "", "", 0, err
			}
			manifestActualSHA, shaErr := computeFileSHA256(manifestPath)
			if shaErr != nil {
				err = shaErr
				return "", "", 0, err
			}
			if !strings.EqualFold(manifestActualSHA, manifestExpectedSHA) {
				err = fmt.Errorf("SHA-256 verification failed for manifest.json: expected %s, got %s", manifestExpectedSHA, manifestActualSHA)
				s.writeJobStatus("failed", err.Error(), rel.TagName)
				return "", "", 0, err
			}
			if err = verifyManifestVersionFile(manifestPath, rel.TagName, ""); err != nil {
				s.writeJobStatus("failed", err.Error(), rel.TagName)
				return "", "", 0, err
			}
		}
	}

	expectedSHA, err := lookupChecksum(checksumPath, archiveName)
	if err != nil {
		s.writeJobStatus("failed", err.Error(), rel.TagName)
		return "", "", 0, err
	}

	s.writeJobStatus("staging", fmt.Sprintf("Downloading %s (%s)...", archiveName, rel.TagName), rel.TagName)
	archivePath := filepath.Join(stageDir, archiveName)
	if err = s.downloadAsset(ctx, cfg, *archiveAsset, archivePath); err != nil {
		s.writeJobStatus("failed", "Download archive failed: "+err.Error(), rel.TagName)
		return "", "", 0, err
	}

	actualSHA, err := computeFileSHA256(archivePath)
	if err != nil {
		return "", "", 0, err
	}
	if !strings.EqualFold(actualSHA, expectedSHA) {
		err = fmt.Errorf("SHA-256 verification failed for %s: expected %s, got %s", archiveName, expectedSHA, actualSHA)
		s.writeJobStatus("failed", err.Error(), rel.TagName)
		return "", "", 0, err
	}

	unpackDir := filepath.Join(stageDir, "unpacked")
	if err = extractTarGzSafe(archivePath, unpackDir); err != nil {
		s.writeJobStatus("failed", "Archive extraction failed: "+err.Error(), rel.TagName)
		return "", "", 0, err
	}

	pkgRoot := filepath.Join(unpackDir, "da-resource-limiter")
	if st, statErr := os.Stat(pkgRoot); statErr != nil || !st.IsDir() {
		pkgRoot = unpackDir
	}

	// Verify extracted package metadata matches the requested release tag to defeat signed-old-archive replay (N13).
	if err = verifyExtractedPackageVersion(pkgRoot, rel.TagName, s.Arch); err != nil {
		s.writeJobStatus("failed", err.Error(), rel.TagName)
		return "", "", 0, err
	}

	return pkgRoot, rel.TagName, cfg.BackupRetention, nil
}

type releaseManifest struct {
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

func normalizeVersionBare(v string) string {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	return s
}

func verifyManifestVersionFile(manifestPath, expectedTag, expectedArch string) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m releaseManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("invalid manifest.json: %w", err)
	}
	if normalizeVersionBare(m.Version) == "" || normalizeVersionBare(m.Version) != normalizeVersionBare(expectedTag) {
		return fmt.Errorf("release tag mismatch: manifest.json declares %q, expected release tag %q (refusing replayed archive)", m.Version, expectedTag)
	}
	if expectedArch != "" && strings.TrimSpace(m.Arch) != "" && strings.TrimSpace(m.Arch) != expectedArch {
		return fmt.Errorf("release arch mismatch: manifest.json declares %q, expected %q", m.Arch, expectedArch)
	}
	return nil
}

func verifyExtractedPackageVersion(pkgRoot, expectedTag, expectedArch string) error {
	expectedBare := normalizeVersionBare(expectedTag)
	if expectedBare == "" {
		return fmt.Errorf("invalid expected release tag %q", expectedTag)
	}

	manifestPath := filepath.Join(pkgRoot, "manifest.json")
	if _, err := os.Stat(manifestPath); err == nil {
		if err := verifyManifestVersionFile(manifestPath, expectedTag, expectedArch); err != nil {
			return err
		}
	}

	pluginConfPath := filepath.Join(pkgRoot, "plugin", "plugin.conf")
	kv, err := config.ParseKeyValueFile(pluginConfPath)
	if err != nil {
		return fmt.Errorf("extracted archive missing valid plugin/plugin.conf: %w", err)
	}
	pluginVer := normalizeVersionBare(kv["version"])
	if pluginVer == "" || pluginVer != expectedBare {
		return fmt.Errorf("release tag mismatch: extracted plugin/plugin.conf declares version=%q, expected %q (refusing replayed archive)", kv["version"], expectedBare)
	}
	return nil
}

// TriggerUpdate stages the verified GitHub Release and launches scripts/update.sh in an independent transient systemd unit.
func (s *Service) TriggerUpdate(ctx context.Context, targetVersion string) (string, error) {
	releaseOp, err := s.acquireUpdateOp()
	if err != nil {
		return "", err
	}
	defer releaseOp()

	pkgRoot, resolvedTag, retention, err := s.stageReleaseLocked(ctx, targetVersion, false)
	if err != nil {
		return "", err
	}

	scriptToRun := s.UpdateScript
	stagedScript := filepath.Join(pkgRoot, "scripts", "update.sh")
	if st, err := os.Stat(stagedScript); err == nil && !st.IsDir() {
		_ = os.Chmod(stagedScript, 0o700)
		scriptToRun = stagedScript
	}

	s.writeJobStatus("running", fmt.Sprintf("Verified Ed25519 & SHA-256 for %s; executing atomic swap & healthcheck...", resolvedTag), resolvedTag)
	if err := s.LaunchDetached(scriptToRun, "apply", pkgRoot, resolvedTag, strconv.Itoa(retention)); err != nil {
		_ = os.RemoveAll(stagingContainerDir(s.StagingRoot, pkgRoot))
		s.writeJobStatus("failed", err.Error(), resolvedTag)
		return "", err
	}

	return fmt.Sprintf("Update job started for %s (Ed25519 + SHA-256 verified, automatic rollback armed)", resolvedTag), nil
}

// TriggerRollback launches scripts/update.sh rollback in an independent transient systemd unit.
func (s *Service) TriggerRollback(_ context.Context) (string, error) {
	releaseOp, err := s.acquireUpdateOp()
	if err != nil {
		return "", err
	}
	defer releaseOp()

	if _, err := os.Stat(s.UpdateScript); err != nil {
		return "", fmt.Errorf("update script not found at %s: %w", s.UpdateScript, err)
	}
	s.writeJobStatus("running", "Restoring previous working snapshot...", "rollback")
	if err := s.LaunchDetached(s.UpdateScript, "rollback"); err != nil {
		s.writeJobStatus("failed", err.Error(), "rollback")
		return "", err
	}
	return "Rollback job started from latest backup snapshot", nil
}

// RunCLIUpdate performs a synchronous update directly in the caller's terminal (for `da-resourced update`).
func (s *Service) RunCLIUpdate(ctx context.Context, targetVersion string) error {
	return s.RunCLIUpdateWithOptions(ctx, targetVersion, false)
}

// RunCLIUpdateWithOptions performs a synchronous CLI update with an optional downgrade override flag (N13).
func (s *Service) RunCLIUpdateWithOptions(ctx context.Context, targetVersion string, allowDowngrade bool) error {
	releaseOp, err := s.acquireUpdateOp()
	if err != nil {
		return err
	}
	defer releaseOp()

	pkgRoot, resolvedTag, retention, err := s.stageReleaseLocked(ctx, targetVersion, allowDowngrade)
	if err != nil {
		return err
	}

	scriptToRun := s.UpdateScript
	stagedScript := filepath.Join(pkgRoot, "scripts", "update.sh")
	if st, err := os.Stat(stagedScript); err == nil && !st.IsDir() {
		_ = os.Chmod(stagedScript, 0o700)
		scriptToRun = stagedScript
	}

	cmd := exec.CommandContext(ctx, scriptToRun, "apply", pkgRoot, resolvedTag, strconv.Itoa(retention))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(stagingContainerDir(s.StagingRoot, pkgRoot))
		return err
	}
	return nil
}

// RunCLIRollback performs a synchronous snapshot rollback directly in the caller's terminal.
func (s *Service) RunCLIRollback(ctx context.Context) error {
	releaseOp, err := s.acquireUpdateOp()
	if err != nil {
		return err
	}
	defer releaseOp()

	cmd := exec.CommandContext(ctx, s.UpdateScript, "rollback")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func stagingContainerDir(stagingRoot, pkgRoot string) string {
	cleanStaging := filepath.Clean(stagingRoot)
	cur := filepath.Clean(pkgRoot)
	for cur != "" && cur != "." && cur != filepath.Dir(cur) {
		parent := filepath.Dir(cur)
		if parent == cleanStaging {
			return cur
		}
		cur = parent
	}
	return ""
}

func escapeGitHubRepoPath(repo string) (string, error) {
	if err := config.ValidateGitHubRepo(repo); err != nil {
		return "", err
	}
	parts := strings.SplitN(strings.TrimSpace(repo), "/", 2)
	return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]), nil
}

func (s *Service) fetchTargetRelease(ctx context.Context, cfg config.UpdaterConfig, explicitTag string, bypassCache bool) (*githubRelease, error) {
	escapedRepo, err := escapeGitHubRepoPath(cfg.GitHubRepo)
	if err != nil {
		return nil, err
	}

	explicitTag = strings.TrimSpace(explicitTag)
	if explicitTag != "" {
		if err := config.ValidateReleaseTag(explicitTag); err != nil {
			return nil, err
		}
	}

	if explicitTag == "" && !bypassCache {
		s.mu.Lock()
		if s.cachedRel != nil && s.cachedRepo == cfg.GitHubRepo && s.cachedChan == cfg.UpdateChannel && time.Now().Before(s.cachedUntil) {
			rel := s.cachedRel
			s.mu.Unlock()
			return rel, nil
		}
		s.mu.Unlock()
	}

	base := strings.TrimRight(s.APIBaseURL, "/")
	if explicitTag != "" {
		apiURL := fmt.Sprintf("%s/repos/%s/releases/tags/%s", base, escapedRepo, url.PathEscape(explicitTag))
		var rel githubRelease
		if err := s.getJSON(ctx, apiURL, cfg.GitHubToken, &rel); err != nil {
			return nil, err
		}
		if err := config.ValidateReleaseTag(rel.TagName); err != nil {
			return nil, err
		}
		return &rel, nil
	}

	if cfg.UpdateChannel == "beta" {
		apiURL := fmt.Sprintf("%s/repos/%s/releases?per_page=10", base, escapedRepo)
		var list []githubRelease
		if err := s.getJSON(ctx, apiURL, cfg.GitHubToken, &list); err != nil {
			return nil, err
		}
		for i := range list {
			if !list[i].Draft && config.ValidateReleaseTag(list[i].TagName) == nil {
				return &list[i], nil
			}
		}
		return nil, errors.New("no valid published releases found in repository")
	}

	apiURL := fmt.Sprintf("%s/repos/%s/releases/latest", base, escapedRepo)
	var rel githubRelease
	if err := s.getJSON(ctx, apiURL, cfg.GitHubToken, &rel); err != nil {
		return nil, err
	}
	if err := config.ValidateReleaseTag(rel.TagName); err != nil {
		return nil, err
	}
	return &rel, nil
}

func (s *Service) getJSON(ctx context.Context, reqURL, token string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "DA-ResourceLimiter/"+version.Version)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GitHub API %s returned HTTP %d: %s", reqURL, resp.StatusCode, strings.TrimSpace(string(bodySnippet)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(out)
}

func (s *Service) downloadAsset(ctx context.Context, cfg config.UpdaterConfig, asset githubAsset, destPath string) error {
	escapedRepo, err := escapeGitHubRepoPath(cfg.GitHubRepo)
	if err != nil {
		return err
	}

	// Critical for Private GitHub Repos: browser_download_url returns 404 with API tokens;
	// use the REST Asset endpoint (/releases/assets/{id}) with Accept: application/octet-stream.
	downloadURL := asset.BrowserDownloadURL
	useAssetAPI := strings.TrimSpace(cfg.GitHubToken) != "" || downloadURL == ""
	if useAssetAPI {
		if asset.URL != "" {
			downloadURL = asset.URL
		} else {
			downloadURL = fmt.Sprintf("%s/repos/%s/releases/assets/%d", strings.TrimRight(s.APIBaseURL, "/"), escapedRepo, asset.ID)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "DA-ResourceLimiter/"+version.Version)
	if useAssetAPI {
		req.Header.Set("Accept", "application/octet-stream")
		if strings.TrimSpace(cfg.GitHubToken) != "" {
			req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.GitHubToken))
		}
	}

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("asset download %q failed (HTTP %d): %s", asset.Name, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, io.LimitReader(resp.Body, maxArchiveDownloadSize))
	return err
}

func lookupChecksum(checksumFilePath, targetAssetName string) (string, error) {
	raw, err := os.ReadFile(checksumFilePath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		hash := fields[0]
		fname := strings.TrimPrefix(fields[1], "*")
		fname = filepath.Base(fname)
		if fname == targetAssetName && len(hash) == 64 {
			if _, err := hex.DecodeString(hash); err == nil {
				return strings.ToLower(hash), nil
			}
		}
	}
	return "", fmt.Errorf("asset %q not listed in checksums.txt", targetAssetName)
}

func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractTarGzSafe(archivePath, destRoot string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	cleanDest := filepath.Clean(destRoot)
	if err := os.MkdirAll(cleanDest, 0o700); err != nil {
		return err
	}

	var totalExtracted int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if hdr.Typeflag == tar.TypeXHeader || hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}

		rel := filepath.Clean(strings.TrimLeft(hdr.Name, "/\\"))
		if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || strings.HasPrefix(rel, "../") {
			return fmt.Errorf("unsafe path in archive: %q", hdr.Name)
		}
		targetPath := filepath.Join(cleanDest, rel)
		if !strings.HasPrefix(targetPath, cleanDest+string(os.PathSeparator)) && targetPath != cleanDest {
			return fmt.Errorf("archive path escapes destination: %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode) & 0o777
			if mode == 0 {
				mode = 0o644
			}
			remaining := maxTotalExtractBytes - totalExtracted
			if remaining <= 0 {
				return errors.New("archive exceeds maximum cumulative extracted size")
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			written, err := io.Copy(outFile, io.LimitReader(tr, remaining+1))
			_ = outFile.Close()
			if err != nil {
				return err
			}
			totalExtracted += written
			if totalExtracted > maxTotalExtractBytes {
				return errors.New("archive exceeds maximum cumulative extracted size")
			}
		default:
			return fmt.Errorf("refusing unsupported tar entry type %d (%q)", hdr.Typeflag, hdr.Name)
		}
	}
	return nil
}

func (s *Service) readJobStatus() JobStatus {
	raw, err := os.ReadFile(s.JobStatusPath)
	if err != nil {
		return JobStatus{State: "idle"}
	}
	var st JobStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return JobStatus{State: "idle"}
	}
	return st
}

func (s *Service) writeJobStatus(state, msg, targetVer string) {
	if s.JobStatusPath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.JobStatusPath), 0o750)
	payload, err := json.MarshalIndent(JobStatus{
		State:       state,
		Message:     msg,
		TargetVer:   targetVer,
		UpdatedUnix: time.Now().UTC().Unix(),
	}, "", "  ")
	if err != nil {
		return
	}
	tmp := s.JobStatusPath + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err == nil {
		_ = os.Rename(tmp, s.JobStatusPath)
	}
}

func sanitizeTag(tag string) string {
	var b strings.Builder
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	res := strings.Trim(b.String(), ".")
	if res == "" || res == "." || res == ".." {
		return "release"
	}
	return res
}
