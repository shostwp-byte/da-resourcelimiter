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
	maxArchiveDownloadSize = 150 * 1024 * 1024 // 150 MB safety cap
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

// Service manages GitHub Releases checks, authenticated asset downloads, SHA-256 verification, and update jobs.
type Service struct {
	Store          *config.Store
	APIBaseURL     string
	HTTPClient     *http.Client
	StagingRoot    string
	JobStatusPath  string
	UpdateScript   string
	Arch           string
	LaunchDetached DetachedLauncher

	mu          sync.Mutex
	cachedRel   *githubRelease
	cachedRepo  string
	cachedChan  string
	cachedUntil time.Time
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
		Store:         store,
		APIBaseURL:    DefaultAPIBaseURL,
		HTTPClient:    httpClient,
		StagingRoot:   DefaultStagingRoot,
		JobStatusPath: DefaultJobStatusPath,
		UpdateScript:  DefaultUpdateScript,
		Arch:          runtime.GOARCH,
	}
	s.LaunchDetached = defaultSystemdRunLauncher
	return s
}

func defaultSystemdRunLauncher(scriptPath string, args ...string) error {
	unitName := fmt.Sprintf("da-resourced-updater-%d", time.Now().Unix())
	cmdArgs := append([]string{"--unit=" + unitName, "--collect", scriptPath}, args...)
	cmd := exec.Command("systemd-run", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// GetStatus returns current configuration, cached release info (if any), and the latest update job state.
func (s *Service) GetStatus(_ context.Context) (ipc.UpdaterStatusData, error) {
	cfg, err := s.Store.LoadUpdaterConfig()
	if err != nil {
		return ipc.UpdaterStatusData{}, err
	}

	job := s.readJobStatus()
	data := ipc.UpdaterStatusData{
		CurrentVersion:  version.Version,
		GitHubRepo:      cfg.GitHubRepo,
		HasToken:        cfg.GitHubToken != "",
		MaskedToken:     cfg.MaskedToken(),
		UpdateChannel:   cfg.UpdateChannel,
		BackupRetention: cfg.BackupRetention,
		LastJobState:    job.State,
		LastJobMessage:  job.Message,
	}

	s.mu.Lock()
	rel := s.cachedRel
	sameTarget := s.cachedRepo == cfg.GitHubRepo && s.cachedChan == cfg.UpdateChannel
	s.mu.Unlock()

	if rel != nil && sameTarget {
		data.LatestVersion = rel.TagName
		data.UpdateAvailable = IsNewerVersion(version.Version, rel.TagName)
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

// StageRelease downloads the release archive + checksums.txt, verifies SHA-256, and extracts into a clean staging folder.
func (s *Service) StageRelease(ctx context.Context, targetVersion string) (unpackedRoot string, resolvedTag string, retention int, err error) {
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

	archiveName := fmt.Sprintf("da-resource-limiter-linux-%s.tar.gz", s.Arch)
	var archiveAsset, checksumAsset *githubAsset
	for i := range rel.Assets {
		a := &rel.Assets[i]
		if a.Name == archiveName {
			archiveAsset = a
		} else if a.Name == "checksums.txt" {
			checksumAsset = a
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

	stageDir := filepath.Join(s.StagingRoot, sanitizeTag(rel.TagName))
	_ = os.RemoveAll(stageDir)
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return "", "", 0, fmt.Errorf("create staging dir: %w", err)
	}

	checksumPath := filepath.Join(stageDir, "checksums.txt")
	if err := s.downloadAsset(ctx, cfg, *checksumAsset, checksumPath); err != nil {
		s.writeJobStatus("failed", "Download checksums.txt failed: "+err.Error(), rel.TagName)
		return "", "", 0, err
	}

	expectedSHA, err := lookupChecksum(checksumPath, archiveName)
	if err != nil {
		s.writeJobStatus("failed", err.Error(), rel.TagName)
		return "", "", 0, err
	}

	s.writeJobStatus("staging", fmt.Sprintf("Downloading %s (%s)...", archiveName, rel.TagName), rel.TagName)
	archivePath := filepath.Join(stageDir, archiveName)
	if err := s.downloadAsset(ctx, cfg, *archiveAsset, archivePath); err != nil {
		s.writeJobStatus("failed", "Download archive failed: "+err.Error(), rel.TagName)
		return "", "", 0, err
	}

	actualSHA, err := computeFileSHA256(archivePath)
	if err != nil {
		return "", "", 0, err
	}
	if !strings.EqualFold(actualSHA, expectedSHA) {
		_ = os.RemoveAll(stageDir)
		err = fmt.Errorf("SHA-256 verification failed for %s: expected %s, got %s", archiveName, expectedSHA, actualSHA)
		s.writeJobStatus("failed", err.Error(), rel.TagName)
		return "", "", 0, err
	}

	unpackDir := filepath.Join(stageDir, "unpacked")
	if err := extractTarGzSafe(archivePath, unpackDir); err != nil {
		_ = os.RemoveAll(stageDir)
		s.writeJobStatus("failed", "Archive extraction failed: "+err.Error(), rel.TagName)
		return "", "", 0, err
	}

	pkgRoot := filepath.Join(unpackDir, "da-resource-limiter")
	if st, err := os.Stat(pkgRoot); err != nil || !st.IsDir() {
		pkgRoot = unpackDir
	}

	return pkgRoot, rel.TagName, cfg.BackupRetention, nil
}

// TriggerUpdate stages the verified GitHub Release and launches scripts/update.sh in an independent transient systemd unit.
func (s *Service) TriggerUpdate(ctx context.Context, targetVersion string) (string, error) {
	pkgRoot, resolvedTag, retention, err := s.StageRelease(ctx, targetVersion)
	if err != nil {
		return "", err
	}

	// Prefer the newly verified update.sh inside the staged release if present, falling back to installed script
	scriptToRun := s.UpdateScript
	stagedScript := filepath.Join(pkgRoot, "scripts", "update.sh")
	if st, err := os.Stat(stagedScript); err == nil && !st.IsDir() {
		_ = os.Chmod(stagedScript, 0o700)
		scriptToRun = stagedScript
	}

	s.writeJobStatus("running", fmt.Sprintf("Verified SHA-256 for %s; executing atomic swap & healthcheck...", resolvedTag), resolvedTag)
	if err := s.LaunchDetached(scriptToRun, "apply", pkgRoot, resolvedTag, strconv.Itoa(retention)); err != nil {
		s.writeJobStatus("failed", err.Error(), resolvedTag)
		return "", err
	}

	return fmt.Sprintf("Update job started for %s (SHA-256 verified, automatic rollback armed)", resolvedTag), nil
}

// TriggerRollback launches scripts/update.sh rollback in an independent transient systemd unit.
func (s *Service) TriggerRollback(_ context.Context) (string, error) {
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
	pkgRoot, resolvedTag, retention, err := s.StageRelease(ctx, targetVersion)
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
	return cmd.Run()
}

// RunCLIRollback performs a synchronous snapshot rollback directly in the caller's terminal.
func (s *Service) RunCLIRollback(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.UpdateScript, "rollback")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (s *Service) fetchTargetRelease(ctx context.Context, cfg config.UpdaterConfig, explicitTag string, bypassCache bool) (*githubRelease, error) {
	explicitTag = strings.TrimSpace(explicitTag)
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
		url := fmt.Sprintf("%s/repos/%s/releases/tags/%s", base, cfg.GitHubRepo, explicitTag)
		var rel githubRelease
		if err := s.getJSON(ctx, url, cfg.GitHubToken, &rel); err != nil {
			return nil, err
		}
		return &rel, nil
	}

	if cfg.UpdateChannel == "beta" {
		url := fmt.Sprintf("%s/repos/%s/releases?per_page=10", base, cfg.GitHubRepo)
		var list []githubRelease
		if err := s.getJSON(ctx, url, cfg.GitHubToken, &list); err != nil {
			return nil, err
		}
		for i := range list {
			if !list[i].Draft {
				return &list[i], nil
			}
		}
		return nil, errors.New("no published releases found in repository")
	}

	url := fmt.Sprintf("%s/repos/%s/releases/latest", base, cfg.GitHubRepo)
	var rel githubRelease
	if err := s.getJSON(ctx, url, cfg.GitHubToken, &rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func (s *Service) getJSON(ctx context.Context, url, token string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
		return fmt.Errorf("GitHub API %s returned HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(bodySnippet)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(out)
}

func (s *Service) downloadAsset(ctx context.Context, cfg config.UpdaterConfig, asset githubAsset, destPath string) error {
	// Critical for Private GitHub Repos: browser_download_url returns 404 with API tokens;
	// use the REST Asset endpoint (/releases/assets/{id}) with Accept: application/octet-stream.
	downloadURL := asset.BrowserDownloadURL
	useAssetAPI := strings.TrimSpace(cfg.GitHubToken) != "" || downloadURL == ""
	if useAssetAPI {
		if asset.URL != "" {
			downloadURL = asset.URL
		} else {
			downloadURL = fmt.Sprintf("%s/repos/%s/releases/assets/%d", strings.TrimRight(s.APIBaseURL, "/"), cfg.GitHubRepo, asset.ID)
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
			return strings.ToLower(hash), nil
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

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		rel := filepath.Clean(strings.TrimLeft(hdr.Name, "/\\"))
		if rel == "." || strings.HasPrefix(rel, "..") {
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
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, io.LimitReader(tr, maxArchiveDownloadSize)); err != nil {
				_ = outFile.Close()
				return err
			}
			_ = outFile.Close()
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
	if b.Len() == 0 {
		return "release"
	}
	return b.String()
}
