package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/cgroup"
	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
	"github.com/shostwp-byte/da-resourcelimiter/internal/engine"
	"github.com/shostwp-byte/da-resourcelimiter/internal/fpm"
	"github.com/shostwp-byte/da-resourcelimiter/internal/ipc"
	"github.com/shostwp-byte/da-resourcelimiter/internal/logger"
	"github.com/shostwp-byte/da-resourcelimiter/internal/mysqlgov"
	"github.com/shostwp-byte/da-resourcelimiter/internal/updater"
	"github.com/shostwp-byte/da-resourcelimiter/internal/version"
)

const (
	DefaultDataDir        = "/usr/local/directadmin/plugins/da_resource_limiter/data"
	DefaultUpdaterCfgPath = "/etc/da-resourced/updater.conf"
	DefaultDADataRoot     = "/usr/local/directadmin/data"
	DefaultPasswdPath     = "/etc/passwd"
	DefaultSystemdDir     = "/etc/systemd/system"
	DefaultCgroupRoot     = "/sys/fs/cgroup"
	DefaultProcRoot       = "/proc"
)

func buildEngine() (*engine.Engine, *updater.Service) {
	dataDir := getenvOr("DA_LIMITER_DATA_DIR", DefaultDataDir)
	updaterPath := getenvOr("DA_LIMITER_UPDATER_CONF", DefaultUpdaterCfgPath)
	daDataRoot := getenvOr("DA_LIMITER_DA_DATA_ROOT", DefaultDADataRoot)
	daUsersDir := getenvOr("DA_LIMITER_DA_USERS_DIR", filepath.Join(daDataRoot, "users"))
	passwdPath := getenvOr("DA_LIMITER_PASSWD_PATH", DefaultPasswdPath)
	systemdDir := getenvOr("DA_LIMITER_SYSTEMD_DIR", DefaultSystemdDir)
	cgroupRoot := getenvOr("DA_LIMITER_CGROUP_ROOT", DefaultCgroupRoot)
	procRoot := getenvOr("DA_LIMITER_PROC_ROOT", DefaultProcRoot)
	logPath := getenvOr("DA_LIMITER_LOG_PATH", logger.DefaultLogPath)
	penaltyPath := getenvOr("DA_LIMITER_PENALTY_PATH", mysqlgov.DefaultPenaltyStatePath)

	store := config.NewStore(dataDir, updaterPath)
	reg := dausers.NewRegistry(daUsersDir, passwdPath)
	cgMgr := cgroup.NewManager(systemdDir, cgroupRoot, nil)
	vlog := logger.NewViolationLogger(logPath, logger.DefaultMaxBytes, logger.DefaultMaxBackups)

	cls := fpm.NewClassifier(procRoot, reg, cgMgr, func(acct dausers.Account) bool {
		lim, err := store.ResolveUserLimits(acct.Username, acct.Package)
		return err == nil && lim.Enabled
	})

	sqlRunner := mysqlgov.NewCLIMySQLRunner("", "", "")
	gov := mysqlgov.NewGovernor(sqlRunner, reg, func(acct dausers.Account) (config.ResourceLimits, error) {
		return store.ResolveUserLimits(acct.Username, acct.Package)
	}, vlog, penaltyPath)

	upd := updater.NewService(store)
	eng := engine.New(store, reg, cgMgr, cls, gov, vlog, daDataRoot, passwdPath)
	eng.Updater = upd
	return eng, upd
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[da-resourced] ")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println(version.Info())

	case "ping":
		if err := runPing(os.Args[2:]); err != nil {
			log.Fatalf("ping failed: %v", err)
		}

	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			log.Fatalf("daemon fatal error: %v", err)
		}

	case "apply":
		if err := runApplyUser(os.Args[2:]); err != nil {
			log.Fatalf("apply failed: %v", err)
		}

	case "apply-all":
		if err := runApplyAll(); err != nil {
			log.Fatalf("apply-all failed: %v", err)
		}

	case "apply-package":
		if err := runApplyPackage(os.Args[2:]); err != nil {
			log.Fatalf("apply-package failed: %v", err)
		}

	case "apply-db-user":
		if err := runApplyDBUser(os.Args[2:]); err != nil {
			log.Fatalf("apply-db-user failed: %v", err)
		}

	case "remove":
		if err := runRemoveUser(os.Args[2:]); err != nil {
			log.Fatalf("remove failed: %v", err)
		}

	case "unblock":
		if err := runUnblock(os.Args[2:]); err != nil {
			log.Fatalf("unblock failed: %v", err)
		}

	case "stats":
		if err := runStats(os.Args[2:]); err != nil {
			log.Fatalf("stats failed: %v", err)
		}

	case "audit-mycnf":
		if err := runAuditMyCnf(os.Args[2:]); err != nil {
			log.Fatalf("audit-mycnf failed: %v", err)
		}

	case "check-update":
		if err := runCheckUpdate(); err != nil {
			log.Fatalf("check-update failed: %v", err)
		}

	case "config-updater":
		if err := runConfigUpdater(os.Args[2:]); err != nil {
			log.Fatalf("config-updater failed: %v", err)
		}

	case "update":
		if err := runUpdate(os.Args[2:]); err != nil {
			log.Fatalf("update failed: %v", err)
		}

	case "rollback":
		if err := runRollback(); err != nil {
			log.Fatalf("rollback failed: %v", err)
		}

	case "keygen":
		if err := runKeygen(); err != nil {
			log.Fatalf("keygen failed: %v", err)
		}

	case "sign":
		if err := runSign(os.Args[2:]); err != nil {
			log.Fatalf("sign failed: %v", err)
		}

	case "verify":
		if err := runVerify(os.Args[2:]); err != nil {
			log.Fatalf("verify failed: %v", err)
		}

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("%s\n\nUsage:\n", version.Info())
	fmt.Println("  da-resourced serve                           Run root daemon (Cgroups v2 + MariaDB Governor + IPC Socket)")
	fmt.Println("  da-resourced ping                            Healthcheck live daemon over Unix socket")
	fmt.Println("  da-resourced apply <username>                Apply OS, PHP-FPM & MariaDB limits for a user")
	fmt.Println("  da-resourced apply-all                       Batch-apply limits to all DirectAdmin users")
	fmt.Println("  da-resourced apply-package <package>         Sync limits to all non-overridden users in package")
	fmt.Println("  da-resourced apply-db-user <user> <db_user>  Enforce MariaDB limits on a newly created DB user")
	fmt.Println("  da-resourced remove <username>               Remove slice drop-in, DB limits & override config")
	fmt.Println("  da-resourced unblock <username>              Immediately lift MySQL Penalty Box for a user")
	fmt.Println("  da-resourced stats [username] [--json]       Display live Cgroups v2 & MariaDB usage metrics")
	fmt.Println("  da-resourced audit-mycnf [/etc/my.cnf]       Audit MariaDB Tier-1 per-thread memory settings")
	fmt.Println("  da-resourced check-update                    Check GitHub Releases for newer version")
	fmt.Println("  da-resourced config-updater [flags]          Update /etc/da-resourced/updater.conf as root")
	fmt.Println("  da-resourced update [--version vX.Y.Z]       Download, verify Ed25519 + SHA-256 & atomically update (--allow-downgrade to force)")
	fmt.Println("  da-resourced rollback                        Restore previous snapshot from /var/backups/da-resource-limiter")
	fmt.Println("  da-resourced verify <file> [sigfile]         Verify Ed25519 detached signature against embedded public key")
	fmt.Println("  da-resourced sign <file> [--out sigfile]     Sign file using RELEASE_SIGNING_PRIVATE_KEY env var")
	fmt.Println("  da-resourced keygen                          Generate a new Ed25519 release-signing keypair")
	fmt.Println("  da-resourced version                         Print build version information")
}

func runPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	sock := fs.String("sock", ipc.DefaultAdminSocketPath, "Admin Unix socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resp, err := ipc.SendRequest(ctx, *sock, ipc.Request{Action: ipc.ActionPing})
	if err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp.Data)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fpmInterval := fs.Duration("fpm-interval", 1*time.Second, "PHP-FPM / lsphp /proc classification interval")
	mysqlInterval := fs.Duration("mysql-interval", 1500*time.Millisecond, "MariaDB PROCESSLIST watchdog interval")
	oomInterval := fs.Duration("oom-interval", 5*time.Second, "Cgroup v2 memory.events OOM polling interval")
	reloadInterval := fs.Duration("users-reload-interval", 30*time.Second, "DirectAdmin user registry refresh interval")
	adminSock := fs.String("admin-sock", ipc.DefaultAdminSocketPath, "Privileged Admin/Hooks Unix socket path")
	userSock := fs.String("user-sock", ipc.DefaultUserSocketPath, "Read-only Customer SO_PEERCRED Unix socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	eng, _ := buildEngine()
	if err := eng.CgroupMgr.VerifyUnifiedHierarchy(); err != nil {
		return err
	}
	if err := eng.Store.MigrateDefaultKeys(); err != nil {
		log.Printf("warning: default.conf migration: %v", err)
	}
	if err := eng.Registry.Reload(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	detectCtx, detectCancel := context.WithTimeout(ctx, 10*time.Second)
	if err := eng.MySQLGov.DetectCapabilities(detectCtx); err != nil {
		log.Printf("warning: MariaDB MEMORY_USED probe failed (falling back to thread/time watchdog): %v", err)
	}
	detectCancel()

	initCtx, initCancel := context.WithTimeout(ctx, 2*time.Minute)
	if err := eng.ApplyAll(initCtx); err != nil {
		log.Printf("warning: initial user limits sync: %v", err)
	}
	initCancel()
	eng.CheckOOMEvents()

	ipcServer := ipc.NewServer(*adminSock, *userSock, eng)
	if err := ipcServer.Start(ctx); err != nil {
		return err
	}

	log.Printf("started %s | users=%d | fpm=%s | mysql=%s | sock=%s",
		version.Info(), eng.Registry.Count(), *fpmInterval, *mysqlInterval, *adminSock)

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)

	var wg sync.WaitGroup
	eng.StartBackgroundWorker(ctx, &wg)

	// 1. Independent PHP-FPM / OpenLiteSpeed PID Classifier goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(*fpmInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				scanCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				if _, err := eng.Classifier.ScanOnce(scanCtx, 0); err != nil && ctx.Err() == nil {
					log.Printf("PHP-FPM classifier scan error: %v", err)
				}
				cancel()
			}
		}
	}()

	// 2. Independent MariaDB PROCESSLIST Watchdog goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(*mysqlInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pollCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				if _, err := eng.MySQLGov.PollOnce(pollCtx); err != nil && ctx.Err() == nil {
					log.Printf("MariaDB watchdog poll error: %v", err)
				}
				cancel()
			}
		}
	}()

	// 3. Independent Cgroups v2 OOM Event Monitor goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(*oomInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				eng.CheckOOMEvents()
			}
		}
	}()

	// 4. Independent DirectAdmin Registry Reload, Orphan Slice Pruner & SIGHUP Sync goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(*reloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighupCh:
				log.Printf("received SIGHUP: reloading DirectAdmin user registry & limits")
				_ = eng.Registry.Reload()
				syncCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
				if err := eng.ApplyAll(syncCtx); err != nil && ctx.Err() == nil {
					log.Printf("SIGHUP ApplyAll error: %v", err)
				}
				cancel()
			case <-ticker.C:
				if err := eng.Registry.Reload(); err != nil {
					log.Printf("periodic registry reload error: %v", err)
					continue
				}
				pruneCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				eng.PruneOrphans(pruneCtx)
				cancel()
			}
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down gracefully...")
	ipcServer.Wait()
	wg.Wait()
	return nil
}

func runApplyUser(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: da-resourced apply <username>")
	}
	resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:   ipc.ActionApplyUserLimits,
		Username: args[0],
	})
	if err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}
	if !ipc.IsDialError(err) {
		return fmt.Errorf("daemon IPC request failed (skipping local fallback while daemon is reachable): %w", err)
	}

	eng, _ := buildEngine()
	if err := eng.CgroupMgr.VerifyUnifiedHierarchy(); err != nil {
		return err
	}
	if err := eng.Registry.Reload(); err != nil {
		return err
	}
	return eng.ApplyUser(context.Background(), args[0])
}

func runApplyAll() error {
	eng, _ := buildEngine()
	if err := eng.CgroupMgr.VerifyUnifiedHierarchy(); err != nil {
		return err
	}
	if err := eng.Registry.Reload(); err != nil {
		return err
	}
	return eng.ApplyAll(context.Background())
}

func runApplyPackage(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: da-resourced apply-package <package>")
	}
	resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:  ipc.ActionApplyPackageLimits,
		Package: args[0],
	})
	if err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}
	if !ipc.IsDialError(err) {
		return fmt.Errorf("daemon IPC request failed (skipping local fallback while daemon is reachable): %w", err)
	}

	eng, _ := buildEngine()
	if err := eng.CgroupMgr.VerifyUnifiedHierarchy(); err != nil {
		return err
	}
	if err := eng.Registry.Reload(); err != nil {
		return err
	}
	synced, err := eng.ApplyPackage(context.Background(), args[0])
	if err != nil {
		return err
	}
	log.Printf("synced %d users in package %q", synced, args[0])
	return nil
}

func runApplyDBUser(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: da-resourced apply-db-user <da_username> <db_username>")
	}
	resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:   ipc.ActionApplyDBUser,
		Username: args[0],
		DBUser:   args[1],
	})
	if err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}
	if !ipc.IsDialError(err) {
		return fmt.Errorf("daemon IPC request failed (skipping local fallback while daemon is reachable): %w", err)
	}

	eng, _ := buildEngine()
	_ = eng.Registry.Reload()
	return eng.ApplyNewDBUser(context.Background(), args[0], args[1])
}

func runRemoveUser(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: da-resourced remove <username>")
	}
	resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:   ipc.ActionRemoveUser,
		Username: args[0],
	})
	if err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}
	if !ipc.IsDialError(err) {
		return fmt.Errorf("daemon IPC request failed (skipping local fallback while daemon is reachable): %w", err)
	}

	eng, _ := buildEngine()
	_ = eng.Registry.Reload()
	return eng.RemoveUser(context.Background(), args[0])
}

func runUnblock(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: da-resourced unblock <username>")
	}
	resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:   ipc.ActionUnblockPenalty,
		Username: args[0],
	})
	if err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}
	if !ipc.IsDialError(err) {
		return fmt.Errorf("daemon IPC request failed (skipping local fallback while daemon is reachable): %w", err)
	}

	eng, _ := buildEngine()
	_ = eng.Registry.Reload()
	return eng.MySQLGov.UnblockUser(context.Background(), args[0])
}

func runStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "Output stats as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	targetUser := ""
	if fs.NArg() > 0 {
		targetUser = fs.Arg(0)
	}

	eng, _ := buildEngine()
	if err := eng.Registry.Reload(); err != nil {
		return err
	}

	var accounts []dausers.Account
	if targetUser != "" {
		acct, ok := eng.Registry.LookupByName(targetUser)
		if !ok {
			return fmt.Errorf("user %q not found", targetUser)
		}
		accounts = []dausers.Account{acct}
	} else {
		accounts = eng.Registry.All()
	}

	snapshots := make([]ipc.UserUsageSnapshot, 0, len(accounts))
	for _, acct := range accounts {
		snapshots = append(snapshots, eng.BuildUserSnapshot(acct, true))
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snapshots)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USER\tUID\tPKG\tCPU %\tRAM (MB)\tPROCS\tMYSQL RAM\tMYSQL CONNS\tOOM(24h)\tPENALTY")
	for _, s := range snapshots {
		penState := "no"
		if s.PenaltyActive {
			penState = "THROTTLED"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%.1f / %d%%\t%.1f / %d\t%d / %d\t%.1f / %dMB\t%d / %d\t%d\t%s\n",
			s.Username, s.UID, s.Package,
			s.CPUPercent, s.Limits.CPUQuota,
			s.MemoryCurrentMB, s.Limits.MemMaxMB,
			s.ActiveProcesses, s.Limits.TasksMax,
			s.MySQLMemoryMB, s.Limits.MySQLMaxMemMB,
			s.MySQLTotalConns, s.Limits.MySQLMaxConnections,
			s.OOMKills24h, penState,
		)
	}
	return tw.Flush()
}

func runAuditMyCnf(args []string) error {
	path := "/etc/my.cnf"
	if len(args) > 0 {
		path = args[0]
	}
	findings, err := mysqlgov.AuditMyCnf(path)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Audit of %s:\nKEY\tCURRENT\tRECOMMENDED\tSTATUS\n", path)
	for _, f := range findings {
		status := "MISSING"
		cur := "-"
		if f.Present {
			status = "SET"
			cur = f.Actual
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Key, cur, f.Recommended, status)
	}
	_ = tw.Flush()
	fmt.Printf("\nRecommended snippet:\n\n%s", mysqlgov.RecommendedMyCnfSnippet())
	return nil
}

func runCheckUpdate() error {
	_, upd := buildEngine()
	st, err := upd.CheckLatest(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("Repository      : %s (%s)\n", st.GitHubRepo, st.UpdateChannel)
	fmt.Printf("Current Version : %s\n", st.CurrentVersion)
	fmt.Printf("Latest Version  : %s\n", st.LatestVersion)
	fmt.Printf("Update Available: %v\n", st.UpdateAvailable)
	if st.ReleaseNotes != "" {
		fmt.Printf("\nRelease Notes:\n%s\n", st.ReleaseNotes)
	}
	return nil
}

func runConfigUpdater(args []string) error {
	fs := flag.NewFlagSet("config-updater", flag.ContinueOnError)
	channel := fs.String("channel", "", "Release channel: stable or beta")
	retention := fs.Int("retention", 0, "Backup snapshot retention (1..30)")
	tokenStdin := fs.Bool("token-stdin", false, "Read GitHub Personal Access Token safely from stdin")
	clearToken := fs.Bool("clear-token", false, "Remove stored GitHub token")
	if err := fs.Parse(args); err != nil {
		return err
	}

	eng, _ := buildEngine()
	cfg, err := eng.Store.LoadUpdaterConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if *channel != "" {
		cfg.UpdateChannel = *channel
	}
	if *retention > 0 {
		cfg.BackupRetention = *retention
	}
	if *clearToken {
		cfg.GitHubToken = ""
	} else if *tokenStdin {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return err
		}
		cfg.GitHubToken = strings.TrimSpace(string(raw))
	}
	if err := eng.Store.SaveUpdaterConfig(cfg); err != nil {
		return err
	}
	log.Printf("saved updater configuration at %s (repo=%s, channel=%s, retention=%d)",
		eng.Store.UpdaterCfgPath, cfg.GitHubRepo, cfg.UpdateChannel, cfg.BackupRetention)
	return nil
}

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	targetVer := fs.String("version", "", "Optional specific release tag (e.g. v1.0.4.2); defaults to latest")
	allowDowngrade := fs.Bool("allow-downgrade", false, "Allow installing a release older than the currently running version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, upd := buildEngine()
	return upd.RunCLIUpdateWithOptions(context.Background(), *targetVer, *allowDowngrade)
}

func runRollback() error {
	_, upd := buildEngine()
	return upd.RunCLIRollback(context.Background())
}

func runKeygen() error {
	pub, priv, err := updater.GenerateKeypairHex()
	if err != nil {
		return err
	}
	fmt.Printf("PUBLIC_KEY_HEX=%s\n", pub)
	fmt.Printf("PRIVATE_KEY_HEX=%s\n", priv)
	return nil
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	outPath := fs.String("out", "", "Detached signature output file (default: <file>.sig)")
	keyFile := fs.String("key-file", "", "Optional file containing hex-encoded Ed25519 private key (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("usage: da-resourced sign [--out sigfile] [--key-file path] <file>")
	}
	targetFile := fs.Arg(0)

	privHex := strings.TrimSpace(os.Getenv("RELEASE_SIGNING_PRIVATE_KEY"))
	if *keyFile != "" {
		rawKey, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		privHex = strings.TrimSpace(string(rawKey))
	}
	if privHex == "" {
		return errors.New("RELEASE_SIGNING_PRIVATE_KEY env var or --key-file is required")
	}

	data, err := os.ReadFile(targetFile)
	if err != nil {
		return err
	}
	sigHex, err := updater.SignDataHex(privHex, data)
	if err != nil {
		return err
	}

	dest := *outPath
	if dest == "" {
		dest = targetFile + ".sig"
	}
	content := fmt.Sprintf("%s  %s\n", sigHex, filepath.Base(targetFile))
	if dest == "-" {
		_, err = os.Stdout.WriteString(content)
		return err
	}
	return os.WriteFile(dest, []byte(content), 0o644)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubHex := fs.String("pubkey", version.DefaultReleasePublicKeyHex, "Hex-encoded Ed25519 release public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("usage: da-resourced verify [--pubkey hex] <file> [sigfile]")
	}
	targetFile := fs.Arg(0)
	sigFile := targetFile + ".sig"
	if fs.NArg() >= 2 {
		sigFile = fs.Arg(1)
	}

	data, err := os.ReadFile(targetFile)
	if err != nil {
		return err
	}
	sigBytes, err := os.ReadFile(sigFile)
	if err != nil {
		return err
	}
	if err := updater.VerifyDataHex(*pubHex, data, string(sigBytes)); err != nil {
		return err
	}
	fmt.Printf("OK: Ed25519 signature verified for %s\n", filepath.Base(targetFile))
	return nil
}

func getenvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
