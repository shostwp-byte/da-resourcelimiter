package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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

func buildEngine() *engine.Engine {
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

	return engine.New(store, reg, cgMgr, cls, gov, vlog, daDataRoot, passwdPath)
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
	fmt.Println("  da-resourced apply <username>                Apply OS, PHP-FPM & MariaDB limits for a user")
	fmt.Println("  da-resourced apply-all                       Batch-apply limits to all DirectAdmin users")
	fmt.Println("  da-resourced apply-package <package>         Sync limits to all non-overridden users in package")
	fmt.Println("  da-resourced apply-db-user <user> <db_user>  Enforce MariaDB limits on a newly created DB user")
	fmt.Println("  da-resourced remove <username>               Remove slice drop-in, DB limits & override config")
	fmt.Println("  da-resourced unblock <username>              Immediately lift MySQL Penalty Box for a user")
	fmt.Println("  da-resourced stats [username] [--json]       Display live Cgroups v2 & MariaDB usage metrics")
	fmt.Println("  da-resourced audit-mycnf [/etc/my.cnf]       Audit MariaDB Tier-1 per-thread memory settings")
	fmt.Println("  da-resourced version                         Print build version information")
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

	eng := buildEngine()
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

	if err := eng.MySQLGov.DetectCapabilities(ctx); err != nil {
		log.Printf("warning: MariaDB MEMORY_USED probe failed (falling back to thread/time watchdog): %v", err)
	}

	if err := eng.ApplyAll(ctx); err != nil {
		log.Printf("warning: initial user limits sync: %v", err)
	}
	eng.CheckOOMEvents() // Seed baseline OOM counters

	ipcServer := ipc.NewServer(*adminSock, *userSock, eng)
	if err := ipcServer.Start(ctx); err != nil {
		return err
	}

	log.Printf("started %s | users=%d | fpm=%s | mysql=%s | sock=%s",
		version.Info(), eng.Registry.Count(), *fpmInterval, *mysqlInterval, *adminSock)

	fpmTicker := time.NewTicker(*fpmInterval)
	defer fpmTicker.Stop()

	mysqlTicker := time.NewTicker(*mysqlInterval)
	defer mysqlTicker.Stop()

	oomTicker := time.NewTicker(*oomInterval)
	defer oomTicker.Stop()

	reloadTicker := time.NewTicker(*reloadInterval)
	defer reloadTicker.Stop()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)

	for {
		select {
		case <-ctx.Done():
			log.Printf("shutting down gracefully...")
			ipcServer.Wait()
			return nil

		case <-sighupCh:
			log.Printf("received SIGHUP: reloading DirectAdmin user registry & limits")
			_ = eng.Registry.Reload()
			_ = eng.ApplyAll(ctx)

		case <-reloadTicker.C:
			if err := eng.Registry.Reload(); err != nil {
				log.Printf("periodic registry reload error: %v", err)
			}

		case <-fpmTicker.C:
			if _, err := eng.Classifier.ScanOnce(ctx, 0); err != nil {
				log.Printf("PHP-FPM classifier scan error: %v", err)
			}

		case <-mysqlTicker.C:
			if _, err := eng.MySQLGov.PollOnce(ctx); err != nil {
				log.Printf("MariaDB watchdog poll error: %v", err)
			}

		case <-oomTicker.C:
			eng.CheckOOMEvents()
		}
	}
}

func runApplyUser(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: da-resourced apply <username>")
	}
	// Prefer routing through running daemon socket if active so live state stays synchronized
	if resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:   ipc.ActionApplyUserLimits,
		Username: args[0],
	}); err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}

	eng := buildEngine()
	if err := eng.CgroupMgr.VerifyUnifiedHierarchy(); err != nil {
		return err
	}
	if err := eng.Registry.Reload(); err != nil {
		return err
	}
	return eng.ApplyUser(context.Background(), args[0])
}

func runApplyAll() error {
	eng := buildEngine()
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
	if resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:  ipc.ActionApplyPackageLimits,
		Package: args[0],
	}); err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}

	eng := buildEngine()
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
	if resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:   ipc.ActionApplyDBUser,
		Username: args[0],
		DBUser:   args[1],
	}); err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}

	eng := buildEngine()
	_ = eng.Registry.Reload()
	return eng.ApplyNewDBUser(context.Background(), args[0], args[1])
}

func runRemoveUser(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: da-resourced remove <username>")
	}
	if resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:   ipc.ActionRemoveUser,
		Username: args[0],
	}); err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}

	eng := buildEngine()
	_ = eng.Registry.Reload()
	return eng.RemoveUser(context.Background(), args[0])
}

func runUnblock(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: da-resourced unblock <username>")
	}
	if resp, err := ipc.SendRequest(context.Background(), ipc.DefaultAdminSocketPath, ipc.Request{
		Action:   ipc.ActionUnblockPenalty,
		Username: args[0],
	}); err == nil {
		if !resp.OK {
			return errors.New(resp.Error)
		}
		log.Println(resp.Message)
		return nil
	}

	eng := buildEngine()
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

	eng := buildEngine()
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

func getenvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
