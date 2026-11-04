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
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/shostwp-byte/da-resourcelimiter/internal/cgroup"
	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
	"github.com/shostwp-byte/da-resourcelimiter/internal/dausers"
	"github.com/shostwp-byte/da-resourcelimiter/internal/fpm"
	"github.com/shostwp-byte/da-resourcelimiter/internal/ipc"
	"github.com/shostwp-byte/da-resourcelimiter/internal/version"
)

const (
	DefaultDataDir        = "/usr/local/directadmin/plugins/da_resource_limiter/data"
	DefaultUpdaterCfgPath = "/etc/da-resourced/updater.conf"
	DefaultDAUsersDir     = "/usr/local/directadmin/data/users"
	DefaultPasswdPath     = "/etc/passwd"
	DefaultSystemdDir     = "/etc/systemd/system"
	DefaultCgroupRoot     = "/sys/fs/cgroup"
	DefaultProcRoot       = "/proc"
)

type runtimeEnv struct {
	store    *config.Store
	registry *dausers.Registry
	cgMgr    *cgroup.Manager
	daDir    string
}

func newRuntimeEnv() *runtimeEnv {
	dataDir := getenvOr("DA_LIMITER_DATA_DIR", DefaultDataDir)
	updaterPath := getenvOr("DA_LIMITER_UPDATER_CONF", DefaultUpdaterCfgPath)
	daUsersDir := getenvOr("DA_LIMITER_DA_USERS_DIR", DefaultDAUsersDir)
	passwdPath := getenvOr("DA_LIMITER_PASSWD_PATH", DefaultPasswdPath)
	systemdDir := getenvOr("DA_LIMITER_SYSTEMD_DIR", DefaultSystemdDir)
	cgroupRoot := getenvOr("DA_LIMITER_CGROUP_ROOT", DefaultCgroupRoot)

	return &runtimeEnv{
		store:    config.NewStore(dataDir, updaterPath),
		registry: dausers.NewRegistry(daUsersDir, passwdPath),
		cgMgr:    cgroup.NewManager(systemdDir, cgroupRoot, nil),
		daDir:    daUsersDir,
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[da-resourced] ")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	switch subcmd {
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

	case "remove":
		if err := runRemoveUser(os.Args[2:]); err != nil {
			log.Fatalf("remove failed: %v", err)
		}

	case "stats":
		if err := runStats(os.Args[2:]); err != nil {
			log.Fatalf("stats failed: %v", err)
		}

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n", subcmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("%s\n\nUsage:\n", version.Info())
	fmt.Println("  da-resourced serve                  Run background resource governor daemon")
	fmt.Println("  da-resourced apply <username>       Apply OS & PHP-FPM limits to a DirectAdmin user")
	fmt.Println("  da-resourced apply-all              Batch-apply limits to all DirectAdmin users")
	fmt.Println("  da-resourced remove <username>      Remove slice drop-in & override config for a user")
	fmt.Println("  da-resourced stats [username] [--json]  Show live Cgroups v2 usage metrics")
	fmt.Println("  da-resourced version                Print build version information")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	scanInterval := fs.Duration("fpm-interval", 1*time.Second, "PHP-FPM / lsphp /proc classification interval")
	reloadInterval := fs.Duration("users-reload-interval", 30*time.Second, "DirectAdmin user registry refresh interval")
	if err := fs.Parse(args); err != nil {
		return err
	}

	env := newRuntimeEnv()
	if err := env.cgMgr.VerifyUnifiedHierarchy(); err != nil {
		return err
	}
	if err := env.store.MigrateDefaultKeys(); err != nil {
		log.Printf("warning: default.conf migration: %v", err)
	}
	if err := env.registry.Reload(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Ensure all active users have slices & da-php.scope ready on boot (even before SSH/Cron login)
	if err := syncAllSlices(ctx, env); err != nil {
		log.Printf("warning: initial slice sync encountered errors: %v", err)
	}

	procRoot := getenvOr("DA_LIMITER_PROC_ROOT", DefaultProcRoot)
	classifier := fpm.NewClassifier(procRoot, env.registry, env.cgMgr, func(acct dausers.Account) bool {
		lim, err := env.store.ResolveUserLimits(acct.Username, acct.Package)
		return err == nil && lim.Enabled
	})

	log.Printf("started %s | managed_users=%d | fpm_interval=%s", version.Info(), env.registry.Count(), *scanInterval)

	fpmTicker := time.NewTicker(*scanInterval)
	defer fpmTicker.Stop()

	reloadTicker := time.NewTicker(*reloadInterval)
	defer reloadTicker.Stop()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)

	for {
		select {
		case <-ctx.Done():
			log.Printf("shutting down gracefully...")
			return nil

		case <-sighupCh:
			log.Printf("received SIGHUP: reloading DirectAdmin user registry & slices")
			if err := env.registry.Reload(); err != nil {
				log.Printf("reload registry error: %v", err)
			}
			if err := syncAllSlices(ctx, env); err != nil {
				log.Printf("sync slices error: %v", err)
			}

		case <-reloadTicker.C:
			if err := env.registry.Reload(); err != nil {
				log.Printf("periodic registry reload error: %v", err)
			}

		case <-fpmTicker.C:
			if _, err := classifier.ScanOnce(ctx, 0); err != nil {
				log.Printf("PHP-FPM classifier scan error: %v", err)
			}
		}
	}
}

func runApplyUser(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: da-resourced apply <username>")
	}
	username := args[0]
	if err := config.ValidateIdentifier(username); err != nil {
		return err
	}

	env := newRuntimeEnv()
	if err := env.cgMgr.VerifyUnifiedHierarchy(); err != nil {
		return err
	}
	if err := env.registry.Reload(); err != nil {
		return err
	}

	acct, ok := env.registry.LookupByName(username)
	if !ok {
		return fmt.Errorf("DirectAdmin hosting user %q not found (or excluded system/admin user)", username)
	}

	limits, err := env.store.ResolveUserLimits(acct.Username, acct.Package)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if err := env.cgMgr.ApplyUserSlice(ctx, acct.UID, limits); err != nil {
		return err
	}
	if err := fpm.SyncDAUserPHPConf(env.daDir, acct.Username, limits); err != nil {
		log.Printf("warning: sync DirectAdmin user.conf tokens for %s: %v", acct.Username, err)
	}

	// Immediately classify any active PHP workers belonging to this user
	procRoot := getenvOr("DA_LIMITER_PROC_ROOT", DefaultProcRoot)
	cls := fpm.NewClassifier(procRoot, env.registry, env.cgMgr, nil)
	moved, _ := cls.ScanOnce(ctx, acct.UID)

	log.Printf("applied limits for user=%s (uid=%d, pkg=%s, cpu=%d%%, mem=%d/%dMB, moved_php_pids=%d)",
		acct.Username, acct.UID, acct.Package, limits.CPUQuota, limits.MemHighMB, limits.MemMaxMB, moved)
	return nil
}

func runApplyAll() error {
	env := newRuntimeEnv()
	if err := env.cgMgr.VerifyUnifiedHierarchy(); err != nil {
		return err
	}
	if err := env.registry.Reload(); err != nil {
		return err
	}
	return syncAllSlices(context.Background(), env)
}

func syncAllSlices(ctx context.Context, env *runtimeEnv) error {
	accounts := env.registry.All()
	anyChanged := false
	var activeAccounts []dausers.Account

	for _, acct := range accounts {
		limits, err := env.store.ResolveUserLimits(acct.Username, acct.Package)
		if err != nil {
			log.Printf("skip %s: resolve limits error: %v", acct.Username, err)
			continue
		}
		changed, err := env.cgMgr.StageUserSlice(acct.UID, limits)
		if err != nil {
			log.Printf("skip %s (uid %d): stage slice error: %v", acct.Username, acct.UID, err)
			continue
		}
		if changed {
			anyChanged = true
		}
		if limits.Enabled {
			activeAccounts = append(activeAccounts, acct)
		}
		_ = fpm.SyncDAUserPHPConf(env.daDir, acct.Username, limits)
	}

	if anyChanged {
		if err := env.cgMgr.ReloadSystemd(ctx); err != nil {
			return err
		}
	}

	for _, acct := range activeAccounts {
		if err := env.cgMgr.EnsureSliceAndPHPScope(ctx, acct.UID); err != nil {
			log.Printf("ensure slice %s (uid %d): %v", acct.Username, acct.UID, err)
		}
	}

	log.Printf("synced Cgroups v2 slices for %d/%d DirectAdmin users (daemon_reloaded=%v)",
		len(activeAccounts), len(accounts), anyChanged)
	return nil
}

func runRemoveUser(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: da-resourced remove <username>")
	}
	username := args[0]
	if err := config.ValidateIdentifier(username); err != nil {
		return err
	}

	env := newRuntimeEnv()
	_ = env.registry.Reload()
	if acct, ok := env.registry.LookupByName(username); ok {
		if err := env.cgMgr.RemoveUserSlice(context.Background(), acct.UID); err != nil {
			return err
		}
	}
	return env.store.DeleteUserLimits(username)
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

	env := newRuntimeEnv()
	if err := env.registry.Reload(); err != nil {
		return err
	}

	var accounts []dausers.Account
	if targetUser != "" {
		acct, ok := env.registry.LookupByName(targetUser)
		if !ok {
			return fmt.Errorf("user %q not found", targetUser)
		}
		accounts = []dausers.Account{acct}
	} else {
		accounts = env.registry.All()
	}

	snapshots := make([]ipc.UserUsageSnapshot, 0, len(accounts))
	for _, acct := range accounts {
		limits, err := env.store.ResolveUserLimits(acct.Username, acct.Package)
		if err != nil {
			continue
		}
		st, _ := env.cgMgr.ReadSliceStats(acct.UID)
		snapshots = append(snapshots, ipc.UserUsageSnapshot{
			Username:         acct.Username,
			UID:              acct.UID,
			Package:          acct.Package,
			CPUPercent:       st.CPUPercent,
			MemoryCurrentMB:  st.MemoryCurrentMB,
			ActiveProcesses:  st.ActiveProcesses,
			MemoryHighEvents: st.MemoryHighEvents,
			OOMKillEvents:    st.OOMKillEvents,
			Limits:           limits,
		})
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snapshots)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USER\tUID\tPACKAGE\tCPU %\tRAM (MB)\tPROCS\tTHROTTLES\tOOM KILLS")
	for _, s := range snapshots {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%.1f / %d%%\t%.1f / %d\t%d / %d\t%d\t%d\n",
			s.Username, s.UID, s.Package,
			s.CPUPercent, s.Limits.CPUQuota,
			s.MemoryCurrentMB, s.Limits.MemMaxMB,
			s.ActiveProcesses, s.Limits.TasksMax,
			s.MemoryHighEvents, s.OOMKillEvents,
		)
	}
	return tw.Flush()
}

func getenvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
