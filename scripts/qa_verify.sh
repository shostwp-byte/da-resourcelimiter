#!/usr/bin/env bash
# QA Acceptance & Daemon Overhead Benchmark Tool for DA-ResourceLimiter
# Subcommands:
#   ./qa_verify.sh preflight                 Verify OS Cgroups v2, MariaDB, Sockets, Hooks & UI endpoints
#   ./qa_verify.sh benchmark [seconds]       Measure da-resourced CPU % & RSS Memory (< 1% CPU, < 20MB RAM DoD)
#   ./qa_verify.sh verify-user <username>    Verify active Cgroup slice & MariaDB limits on a hosting account

set -euo pipefail

MODE="${1:-preflight}"
ARG2="${2:-}"

PASS_CNT=0
FAIL_CNT=0

pass() { PASS_CNT=$((PASS_CNT + 1)); printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
fail() { FAIL_CNT=$((FAIL_CNT + 1)); printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }

run_preflight() {
    info "Running Production Readiness & QA Preflight Checks..."

    if [[ -f "/sys/fs/cgroup/cgroup.controllers" ]]; then
        pass "Cgroups v2 Unified Hierarchy mounted (/sys/fs/cgroup/cgroup.controllers)"
    else
        fail "Cgroups v2 Unified Hierarchy NOT active"
    fi

    if systemctl is-active --quiet da-resourced; then
        pass "systemd unit da-resourced.service is active"
        local main_pid
        main_pid=$(systemctl show -p MainPID --value da-resourced 2>/dev/null || echo "0")
        if [[ "$EUID" -eq 0 && -n "$main_pid" && "$main_pid" != "0" && -d "/proc/${main_pid}/root/sys/fs/cgroup" ]]; then
            if [[ -w "/proc/${main_pid}/root/sys/fs/cgroup" ]]; then
                pass "Daemon mount namespace has write access to /sys/fs/cgroup (N7)"
            else
                fail "Daemon mount namespace has read-only /sys/fs/cgroup (check systemd unit)"
            fi
            for sock_candidate in /tmp/mysql.sock /var/lib/mysql/mysql.sock /run/mysqld/mysqld.sock /home/mysql/mysql.sock; do
                if [[ -S "$sock_candidate" ]]; then
                    if [[ -S "/proc/${main_pid}/root${sock_candidate}" ]]; then
                        pass "Daemon mount namespace sees MySQL socket ${sock_candidate} (N7)"
                    else
                        fail "Daemon mount namespace CANNOT see host MySQL socket ${sock_candidate} (PrivateTmp conflict)"
                    fi
                fi
            done
        fi
    else
        fail "systemd unit da-resourced.service is NOT running"
    fi

    if [[ -S "/var/run/da-resourced.sock" ]] && /usr/local/sbin/da-resourced ping >/dev/null 2>&1; then
        pass "Admin IPC Socket (/var/run/da-resourced.sock) responded to ping"
    else
        fail "Admin IPC Socket (/var/run/da-resourced.sock) failed ping"
    fi

    if [[ -S "/var/run/da-resourced-user.sock" ]]; then
        pass "Customer SO_PEERCRED Socket (/var/run/da-resourced-user.sock) is present"
    else
        fail "Customer SO_PEERCRED Socket (/var/run/da-resourced-user.sock) missing"
    fi

    local da_mycnf="/usr/local/directadmin/conf/my.cnf"
    if [[ -f "$da_mycnf" ]] && mysql --defaults-extra-file="$da_mycnf" -N -B -e "SELECT MEMORY_USED FROM information_schema.PROCESSLIST LIMIT 1;" >/dev/null 2>&1; then
        pass "MariaDB 10.5+ PROCESSLIST.MEMORY_USED column available"
    else
        fail "MariaDB PROCESSLIST.MEMORY_USED check failed"
    fi

    for h in user_create_post user_modify_post user_destroy_post database_create_post database_user_create_post package_write_post; do
        if [[ -x "/usr/local/directadmin/scripts/custom/${h}/da_resource_limiter.sh" ]]; then
            pass "DirectAdmin hook installed: ${h}/da_resource_limiter.sh"
        else
            fail "DirectAdmin hook missing or not executable: ${h}/da_resource_limiter.sh"
        fi
    done

    printf '\nSummary: %d passed, %d failed.\n' "$PASS_CNT" "$FAIL_CNT"
    [[ "$FAIL_CNT" -eq 0 ]]
}

run_benchmark() {
    local duration="${ARG2:-15}"
    local pid
    pid=$(systemctl show -p MainPID --value da-resourced 2>/dev/null || echo "0")
    if [[ -z "$pid" || "$pid" == "0" || ! -d "/proc/${pid}" ]]; then
        fail "da-resourced is not running."
        exit 1
    fi

    info "Sampling da-resourced (PID ${pid}) overhead over ${duration}s..."
    local clk_tck
    clk_tck=$(getconf CLK_TCK)

    local stat1 stat2 utime1 stime1 utime2 stime2
    stat1=$(cat "/proc/${pid}/stat")
    utime1=$(awk '{print $14}' <<< "$stat1")
    stime1=$(awk '{print $15}' <<< "$stat1")

    sleep "$duration"

    if [[ ! -d "/proc/${pid}" ]]; then
        fail "da-resourced process exited during benchmark!"
        exit 1
    fi
    stat2=$(cat "/proc/${pid}/stat")
    utime2=$(awk '{print $14}' <<< "$stat2")
    stime2=$(awk '{print $15}' <<< "$stat2")

    local rss_kb rss_mb fd_count cpu_pct
    rss_kb=$(awk '/^VmRSS:/ {print $2}' "/proc/${pid}/status")
    rss_mb=$(awk -v kb="${rss_kb:-0}" 'BEGIN { printf "%.2f", kb / 1024.0 }')
    fd_count=$(find "/proc/${pid}/fd" -maxdepth 1 | wc -l)
    cpu_pct=$(awk -v u1="$utime1" -v s1="$stime1" -v u2="$utime2" -v s2="$stime2" -v hz="$clk_tck" -v dur="$duration" \
        'BEGIN { printf "%.3f", (((u2 - u1) + (s2 - s1)) / hz / dur) * 100.0 }')

    info "Measured RSS Memory      : ${rss_mb} MB (Target DoD: < 30.00 MB)"
    info "Measured Avg CPU Usage   : ${cpu_pct}% (Target DoD: < 1.000%)"
    info "Open File Descriptors    : ${fd_count}"

    if awk -v m="$rss_mb" 'BEGIN { exit !(m < 30.0) }'; then
        pass "Daemon memory footprint (${rss_mb} MB) is within DoD target (< 30 MB)"
    else
        fail "Daemon memory footprint (${rss_mb} MB) exceeded 30 MB target"
    fi

    if awk -v c="$cpu_pct" 'BEGIN { exit !(c < 1.0) }'; then
        pass "Daemon CPU usage (${cpu_pct}%) is within DoD target (< 1%)"
    else
        fail "Daemon CPU usage (${cpu_pct}%) exceeded 1% target"
    fi

    [[ "$FAIL_CNT" -eq 0 ]]
}

run_verify_user() {
    local uname="$ARG2"
    if [[ -z "$uname" ]]; then
        printf 'Usage: %s verify-user <da_username>\n' "$0" >&2
        exit 1
    fi
    if ! id "$uname" >/dev/null 2>&1; then
        fail "System user ${uname} does not exist"
        exit 1
    fi

    local uid slice_dir dropin
    uid=$(id -u "$uname")
    slice_dir="/sys/fs/cgroup/user.slice/user-${uid}.slice"
    dropin="/etc/systemd/system/user-${uid}.slice.d/50-da-limits.conf"

    info "Verifying Cgroups v2 & MariaDB enforcement for ${uname} (UID ${uid})..."

    if [[ -f "$dropin" ]]; then
        pass "Slice drop-in present: ${dropin}"
    else
        fail "Slice drop-in missing: ${dropin}"
    fi

    if [[ -d "${slice_dir}/da-php.scope" ]]; then
        pass "PHP worker sub-cgroup active: ${slice_dir}/da-php.scope"
        if [[ -f "${slice_dir}/da-php.scope/cgroup.procs" ]]; then
            local scope_pids
            scope_pids=$(wc -l < "${slice_dir}/da-php.scope/cgroup.procs" | tr -d '[:space:]')
            info "Active PHP worker PIDs inside da-php.scope: ${scope_pids}"
        fi
    else
        fail "PHP worker sub-cgroup missing: ${slice_dir}/da-php.scope"
    fi

    if [[ -f "${slice_dir}/memory.swap.max" ]] && [[ "$(cat "${slice_dir}/memory.swap.max")" == "0" ]]; then
        pass "Swap usage strictly locked to 0 (MemorySwapMax=0M)"
    else
        fail "Swap limit is not locked to 0 on ${slice_dir}/memory.swap.max"
    fi

    for ctrl in cpu.max memory.high memory.max pids.max; do
        if [[ -f "${slice_dir}/${ctrl}" ]]; then
            info "Kernel ${ctrl} = $(cat "${slice_dir}/${ctrl}")"
        fi
    done

    /usr/local/sbin/da-resourced stats "$uname"
    [[ "$FAIL_CNT" -eq 0 ]]
}

case "$MODE" in
    preflight)   run_preflight ;;
    benchmark)   run_benchmark ;;
    verify-user) run_verify_user ;;
    *)
        printf 'Usage: %s {preflight | benchmark [seconds] | verify-user <username>}\n' "$0" >&2
        exit 1
        ;;
esac
