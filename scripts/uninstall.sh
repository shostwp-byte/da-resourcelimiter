#!/usr/bin/env bash
# Safe Uninstaller for DA-ResourceLimiter
# Usage:
#   ./uninstall.sh              (Removes daemon, slice limits & UI; archives data/ backup in /var/backups)
#   ./uninstall.sh --purge-data (Also deletes /etc/da-resourced, /var/lib/da-resourced & /var/log/da-resourced)

set -euo pipefail

PURGE_DATA="no"
if [[ "${1:-}" == "--purge-data" ]]; then
    PURGE_DATA="yes"
fi

BIN_DEST="/usr/local/sbin/da-resourced"
PLUGIN_DEST="/usr/local/directadmin/plugins/da_resource_limiter"
SYSTEMD_UNIT="/etc/systemd/system/da-resourced.service"
DA_CUSTOM_HOOKS="/usr/local/directadmin/scripts/custom"
BACKUP_DIR="/var/backups/da-resource-limiter"

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m   %s\n' "$*"; }

if [[ "$(id -u)" -ne 0 ]]; then
    printf '[ERROR] uninstall.sh must be run as root.\n' >&2
    exit 1
fi

info "Stopping and disabling da-resourced.service..."
systemctl stop da-resourced 2>/dev/null || true
systemctl disable da-resourced 2>/dev/null || true
rm -f "$SYSTEMD_UNIT" /var/run/da-resourced.sock /var/run/da-resourced-user.sock

info "Removing Cgroups v2 slice drop-ins (50-da-limits.conf)..."
shopt -s nullglob
for dropin in /etc/systemd/system/user-*.slice.d/50-da-limits.conf; do
    slice_dir=$(dirname "$dropin")
    rm -f "$dropin"
    rmdir "$slice_dir" 2>/dev/null || true
done
shopt -u nullglob
systemctl daemon-reload

info "Resetting MariaDB per-user resource limits back to unlimited..."
DA_MYCNF="/usr/local/directadmin/conf/my.cnf"
if command -v mysql >/dev/null 2>&1 && [[ -f "$DA_MYCNF" ]] && [[ -d "/usr/local/directadmin/data/users" ]]; then
    shopt -s nullglob
    for udir in /usr/local/directadmin/data/users/*; do
        [[ -d "$udir" ]] || continue
        uname=$(basename "$udir")
        [[ "$uname" == "admin" ]] && continue
        escaped_like="${uname//!/!!}"
        escaped_like="${escaped_like//%/!%}"
        escaped_like="${escaped_like//_/!_}!_%"

        db_rows=$(mysql --defaults-extra-file="$DA_MYCNF" -N -B -e \
            "SELECT User, Host FROM mysql.user WHERE User = '${uname}' OR User LIKE '${escaped_like}' ESCAPE '!';" 2>/dev/null || true)
        if [[ -n "$db_rows" ]]; then
            sql_batch=""
            while IFS=$'\t' read -r dbu dbh; do
                [[ -z "${dbu:-}" || -z "${dbh:-}" ]] && continue
                sql_batch+="ALTER USER '${dbu}'@'${dbh}' WITH MAX_USER_CONNECTIONS 0 MAX_STATEMENT_TIME 0;"$'\n'
            done <<< "$db_rows"
            sql_batch+="FLUSH USER_RESOURCES;"$'\n'
            mysql --defaults-extra-file="$DA_MYCNF" -N -B <<< "$sql_batch" 2>/dev/null || true
        fi
    done
    shopt -u nullglob
fi

info "Removing DirectAdmin lifecycle hook entries & restoring user.conf PHP tokens..."
for hook_folder in user_create_post user_modify_post user_destroy_post database_create_post database_user_create_post package_write_post; do
    rm -f "${DA_CUSTOM_HOOKS}/${hook_folder}/da_resource_limiter.sh"
done

if [[ -d "/usr/local/directadmin/data/users" ]]; then
    shopt -s nullglob
    for uconf in /usr/local/directadmin/data/users/*/user.conf; do
        sed -i '/^DA_PHP_MAX_CHILDREN=/d;/^DA_PHP_MEM_LIMIT=/d' "$uconf" 2>/dev/null || true
        if id diradmin >/dev/null 2>&1; then
            chown diradmin:diradmin "$uconf" 2>/dev/null || true
        fi
        chmod 0600 "$uconf" 2>/dev/null || true
    done
    shopt -u nullglob
fi

if [[ -d "${PLUGIN_DEST}/data" ]]; then
    mkdir -p "$BACKUP_DIR"
    chmod 0700 "$BACKUP_DIR"
    ts=$(date -u +"%Y%m%dT%H%M%SZ")
    archive="${BACKUP_DIR}/uninstall-data-backup-${ts}.tar.gz"
    tar -czf "$archive" -C "${PLUGIN_DEST}" data
    ok "Archived plugin/data configuration backup to ${archive}"
fi

info "Removing plugin directory and daemon binary..."
rm -rf "${PLUGIN_DEST:?}"
rm -f "$BIN_DEST"

if [[ "$PURGE_DATA" == "yes" ]]; then
    info "Purging /etc/da-resourced, /var/lib/da-resourced & /var/log/da-resourced..."
    rm -rf /etc/da-resourced /var/lib/da-resourced /var/log/da-resourced
fi

ok "DA-ResourceLimiter has been cleanly uninstalled."
