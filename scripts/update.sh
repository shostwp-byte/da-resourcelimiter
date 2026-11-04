#!/usr/bin/env bash
# Atomic Self-Update & Snapshot Rollback Executor for DA-ResourceLimiter
# Executed as root (either via CLI `da-resourced update` or detached `systemd-run`).
# Preserves 100% of customer/package configuration files in plugin/data/.

set -euo pipefail

MODE="${1:-}"
STAGE_DIR="${2:-}"
TARGET_VER="${3:-unknown}"
RETENTION="${4:-5}"

BIN_DEST="/usr/local/sbin/da-resourced"
PLUGIN_DEST="/usr/local/directadmin/plugins/da_resource_limiter"
DA_CUSTOM_HOOKS="/usr/local/directadmin/scripts/custom"
SYSTEMD_UNIT="/etc/systemd/system/da-resourced.service"
BACKUP_DIR="/var/backups/da-resource-limiter"
STATUS_FILE="/var/lib/da-resourced/update_status.json"
LOCK_FILE="/var/lock/da-limiter-update.lock"

write_status() {
    local state="$1"
    local msg="$2"
    local ver="$3"
    local ts
    ts=$(date -u +%s)
    mkdir -p "$(dirname "$STATUS_FILE")"
    local escaped_msg="${msg//\\/\\\\}"
    escaped_msg="${escaped_msg//\"/\\\"}"
    cat <<EOF > "${STATUS_FILE}.tmp"
{
  "state": "${state}",
  "message": "${escaped_msg}",
  "target_version": "${ver}",
  "updated_unix": ${ts}
}
EOF
    mv -f "${STATUS_FILE}.tmp" "$STATUS_FILE"
}

fix_permissions() {
    mkdir -p "${PLUGIN_DEST}/data/packages" "${PLUGIN_DEST}/data/users"
    if id diradmin >/dev/null 2>&1; then
        chown -R diradmin:diradmin \
            "${PLUGIN_DEST}/plugin.conf" \
            "${PLUGIN_DEST}/admin" \
            "${PLUGIN_DEST}/user" \
            "${PLUGIN_DEST}/hooks" \
            "${PLUGIN_DEST}/templates" \
            "${PLUGIN_DEST}/data" 2>/dev/null || true
    fi
    chmod 0755 \
        "${PLUGIN_DEST}/admin/index.html" \
        "${PLUGIN_DEST}/admin/api.raw" \
        "${PLUGIN_DEST}/user/index.html" \
        "${PLUGIN_DEST}/user/stats.raw" 2>/dev/null || true

    if [[ -d "${PLUGIN_DEST}/scripts" ]]; then
        chown -R root:root "${PLUGIN_DEST}/scripts"
        chmod 0700 "${PLUGIN_DEST}/scripts"/*.sh 2>/dev/null || true
    fi
}

install_da_hooks() {
    local src_hooks_dir="$1"
    if [[ ! -d "$src_hooks_dir" ]]; then
        return 0
    fi

    local hook_pairs=(
        "user_create_post:user_create_post.sh"
        "user_modify_post:user_modify_post.sh"
        "user_destroy_post:user_destroy_post.sh"
        "database_create_post:database_user_create_post.sh"
        "database_user_create_post:database_user_create_post.sh"
        "package_write_post:package_write_post.sh"
    )

    local pair hook_folder src_script dest_folder dest_file
    for pair in "${hook_pairs[@]}"; do
        hook_folder="${pair%%:*}"
        src_script="${pair##*:}"
        if [[ -f "${src_hooks_dir}/${src_script}" ]]; then
            dest_folder="${DA_CUSTOM_HOOKS}/${hook_folder}"
            dest_file="${dest_folder}/da_resource_limiter.sh"
            mkdir -p "$dest_folder"
            install -o root -g root -m 0700 "${src_hooks_dir}/${src_script}" "$dest_file"
        fi
    done
}

healthcheck_daemon() {
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if systemctl is-active --quiet da-resourced && "$BIN_DEST" ping >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

create_snapshot_backup() {
    mkdir -p "$BACKUP_DIR"
    chmod 0700 "$BACKUP_DIR"
    local ts
    ts=$(date -u +"%Y%m%dT%H%M%SZ")
    local snap_stage="${BACKUP_DIR}/.stage-${ts}"
    local snap_archive="${BACKUP_DIR}/snapshot-${ts}.tar.gz"

    rm -rf "$snap_stage"
    mkdir -p "${snap_stage}/bin" "${snap_stage}/plugin" "${snap_stage}/systemd"

    if [[ -f "$BIN_DEST" ]]; then
        cp -a "$BIN_DEST" "${snap_stage}/bin/da-resourced"
    fi
    if [[ -d "$PLUGIN_DEST" ]]; then
        cp -a "$PLUGIN_DEST/." "${snap_stage}/plugin/"
    fi
    if [[ -f "$SYSTEMD_UNIT" ]]; then
        cp -a "$SYSTEMD_UNIT" "${snap_stage}/systemd/da-resourced.service"
    fi

    tar -czf "$snap_archive" -C "$snap_stage" .
    rm -rf "$snap_stage"
    ln -sfn "$snap_archive" "${BACKUP_DIR}/latest.tar.gz"

    # Prune old snapshots beyond retention limit (ISO-8601 UTC names sort chronologically)
    if [[ "$RETENTION" =~ ^[0-9]+$ ]] && (( RETENTION >= 1 )); then
        shopt -s nullglob
        local snaps=("${BACKUP_DIR}"/snapshot-*.tar.gz)
        shopt -u nullglob
        local total=${#snaps[@]}
        if (( total > RETENTION )); then
            local idx
            for (( idx = 0; idx < total - RETENTION; idx++ )); do
                rm -f "${snaps[$idx]}"
            done
        fi
    fi

    printf '%s' "$snap_archive"
}

restore_snapshot_archive() {
    local archive="$1"
    if [[ ! -f "$archive" ]]; then
        echo "Backup snapshot archive not found: $archive" >&2
        return 1
    fi

    local restore_tmp="${BACKUP_DIR}/.restore-$$"
    rm -rf "$restore_tmp"
    mkdir -p "$restore_tmp"
    tar -xzf "$archive" -C "$restore_tmp"

    if [[ -f "${restore_tmp}/bin/da-resourced" ]]; then
        install -o root -g root -m 0755 "${restore_tmp}/bin/da-resourced" "${BIN_DEST}.rollback"
        mv -f "${BIN_DEST}.rollback" "$BIN_DEST"
    fi

    # Restore code/UI/scripts while strictly preserving live customer plugin/data/
    local sub
    for sub in admin user hooks templates scripts; do
        if [[ -d "${restore_tmp}/plugin/${sub}" ]]; then
            rm -rf "${PLUGIN_DEST:?}/${sub}"
            cp -a "${restore_tmp}/plugin/${sub}" "${PLUGIN_DEST}/${sub}"
        fi
    done
    if [[ -f "${restore_tmp}/plugin/plugin.conf" ]]; then
        cp -a "${restore_tmp}/plugin/plugin.conf" "${PLUGIN_DEST}/plugin.conf"
    fi
    if [[ -f "${restore_tmp}/systemd/da-resourced.service" ]]; then
        cp -a "${restore_tmp}/systemd/da-resourced.service" "$SYSTEMD_UNIT"
    fi

    fix_permissions
    rm -rf "$restore_tmp"

    systemctl daemon-reload
    systemctl restart da-resourced
}

mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "Another update or rollback operation is already in progress." >&2
    exit 1
fi

case "$MODE" in
    apply)
        if [[ -z "$STAGE_DIR" || ! -d "$STAGE_DIR" ]]; then
            write_status "failed" "Staging directory missing: ${STAGE_DIR}" "$TARGET_VER"
            exit 1
        fi
        if [[ ! -f "${STAGE_DIR}/bin/da-resourced" ]]; then
            write_status "failed" "Staged binary missing at ${STAGE_DIR}/bin/da-resourced" "$TARGET_VER"
            exit 1
        fi

        write_status "running" "Creating pre-update snapshot backup..." "$TARGET_VER"
        SNAP_FILE=$(create_snapshot_backup)

        write_status "running" "Deploying binary, Evolution UI & DirectAdmin hooks (preserving data/)..." "$TARGET_VER"
        mkdir -p "$PLUGIN_DEST" "${PLUGIN_DEST}/scripts" "${PLUGIN_DEST}/data/packages" "${PLUGIN_DEST}/data/users"

        # 1. Atomic swap of root daemon binary
        install -o root -g root -m 0755 "${STAGE_DIR}/bin/da-resourced" "${BIN_DEST}.new"
        mv -f "${BIN_DEST}.new" "$BIN_DEST"

        # 2. Update plugin UI/code WITHOUT touching plugin/data/
        for subdir in admin user hooks templates; do
            if [[ -d "${STAGE_DIR}/plugin/${subdir}" ]]; then
                rm -rf "${PLUGIN_DEST:?}/${subdir}"
                cp -a "${STAGE_DIR}/plugin/${subdir}" "${PLUGIN_DEST}/${subdir}"
            fi
        done
        if [[ -f "${STAGE_DIR}/plugin/plugin.conf" ]]; then
            cp -a "${STAGE_DIR}/plugin/plugin.conf" "${PLUGIN_DEST}/plugin.conf"
            clean_ver="${TARGET_VER#v}"
            sed -i "s/^version=.*/version=${clean_ver}/" "${PLUGIN_DEST}/plugin.conf" || true
        fi
        if [[ -f "${STAGE_DIR}/plugin/data/default.conf.example" ]]; then
            cp -a "${STAGE_DIR}/plugin/data/default.conf.example" "${PLUGIN_DEST}/data/default.conf.example"
        fi
        if [[ -d "${STAGE_DIR}/scripts" ]]; then
            cp -a "${STAGE_DIR}/scripts"/*.sh "${PLUGIN_DEST}/scripts/" 2>/dev/null || true
            install_da_hooks "${STAGE_DIR}/scripts/da_hooks"
        fi
        if [[ -f "${STAGE_DIR}/systemd/da-resourced.service" ]]; then
            install -o root -g root -m 0644 "${STAGE_DIR}/systemd/da-resourced.service" "$SYSTEMD_UNIT"
        fi

        fix_permissions

        write_status "running" "Restarting da-resourced & running 10s socket healthcheck..." "$TARGET_VER"
        systemctl daemon-reload
        if systemctl restart da-resourced && healthcheck_daemon; then
            rm -rf "$(dirname "$STAGE_DIR")" 2>/dev/null || true
            write_status "success" "Successfully updated to ${TARGET_VER} (snapshot saved at ${SNAP_FILE})" "$TARGET_VER"
            echo "Update to ${TARGET_VER} succeeded."
            exit 0
        else
            write_status "running" "Healthcheck failed for ${TARGET_VER}; executing automatic rollback..." "$TARGET_VER"
            if restore_snapshot_archive "$SNAP_FILE" && healthcheck_daemon; then
                write_status "rolled_back" "Update to ${TARGET_VER} failed healthcheck; automatically rolled back to previous working snapshot." "$TARGET_VER"
            else
                write_status "failed" "Update to ${TARGET_VER} failed and rollback encountered errors. Check journalctl -u da-resourced." "$TARGET_VER"
            fi
            exit 1
        fi
        ;;

    rollback)
        LATEST_SNAP="${BACKUP_DIR}/latest.tar.gz"
        if [[ ! -e "$LATEST_SNAP" ]]; then
            write_status "failed" "No snapshot backup available at ${LATEST_SNAP}" "rollback"
            echo "No snapshot backup available to roll back." >&2
            exit 1
        fi
        REAL_SNAP=$(readlink -f "$LATEST_SNAP")
        write_status "running" "Rolling back from ${REAL_SNAP}..." "rollback"
        if restore_snapshot_archive "$REAL_SNAP" && healthcheck_daemon; then
            CUR_VER=$("$BIN_DEST" version 2>/dev/null || echo "restored")
            write_status "rolled_back" "Successfully rolled back using snapshot $(basename "$REAL_SNAP") (${CUR_VER})" "rollback"
            echo "Rollback completed successfully."
            exit 0
        else
            write_status "failed" "Rollback failed healthcheck. Check journalctl -u da-resourced." "rollback"
            exit 1
        fi
        ;;

    *)
        echo "Usage: $0 {apply <stage_dir> <version> [retention] | rollback}" >&2
        exit 1
        ;;
esac
