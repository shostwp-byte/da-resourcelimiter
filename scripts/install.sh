#!/usr/bin/env bash
# 1-Click Production Installer for DA-ResourceLimiter
# Supports:
#   1) Running from an extracted release archive (./scripts/install.sh)
#   2) Remote 1-line bootstrap from GitHub Releases (Public or Private repo via GITHUB_TOKEN)

set -euo pipefail

GITHUB_REPO="${GITHUB_REPO:-shostwp-byte/da-resourcelimiter}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
TARGET_VERSION="${TARGET_VERSION:-latest}"
FORCE_DB="${FORCE_DB:-no}"

BIN_DEST="/usr/local/sbin/da-resourced"
PLUGIN_DEST="/usr/local/directadmin/plugins/da_resource_limiter"
UPDATER_CONF="/etc/da-resourced/updater.conf"
SYSTEMD_UNIT="/etc/systemd/system/da-resourced.service"
DA_CUSTOM_HOOKS="/usr/local/directadmin/scripts/custom"
DA_CUSTOM_TPL_DIR="/usr/local/directadmin/data/templates/custom"

info()  { printf '\033[1;34m[INFO]\033[0m  %s\n' "$*"; }
ok()    { printf '\033[1;32m[OK]\033[0m    %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*"; }
fatal() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

check_prerequisites() {
    if [[ "$(id -u)" -ne 0 ]]; then
        fatal "install.sh must be executed as root."
    fi

    if [[ ! -d "/usr/local/directadmin" ]]; then
        fatal "DirectAdmin installation not found at /usr/local/directadmin."
    fi

    # 1. Verify Linux Cgroups v2 Unified Hierarchy
    if [[ ! -f "/sys/fs/cgroup/cgroup.controllers" ]]; then
        printf '\n'
        warn "Linux Cgroups v2 (Unified Hierarchy) is NOT active on this server!"
        warn "Enable it on AlmaLinux/Rocky 8-9:"
        warn "  grubby --update-kernel=ALL --args=\"systemd.unified_cgroup_hierarchy=1\" && reboot"
        warn "Or on Ubuntu 22.04/24.04:"
        warn "  Add systemd.unified_cgroup_hierarchy=1 to GRUB_CMDLINE_LINUX in /etc/default/grub && update-grub && reboot"
        fatal "Aborting installation until Cgroups v2 is active."
    fi
    ok "Detected Linux Cgroups v2 Unified Hierarchy (/sys/fs/cgroup/cgroup.controllers)."

    # 2. Verify MariaDB 10.5+ (MEMORY_USED column in information_schema.PROCESSLIST)
    local da_mycnf="/usr/local/directadmin/conf/my.cnf"
    if command -v mysql >/dev/null 2>&1 && [[ -f "$da_mycnf" ]]; then
        local db_ver=""
        db_ver=$(mysql --defaults-extra-file="$da_mycnf" -N -B -e "SELECT VERSION();" 2>/dev/null || true)
        if [[ -n "$db_ver" ]]; then
            info "Detected Database Engine: ${db_ver}"
            if ! mysql --defaults-extra-file="$da_mycnf" -N -B -e "SELECT MEMORY_USED FROM information_schema.PROCESSLIST LIMIT 1;" >/dev/null 2>&1; then
                if [[ "$FORCE_DB" != "yes" ]]; then
                    warn "Database does not expose information_schema.PROCESSLIST.MEMORY_USED (MariaDB 10.5+ recommended)."
                    fatal "Upgrade to MariaDB 10.6/10.11 LTS via CustomBuild, or re-run with FORCE_DB=yes to run in thread/time-only mode."
                else
                    warn "FORCE_DB=yes set: continuing without per-query MEMORY_USED column."
                fi
            else
                ok "MariaDB per-thread MEMORY_USED telemetry verified."
            fi
        fi
    fi
}

detect_arch() {
    local machine
    machine=$(uname -m)
    case "$machine" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) fatal "Unsupported CPU architecture: ${machine}" ;;
    esac
}

bootstrap_from_github() {
    local arch="$1"
    local work_dir="$2"
    local archive_name="da-resource-limiter-linux-${arch}.tar.gz"
    local api_url

    if [[ "$TARGET_VERSION" == "latest" ]]; then
        api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    else
        api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/tags/${TARGET_VERSION}"
    fi

    info "Fetching release metadata from ${GITHUB_REPO} (${TARGET_VERSION})..."
    local curl_auth=()
    if [[ -n "$GITHUB_TOKEN" ]]; then
        curl_auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    fi

    local rel_json="${work_dir}/release.json"
    curl -fsSL "${curl_auth[@]}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "$api_url" -o "$rel_json"

    # Extract asset API URLs without requiring jq on minimal OS installs
    local archive_asset_url checksum_asset_url
    archive_asset_url=$(grep -B 4 "\"name\": *\"${archive_name}\"" "$rel_json" | grep '"url":' | head -n 1 | sed -E 's/.*"url": *"([^"]+)".*/\1/')
    checksum_asset_url=$(grep -B 4 '"name": *"checksums.txt"' "$rel_json" | grep '"url":' | head -n 1 | sed -E 's/.*"url": *"([^"]+)".*/\1/')

    if [[ -z "$archive_asset_url" || -z "$checksum_asset_url" ]]; then
        fatal "Could not locate ${archive_name} or checksums.txt in GitHub Release."
    fi

    info "Downloading checksums.txt & ${archive_name}..."
    curl -fsSL "${curl_auth[@]}" -H "Accept: application/octet-stream" "$checksum_asset_url" -o "${work_dir}/checksums.txt"
    curl -fsSL "${curl_auth[@]}" -H "Accept: application/octet-stream" "$archive_asset_url" -o "${work_dir}/${archive_name}"

    info "Verifying SHA-256 signature..."
    (
        cd "$work_dir"
        grep " ${archive_name}\$" checksums.txt | sha256sum -c -
    )
    ok "SHA-256 checksum verified."

    tar -xzf "${work_dir}/${archive_name}" -C "$work_dir"
}

install_from_bundle() {
    local bundle_dir="$1"

    info "Installing da-resourced static binary to ${BIN_DEST}..."
    install -o root -g root -m 0755 "${bundle_dir}/bin/da-resourced" "${BIN_DEST}.new"
    mv -f "${BIN_DEST}.new" "$BIN_DEST"

    info "Deploying DirectAdmin Plugin files to ${PLUGIN_DEST}..."
    mkdir -p "$PLUGIN_DEST" "${PLUGIN_DEST}/scripts" "${PLUGIN_DEST}/data/packages" "${PLUGIN_DEST}/data/users"

    local sub
    for sub in admin user hooks templates; do
        rm -rf "${PLUGIN_DEST:?}/${sub}"
        cp -a "${bundle_dir}/plugin/${sub}" "${PLUGIN_DEST}/${sub}"
    done
    cp -a "${bundle_dir}/plugin/plugin.conf" "${PLUGIN_DEST}/plugin.conf"
    cp -a "${bundle_dir}/plugin/data/default.conf.example" "${PLUGIN_DEST}/data/default.conf.example"

    if [[ ! -f "${PLUGIN_DEST}/data/default.conf" ]]; then
        cp -a "${bundle_dir}/plugin/data/default.conf.example" "${PLUGIN_DEST}/data/default.conf"
        ok "Initialized default limits at ${PLUGIN_DEST}/data/default.conf"
    else
        info "Existing ${PLUGIN_DEST}/data/default.conf preserved."
    fi

    cp -a "${bundle_dir}/scripts"/*.sh "${PLUGIN_DEST}/scripts/"

    if id diradmin >/dev/null 2>&1; then
        chown -R diradmin:diradmin \
            "${PLUGIN_DEST}/plugin.conf" \
            "${PLUGIN_DEST}/admin" \
            "${PLUGIN_DEST}/user" \
            "${PLUGIN_DEST}/hooks" \
            "${PLUGIN_DEST}/templates" \
            "${PLUGIN_DEST}/data"

        if [[ -d "/usr/local/directadmin/data/users" ]]; then
            chown diradmin:diradmin /usr/local/directadmin/data/users/*/user.conf 2>/dev/null || true
            chmod 0600 /usr/local/directadmin/data/users/*/user.conf 2>/dev/null || true
        fi
    fi
    chmod 0755 \
        "${PLUGIN_DEST}/admin/index.html" \
        "${PLUGIN_DEST}/admin/api.raw" \
        "${PLUGIN_DEST}/user/index.html" \
        "${PLUGIN_DEST}/user/stats.raw"
    chown -R root:root "${PLUGIN_DEST}/scripts"
    chmod 0700 "${PLUGIN_DEST}/scripts"/*.sh

    # Initialize /etc/da-resourced/updater.conf (0600 root:root) if not yet present
    mkdir -p "$(dirname "$UPDATER_CONF")"
    chmod 0700 "$(dirname "$UPDATER_CONF")"
    if [[ ! -f "$UPDATER_CONF" ]]; then
        cat <<EOF > "$UPDATER_CONF"
# DA-ResourceLimiter GitHub Updater Configuration (0600 root:root)
GITHUB_REPO=${GITHUB_REPO}
GITHUB_TOKEN=${GITHUB_TOKEN}
UPDATE_CHANNEL=stable
BACKUP_RETENTION=5
EOF
        chmod 0600 "$UPDATER_CONF"
        chown root:root "$UPDATER_CONF"
        ok "Created GitHub Updater configuration at ${UPDATER_CONF}"
    elif [[ -n "$GITHUB_TOKEN" ]]; then
        sed -i "s|^GITHUB_TOKEN=.*|GITHUB_TOKEN=${GITHUB_TOKEN}|" "$UPDATER_CONF"
        chmod 0600 "$UPDATER_CONF"
        ok "Updated GITHUB_TOKEN in ${UPDATER_CONF}"
    fi

    info "Installing non-destructive DirectAdmin Custom Hooks..."
    local hook_pairs=(
        "user_create_post:user_create_post.sh"
        "user_modify_post:user_modify_post.sh"
        "user_destroy_post:user_destroy_post.sh"
        "database_create_post:database_user_create_post.sh"
        "database_user_create_post:database_user_create_post.sh"
        "package_write_post:package_write_post.sh"
    )
    local pair hook_folder src_script
    for pair in "${hook_pairs[@]}"; do
        hook_folder="${pair%%:*}"
        src_script="${pair##*:}"
        mkdir -p "${DA_CUSTOM_HOOKS}/${hook_folder}"
        install -o root -g root -m 0700 "${bundle_dir}/scripts/da_hooks/${src_script}" \
            "${DA_CUSTOM_HOOKS}/${hook_folder}/da_resource_limiter.sh"
    done
    ok "DirectAdmin lifecycle hooks installed."

    # Check DirectAdmin custom php-fpm.conf note
    if [[ -f "${DA_CUSTOM_TPL_DIR}/php-fpm.conf" ]]; then
        info "Existing ${DA_CUSTOM_TPL_DIR}/php-fpm.conf detected (left untouched). Reference snippet: ${PLUGIN_DEST}/templates/php-fpm.conf.custom"
    else
        info "Reference PHP-FPM custom template snippet saved at: ${PLUGIN_DEST}/templates/php-fpm.conf.custom"
    fi

    info "Enabling & starting systemd service da-resourced.service..."
    install -o root -g root -m 0644 "${bundle_dir}/systemd/da-resourced.service" "$SYSTEMD_UNIT"
    systemctl daemon-reload
    systemctl enable --now da-resourced

    local ok_ping="no"
    for _ in 1 2 3 4 5 6 7 8; do
        if "$BIN_DEST" ping >/dev/null 2>&1; then
            ok_ping="yes"
            break
        fi
        sleep 1
    done

    if [[ "$ok_ping" != "yes" ]]; then
        fatal "da-resourced started but socket ping failed. Inspect: journalctl -u da-resourced -n 50"
    fi

    printf '\n'
    ok "==================================================================="
    ok " DA-ResourceLimiter installed & active! ($("$BIN_DEST" version))"
    ok " Admin Panel : /CMD_PLUGINS_ADMIN/da_resource_limiter"
    ok " User Portal : /CMD_PLUGINS/da_resource_limiter"
    ok " CLI Status  : da-resourced stats"
    ok " MySQL Audit : da-resourced audit-mycnf"
    ok "==================================================================="
}

check_prerequisites

SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
LOCAL_BUNDLE=""
if [[ -n "$SCRIPT_SOURCE" && -f "$SCRIPT_SOURCE" ]]; then
    CANDIDATE_ROOT=$(CDPATH='' cd -- "$(dirname -- "$SCRIPT_SOURCE")/.." && pwd)
    if [[ -f "${CANDIDATE_ROOT}/bin/da-resourced" && -d "${CANDIDATE_ROOT}/plugin" ]]; then
        LOCAL_BUNDLE="$CANDIDATE_ROOT"
    fi
fi

if [[ -n "$LOCAL_BUNDLE" ]]; then
    info "Installing from local verified bundle: ${LOCAL_BUNDLE}"
    install_from_bundle "$LOCAL_BUNDLE"
else
    ARCH=$(detect_arch)
    TMP_WORK=$(mktemp -d /tmp/da-limiter-install.XXXXXX)
    trap '[[ -n "${TMP_WORK:-}" ]] && rm -rf "$TMP_WORK"' EXIT
    bootstrap_from_github "$ARCH" "$TMP_WORK"
    install_from_bundle "${TMP_WORK}/da-resource-limiter"
fi
