#!/usr/bin/env bash
# DirectAdmin Hook: /usr/local/directadmin/scripts/custom/package_write_post/da_resource_limiter.sh
# Re-synchronizes non-overridden users whenever a Hosting Package is modified in DirectAdmin.

set -u

DAEMON_BIN="/usr/local/sbin/da-resourced"
TARGET_PKG="${package:-}"

if [[ -z "$TARGET_PKG" || ! -x "$DAEMON_BIN" ]]; then
    exit 0
fi

timeout 25s "$DAEMON_BIN" apply-package "$TARGET_PKG" >/dev/null 2>&1 || true
exit 0
