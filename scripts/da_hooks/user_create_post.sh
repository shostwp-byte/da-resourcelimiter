#!/usr/bin/env bash
# DirectAdmin Hook: /usr/local/directadmin/scripts/custom/user_create_post/da_resource_limiter.sh
# Triggered immediately after DirectAdmin creates a new hosting account.

set -u

DAEMON_BIN="/usr/local/sbin/da-resourced"
TARGET_USER="${username:-}"

if [[ -z "$TARGET_USER" || ! -x "$DAEMON_BIN" ]]; then
    exit 0
fi

timeout 25s "$DAEMON_BIN" apply "$TARGET_USER" >/dev/null 2>&1 || true
exit 0
