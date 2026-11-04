#!/usr/bin/env bash
# DirectAdmin Hook:
#   /usr/local/directadmin/scripts/custom/database_create_post/da_resource_limiter.sh
#   /usr/local/directadmin/scripts/custom/database_user_create_post/da_resource_limiter.sh
# Enforces Tier-2 MariaDB limits immediately whenever a customer creates a database or DB user.

set -u

DAEMON_BIN="/usr/local/sbin/da-resourced"
DA_USER="${username:-}"
RAW_DB_USER="${user:-}"

if [[ -z "$DA_USER" || ! -x "$DAEMON_BIN" ]]; then
    exit 0
fi

if [[ -n "$RAW_DB_USER" ]]; then
    # DirectAdmin may pass either full "username_dbuser" or short suffix depending on skin/API
    if [[ "$RAW_DB_USER" == "${DA_USER}" || "$RAW_DB_USER" == "${DA_USER}_"* ]]; then
        FULL_DB_USER="$RAW_DB_USER"
    else
        FULL_DB_USER="${DA_USER}_${RAW_DB_USER}"
    fi
    timeout 8s "$DAEMON_BIN" apply-db-user "$DA_USER" "$FULL_DB_USER" >/dev/null 2>&1 || true
else
    timeout 8s "$DAEMON_BIN" apply "$DA_USER" >/dev/null 2>&1 || true
fi

exit 0
