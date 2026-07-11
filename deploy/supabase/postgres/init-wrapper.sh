#!/bin/bash
# Pass the app-role secret into init.sql via current_setting().
# docker-entrypoint-initdb.d runs this before 01-init.sql.
#
# Passwords are read from a mounted secret file only — never from env, and
# never logged. The runtime API must connect as agent_bom_app (DML-only),
# not as the bootstrap/admin role created by the official Postgres image.
set -euo pipefail

APP_PASS_FILE="${POSTGRES_APP_PASSWORD_FILE:-/run/secrets/postgres_app_password}"

if [ -n "${POSTGRES_APP_PASSWORD:-}" ]; then
    echo "ERROR: POSTGRES_APP_PASSWORD env is not supported."
    echo "Write the app role secret to ${APP_PASS_FILE} (Docker secret / file mount)."
    exit 1
fi

if [ ! -f "${APP_PASS_FILE}" ]; then
    echo "ERROR: missing app role secret at ${APP_PASS_FILE}."
    echo "Create deploy/secrets/postgres_app_password (chmod 0400) before compose up."
    echo "Refusing to fall back to the bootstrap/admin role."
    exit 1
fi

APP_PASS="$(tr -d '\r\n' < "${APP_PASS_FILE}")"
if [ -z "${APP_PASS}" ]; then
    echo "ERROR: ${APP_PASS_FILE} is empty."
    exit 1
fi

# Escape single quotes for a SQL string literal (password never printed).
APP_PASS_SQL="${APP_PASS//\'/\'\'}"

echo "Setting init.app_password from secret file for least-privilege app user creation"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
        ALTER DATABASE ${POSTGRES_DB} SET init.app_password = '${APP_PASS_SQL}';
SQL
