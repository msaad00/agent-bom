#!/bin/bash
# Pass the app-role secret into init.sql via current_setting().
# docker-entrypoint-initdb.d runs this before 01-init.sql.
#
# Passwords are read from a mounted secret file only — never from env, and
# never logged. The runtime API must connect as agent_bom_app (DML-only),
# not as the bootstrap/admin role created by the official Postgres image.
set -euo pipefail

APP_PASS_FILE="${POSTGRES_APP_PASSWORD_FILE:-/run/secrets/postgres_app_password}"
MAINTENANCE_PASS_FILE="${POSTGRES_MAINTENANCE_PASSWORD_FILE:-/run/secrets/postgres_maintenance_password}"

if [ -n "${POSTGRES_APP_PASSWORD:-}" ]; then
    echo "ERROR: POSTGRES_APP_PASSWORD env is not supported."
    echo "Write the app role secret to ${APP_PASS_FILE} (Docker secret / file mount)."
    exit 1
fi

if [ -n "${POSTGRES_MAINTENANCE_PASSWORD:-}" ]; then
    echo "ERROR: POSTGRES_MAINTENANCE_PASSWORD env is not supported."
    echo "Write the maintenance role secret to ${MAINTENANCE_PASS_FILE}."
    exit 1
fi

if [ ! -f "${APP_PASS_FILE}" ]; then
    echo "ERROR: missing app role secret at ${APP_PASS_FILE}."
    echo "Create deploy/secrets/postgres_app_password (chmod 0644) before compose up."
    echo "Refusing to fall back to the bootstrap/admin role."
    exit 1
fi


if [ ! -f "${MAINTENANCE_PASS_FILE}" ]; then
    echo "ERROR: missing maintenance role secret at ${MAINTENANCE_PASS_FILE}."
    echo "Create deploy/secrets/postgres_maintenance_password (chmod 0644) before compose up."
    echo "Refusing to reuse the app or bootstrap/admin role for maintenance."
    exit 1
fi

APP_PASS="$(tr -d '\r\n' < "${APP_PASS_FILE}")"
if [ -z "${APP_PASS}" ]; then
    echo "ERROR: ${APP_PASS_FILE} is empty."
    exit 1
fi

MAINTENANCE_PASS="$(tr -d '\r\n' < "${MAINTENANCE_PASS_FILE}")"
if [ -z "${MAINTENANCE_PASS}" ]; then
    echo "ERROR: ${MAINTENANCE_PASS_FILE} is empty."
    exit 1
fi

# Escape single quotes for a SQL string literal (password never printed).
APP_PASS_SQL="${APP_PASS//\'/\'\'}"
MAINTENANCE_PASS_SQL="${MAINTENANCE_PASS//\'/\'\'}"

echo "Setting runtime-role passwords from separate secret files"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
        ALTER DATABASE ${POSTGRES_DB} SET init.app_password = '${APP_PASS_SQL}';
        ALTER DATABASE ${POSTGRES_DB} SET init.maintenance_password = '${MAINTENANCE_PASS_SQL}';
SQL
