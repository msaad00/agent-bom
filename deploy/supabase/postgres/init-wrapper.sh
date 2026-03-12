#!/bin/bash
# Wrapper to pass POSTGRES_APP_PASSWORD into the init SQL via current_setting().
# docker-entrypoint-initdb.d runs this before 01-init.sql.
set -euo pipefail

# Set the app password as a custom GUC so init.sql can read it
if [ -n "${POSTGRES_APP_PASSWORD:-}" ]; then
    echo "Setting init.app_password for least-privilege app user creation"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
        ALTER DATABASE ${POSTGRES_DB} SET init.app_password = '${POSTGRES_APP_PASSWORD}';
SQL
else
    echo "POSTGRES_APP_PASSWORD not set — app will use admin user (dev mode)"
fi
