#!/bin/sh
set -eu
# Reuse only extension/enum declarations. Hibernate creates tables afterwards.
# schema.sql uses Spring's @@ delimiter rather than psql semicolons.
schema_file=$(mktemp)
trap 'rm -f "$schema_file"' EXIT
sed -e '/^ALTER TABLE/,$d' -e 's/@@/;/g' "${BACKEND_SCHEMA_FILE:-/backend-schema.sql}" > "$schema_file"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$schema_file"
