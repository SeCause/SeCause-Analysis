#!/bin/sh
set -eu
# Reuse only extension/enum declarations. Hibernate creates tables afterwards.
# schema.sql uses Spring's @@ delimiter rather than psql semicolons.
sed '/^ALTER TABLE/,$d' /backend-schema.sql | sed 's/@@/;/g' \
  | psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"
