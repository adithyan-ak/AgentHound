#!/bin/sh
set -e

# Debian puts PostgreSQL binaries under /usr/lib/postgresql/<ver>/bin/
export PATH="/usr/lib/postgresql/13/bin:$PATH"

PGDATA=/data/postgres

# ── PostgreSQL initialization ──
if [ ! -f "$PGDATA/PG_VERSION" ]; then
  echo "[init-db] Initializing PostgreSQL..."
  mkdir -p "$PGDATA"
  chown postgres:postgres "$PGDATA"
  gosu postgres initdb -D "$PGDATA" --auth=trust --no-locale --encoding=UTF-8

  # Start temporarily for user/database creation
  gosu postgres pg_ctl -D "$PGDATA" -l /tmp/pg-init.log start -w -o "-c listen_addresses=127.0.0.1"
  gosu postgres createuser -s agenthound 2>/dev/null || true
  gosu postgres createdb -O agenthound agenthound 2>/dev/null || true
  gosu postgres pg_ctl -D "$PGDATA" stop -w
  echo "[init-db] PostgreSQL initialized"
else
  echo "[init-db] PostgreSQL data directory exists, skipping init"
fi

# ── Neo4j initialization ──
if [ ! -d "/data/neo4j/databases" ]; then
  echo "[init-db] Initializing Neo4j data directory..."
  mkdir -p /data/neo4j
  /opt/neo4j/bin/neo4j-admin set-initial-password agenthound 2>/dev/null || true
  echo "[init-db] Neo4j initialized"
else
  echo "[init-db] Neo4j data directory exists, skipping init"
fi

