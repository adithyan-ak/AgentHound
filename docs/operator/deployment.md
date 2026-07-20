# Production Deployment

AgentHound's analysis server has no application-layer authentication. The network boundary is the security control. This guide covers deployment patterns from simplest to most hardened.

---

## Default: Docker Compose (Loopback)

The shipped `docker/docker-compose.yml` runs three containers:

| Service | Image | Port |
|---------|-------|------|
| `graph-db` | `neo4j:4.4-community` | `127.0.0.1:7474`, `127.0.0.1:7687` |
| `app-db` | `postgres:16-alpine` | `127.0.0.1:5432` |
| `agenthound` | `agenthound-server` | `127.0.0.1:8080` |

```bash
export AGENTHOUND_HOST_ID=security-laptop
export AGENTHOUND_NETWORK_REALM_ID=corp-lab
export AGENTHOUND_STORAGE_PAIR_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
cd docker && docker compose up -d
```

All ports bind to loopback. No external exposure. Suitable for single-operator use on a laptop or jump box.

Generate the storage UUID only for a new empty pair, then persist all three
values in the deployment configuration. `host-id` is the one collector machine
whose artifacts this pair accepts; `network-realm-id` identifies the private
network visible from it. Each ID must match
`[a-z0-9][a-z0-9._-]{0,127}`. Do not infer them from a container hostname or
IP address, which can change across restarts.

### One collection realm per database pair

The host/realm restriction prevents false graph merges between filesystem
paths, loopback services, RFC1918 endpoints, host identities, and lifecycle
coverage observed from different vantage points. The server compares every v3
artifact with its configured tuple before generic validation or any scan/graph
write. A mismatch returns `409 COLLECTION_REALM_MISMATCH`.

The storage UUID binds PostgreSQL and Neo4j to each other. Startup reads both
markers before migrations or schema writes. Crossed pairs, future marker
versions, mismatches, and unbound non-empty databases fail closed. A one-sided
missing marker is repaired only while both stores are product-empty, covering
an interrupted first initialization. A runtime verification failure returns a
sanitized `503 STORAGE_BINDING_UNAVAILABLE` and writes nothing.

These identifiers are admission provenance, not authentication or signatures.
Keep the server behind its documented network boundary and protect artifacts
in transit. To move to another host or realm, reset both databases and recollect
rather than editing provenance on retained artifacts.

---

## Remote Access Patterns

### SSH Tunnel (simplest)

Forward the server port over SSH from your workstation:

```bash
ssh -L 8080:localhost:8080 operator@analysis-box
```

Then open `http://localhost:8080` locally. Zero config changes on the server side.

### Tailscale / WireGuard

Bind the server to `0.0.0.0:8080` (set `AGENTHOUND_BIND=0.0.0.0:8080`) and restrict access at the mesh layer. Tailscale ACLs or WireGuard AllowedIPs scope who can reach port 8080.

### Nginx Reverse Proxy with mTLS

For team deployments where multiple operators need access:

```nginx
server {
    listen 443 ssl;
    server_name agenthound.internal;

    ssl_certificate     /etc/nginx/tls/server.crt;
    ssl_certificate_key /etc/nginx/tls/server.key;
    ssl_client_certificate /etc/nginx/tls/ca.crt;
    ssl_verify_client on;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Update `AGENTHOUND_CORS_ORIGINS=https://agenthound.internal` to match.

---

## Neo4j Tuning

Default heap: 512m initial / 1G max (set in `docker-compose.yml`). Adjust for large graphs:

| Graph Size | Recommended Heap | Page Cache |
|------------|-----------------|------------|
| < 50k nodes | 512m / 1G | 512m |
| 50k-500k nodes | 1G / 2G | 1G |
| > 500k nodes | 2G / 4G | 2G |

Set via environment variables in compose:

```yaml
NEO4J_dbms_memory_heap_initial__size: 1G
NEO4J_dbms_memory_heap_max__size: 2G
NEO4J_dbms_memory_pagecache_size: 1G
```

Path queries use the built-in bounded traversal engine and do not require APOC.

---

## PostgreSQL

Postgres stores scan lifecycle, immutable finding snapshots, analyst triage,
coverage heads, and published posture revisions. No special tuning is needed
for normal single-user deployments. The default `postgres:16-alpine` image is
sufficient.

---

## Backup

### Neo4j

```bash
docker compose -f docker/docker-compose.yml exec graph-db neo4j-admin dump --database=neo4j --to=/tmp/neo4j.dump
docker compose -f docker/docker-compose.yml cp graph-db:/tmp/neo4j.dump ./backups/
```

### PostgreSQL

```bash
docker compose -f docker/docker-compose.yml exec app-db pg_dump -U agenthound agenthound > ./backups/pg.sql
```

Schedule both as one coordinated backup set. Neo4j contains the mutable graph projection; Postgres
contains publication history and analyst triage that re-ingestion does not
reconstruct. The immutable storage-pair marker deliberately makes a PostgreSQL
backup from one deployment incompatible with a Neo4j backup from another.

---

## Upgrades

`agenthound-server` initializes Neo4j constraints and the PostgreSQL schema on
startup. The pre-launch PostgreSQL history was replaced by one current
single-user `001_initial.sql`; prior development schemas are intentionally not
upgradeable. After checking out this baseline, recreate both development
databases:

```bash
docker compose -f docker/docker-compose.yml down --volumes
docker compose -f docker/docker-compose.yml up -d
```

This permanently deletes the development Neo4j and PostgreSQL volumes. The
fresh baseline is idempotent after creation. The server still detects Neo4j
4.4 versus 5.x and applies the appropriate constraint syntax.

---

## Security Checklist

- [ ] All ports bound to `127.0.0.1` (or behind VPN/mesh)
- [ ] `AGENTHOUND_CORS_ORIGINS` matches the operator-facing URL(s); foreign-origin browser POSTs are rejected
- [ ] Stable `AGENTHOUND_HOST_ID` and `AGENTHOUND_NETWORK_REALM_ID` name the one admitted collection vantage point
- [ ] One canonical `AGENTHOUND_STORAGE_PAIR_ID` is retained with the paired PostgreSQL and Neo4j volumes/backups
- [ ] Neo4j credentials changed from default `agenthound`
- [ ] Postgres credentials changed from default
- [ ] If exposed via reverse proxy: mTLS or equivalent client auth enabled
- [ ] Scan output files (`scan-*.json`) stored with restricted permissions (may contain credential hashes)
