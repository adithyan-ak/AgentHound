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
cd docker && docker compose up -d
```

All ports bind to loopback. No external exposure. Suitable for single-operator use on a laptop or jump box.

### Automatic multi-vantage provenance

The collector derives a deterministic collection point from the OS instance,
effective principal, and filesystem/container execution scope. It derives a
network context from that point plus the network visibility it can observe.
Raw identity evidence never leaves the collection host; bounded hostname, OS,
and architecture labels are emitted only for display. The server accepts every
structurally valid ingest-v1 artifact and uses the derived IDs to scope local,
private, and endpoint-derived graph evidence; they are not authentication or
attestation. If route/interface inspection fails, the point can remain strong
while only network-scoped evidence is made artifact-local.

The server also generates the storage UUID internally. Startup reads the
versioned marker from both databases before migrations or schema writes.
Crossed pairs, non-V1 marker versions, and unsafe unbound non-empty databases
fail closed. Binding V1 requires freshly initialized paired stores. Recreate
both database volumes together, restart, and recollect ingest-v1 artifacts.
A repairable one-sided missing marker is
restored automatically only for product-empty stores.
A runtime verification failure returns a sanitized
`503 STORAGE_BINDING_UNAVAILABLE` and writes nothing.

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
reconstruct. The internal storage-pair marker deliberately makes a PostgreSQL
backup from one deployment incompatible with a Neo4j backup from another.

---

## Upgrades

This development V1 baseline has no in-place upgrade or artifact-conversion
path. PostgreSQL and Neo4j must be initialized together from empty storage.
Before resetting collector state, resolve every applied offensive-action
receipt: discard dry-run-only receipts, then revert and verify each real
mutation. Stop if any reversion cannot be verified.

Then recreate both development databases:

```bash
docker compose -f docker/docker-compose.yml down --volumes
docker compose -f docker/docker-compose.yml up -d
```

This permanently deletes the selected Neo4j and PostgreSQL volumes. The fresh
graph schema is idempotent after creation, and the server still detects Neo4j
4.4 versus 5.x constraint syntax.

For the public no-clone installation, the equivalent full operation reset is:

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/docker/docker-compose.public.yml \
  | docker compose -f - -p agenthound down --volumes
```

This command is intentionally destructive and cannot be undone without a
coordinated backup. Run the public Quickstart `up` command again afterward.

Re-run the current collector after the reset. The strict server accepts only V1
artifacts and rejects incompatible identity or instruction-registry metadata
before graph mutation.

Per-collection-point purge is intentionally unavailable. The graph stores a
merged current projection, not every point's immutable normalized contribution,
so removing one owner could not always reconstruct surviving properties
exactly. Scan deletion remains history-only. When all evidence must be removed,
perform a documented full operation reset by replacing both database volumes.

---

## Security Checklist

- [ ] All ports bound to `127.0.0.1` (or behind VPN/mesh)
- [ ] `AGENTHOUND_CORS_ORIGINS` matches the operator-facing URL(s); foreign-origin browser POSTs are rejected
- [ ] PostgreSQL and Neo4j are backed up and restored as one coordinated pair
- [ ] PostgreSQL and Neo4j were freshly initialized together for V1
- [ ] Neo4j credentials changed from default `agenthound`
- [ ] Postgres credentials changed from default
- [ ] If exposed via reverse proxy: mTLS or equivalent client auth enabled
- [ ] Scan output files (`scan-*.json`) stored with restricted permissions (may contain credential hashes)
