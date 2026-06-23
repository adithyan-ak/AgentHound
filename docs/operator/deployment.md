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

APOC plugin is required for Dijkstra weighted-path queries. Enabled by default in the compose file via `NEO4J_PLUGINS: '["apoc"]'`.

---

## PostgreSQL

Postgres stores only the `scans` table (scan metadata, status, timestamps). Storage is negligible even at thousands of scans. No special tuning needed. The default `postgres:16-alpine` image is sufficient.

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

Schedule both via cron. The graph is the high-value artifact; Postgres is trivially recreatable from re-ingestion.

---

## Upgrades

`agenthound-server` handles schema migrations on startup (both Neo4j constraint creation and Postgres table migrations). Upgrade process:

1. Pull new image or binary.
2. Stop the server container.
3. Back up Neo4j and Postgres (above).
4. Start the new version — migrations run automatically.
5. Verify via `GET /api/v1/health` (checks both DB connections).

No manual migration scripts required. The server detects Neo4j version (4.4 vs 5.x) and applies the correct constraint syntax automatically.

---

## Security Checklist

- [ ] All ports bound to `127.0.0.1` (or behind VPN/mesh)
- [ ] `AGENTHOUND_CORS_ORIGINS` matches the operator-facing URL(s); foreign-origin browser POSTs are rejected
- [ ] Neo4j credentials changed from default `agenthound`
- [ ] Postgres credentials changed from default
- [ ] If exposed via reverse proxy: mTLS or equivalent client auth enabled
- [ ] Scan output files (`scan-*.json`) stored with restricted permissions (may contain credential hashes)
