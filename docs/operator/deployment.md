# Deployment

The analysis server is a single-user application. Its default loopback bind is the primary access boundary.

## Docker Compose

Run the published stack:

```bash
curl -sSfL \
  https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.0/docker/docker-compose.public.yml \
  -o agenthound-compose.yml
docker compose -f agenthound-compose.yml -p agenthound up -d --wait
```

The stack contains:

| Service | Default host exposure | Role |
|---|---|---|
| `agenthound` | `127.0.0.1:8080` | API and dashboard |
| `graph-db` | `127.0.0.1:7474`, `127.0.0.1:7687` | Neo4j graph projection |
| `app-db` | `127.0.0.1:5432` | PostgreSQL history, findings, triage, and publication state |

Check readiness:

```bash
curl -fsS http://127.0.0.1:8080/api/v1/health
```

For a source checkout, use `docker compose -f docker/docker-compose.yml up -d --wait`.

## Remote access

Prefer an SSH tunnel when one operator needs remote access:

```bash
ssh -L 8080:localhost:8080 operator@analysis-box
```

Then open `http://localhost:8080` locally.

For a private mesh, bind the host port on the mesh interface and restrict it with Tailscale ACLs, WireGuard AllowedIPs, or equivalent firewall policy. For a shared HTTPS endpoint, place the loopback server behind an authenticated reverse proxy such as mTLS and set:

```bash
AGENTHOUND_CORS_ORIGINS=https://agenthound.internal
```

OriginGuard protects browser mutations from unapproved origins; it is not user authentication. Requests from local processes without an `Origin` header remain inside the server's trust boundary.

## Storage pair

Neo4j holds the graph projection. PostgreSQL holds scan lifecycle, finding snapshots, triage, coverage heads, and publication revisions. The server writes a shared binding marker to both stores and refuses to start against a crossed pair.

Back up and restore both databases as one coordinated set. For the source Compose file:

```bash
mkdir -p backups
docker compose -f docker/docker-compose.yml exec graph-db \
  neo4j-admin dump --database=neo4j --to=/tmp/neo4j.dump
docker compose -f docker/docker-compose.yml cp \
  graph-db:/tmp/neo4j.dump backups/neo4j.dump
docker compose -f docker/docker-compose.yml exec -T app-db \
  pg_dump -U agenthound agenthound > backups/postgres.sql
```

Use the same timestamp or release identifier for both files. Test restores on an isolated stack before depending on them operationally.

## Upgrade

1. Preserve a coordinated database backup.
2. Pull the desired server image or source revision.
3. Start the full stack and wait for health.
4. Confirm the dashboard, scan history, and a representative finding.

```bash
curl -sSfL \
  https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.0/docker/docker-compose.public.yml \
  -o agenthound-compose.yml
docker compose -f agenthound-compose.yml -p agenthound pull
docker compose -f agenthound-compose.yml -p agenthound up -d --wait
```

The server applies PostgreSQL migrations and Neo4j schema initialization during startup. Keep the collector and server on the same release when ingesting artifacts with same-scan action proof.

## Capacity

Default Neo4j memory settings suit normal single-operator graphs. For larger projections, raise heap and page cache together and monitor container memory. Path traversals are bounded and do not require APOC-specific query authoring.

PostgreSQL normally needs no special tuning beyond durable storage and regular backups.

## Operational checklist

- Keep API, Neo4j, and PostgreSQL on loopback or a protected private network.
- Change the default database credentials before shared deployment.
- Configure `AGENTHOUND_CORS_ORIGINS` for the browser URL.
- Back up PostgreSQL and Neo4j together.
- Store scan artifacts with restricted permissions; they can contain raw credentials and collected service content.
- Verify `/api/v1/health` after startup or upgrade.
- Use VPN, SSH, or authenticated reverse-proxy controls for remote access.
