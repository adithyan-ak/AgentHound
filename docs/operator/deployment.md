# Deployment

The analysis server is a single-user application. Its default loopback bind is the primary access boundary.

## Docker Compose

Run the published stack:

```bash
curl -sSfL \
  https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.1/docker/docker-compose.public.yml \
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

### Database credentials

The published file uses development credentials and keeps every port on
loopback. Before the first start of a shared or remotely accessible deployment,
edit the downloaded file and change all matching credential references:

- `NEO4J_AUTH`
- the Neo4j health check password after `-p`
- `POSTGRES_PASSWORD`
- `AGENTHOUND_NEO4J_PASSWORD`
- the password inside `AGENTHOUND_PG_URI`

Database images apply their initialization credentials only when creating a new
volume. If the volumes already contain data, follow the Neo4j and PostgreSQL
password-rotation procedures instead of changing only the Compose environment.

## Remote access

Prefer an SSH tunnel when one operator needs remote access:

```bash
ssh -L 8080:localhost:8080 operator@analysis-box
```

Then open `http://localhost:8080` locally.

For a private mesh, bind the host port on the mesh interface and restrict it with Tailscale ACLs, WireGuard AllowedIPs, or equivalent firewall policy. For a shared HTTPS endpoint, place the loopback server behind an authenticated reverse proxy such as mTLS. Add the browser origin under the `agenthound` service's `environment` block in the downloaded Compose file:

```yaml
environment:
  AGENTHOUND_CORS_ORIGINS: https://agenthound.internal
```

When running the server binary directly, export the same variable before
`agenthound-server serve`.

OriginGuard protects browser mutations from unapproved origins; it is not user authentication. Requests from local processes without an `Origin` header remain inside the server's trust boundary.

## Storage pair

Neo4j holds the graph projection. PostgreSQL holds scan lifecycle, finding snapshots, triage, coverage heads, and publication revisions. The server writes a shared binding marker to both stores and refuses to start against a crossed pair.

Back up and restore both databases as one coordinated set. Stop the AgentHound
service first so neither store changes between snapshots. Neo4j 4.4 dump also
requires the database to be offline:

```bash
agenthound_backup_dir="backups/$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$agenthound_backup_dir"
docker compose -f agenthound-compose.yml -p agenthound stop agenthound
docker compose -f agenthound-compose.yml -p agenthound exec -T app-db \
  pg_dump -U agenthound agenthound > "$agenthound_backup_dir/postgres.sql"
docker compose -f agenthound-compose.yml -p agenthound stop graph-db
docker compose -f agenthound-compose.yml -p agenthound run --rm --no-deps -T \
  graph-db neo4j-admin dump --database=neo4j --to=- > "$agenthound_backup_dir/neo4j.dump"
docker compose -f agenthound-compose.yml -p agenthound up -d --wait
```

The command keeps both files under one timestamp. They can contain sensitive
data. Test the database-vendor restore procedures on an isolated stack before
depending on them operationally.

## Upgrade

1. Preserve a coordinated database backup.
2. Pull the desired server image or source revision.
3. Start the full stack and wait for health.
4. Confirm the dashboard, scan history, and a representative finding.

```bash
curl -sSfL \
  https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.1/docker/docker-compose.public.yml \
  -o agenthound-compose.yml
docker compose -f agenthound-compose.yml -p agenthound pull
docker compose -f agenthound-compose.yml -p agenthound up -d --wait
```

The server applies PostgreSQL migrations and Neo4j schema initialization during startup. Use the coordinated collector and server release pair by default; the artifact compatibility policy is described below.

## Collector and server compatibility

AgentHound releases the collector and server together under one product version.
Use the matching pair unless you are intentionally testing another combination.

| Combination | Support |
|---|---|
| Collector and server from the same release | Recommended and tested together |
| Older V1 artifact ingested by a current server | Supported |
| Newer artifact ingested by an older server | Not guaranteed; upgrade the server |
| Breaking artifact change | Requires a new contract version, such as V2 |

Compatibility follows the artifact contract, not exact binary-version equality.
The `collector_version` is diagnostic information. Releases after `1.1.1` pin
the exact server image in Compose. Immutable Compose files from `1.0.0` through
`1.1.1` keep their original `latest` reference.

## Stop or remove the stack

Stop and remove the containers while retaining both database volumes:

```bash
docker compose -f agenthound-compose.yml -p agenthound down
```

To permanently delete the AgentHound containers and both database volumes, run:

```bash
docker compose -f agenthound-compose.yml -p agenthound down -v
```

The second command deletes scan history, findings, triage, and the graph. Back
up both databases first if any of that data must be retained.

## Troubleshooting

If startup or upgrade does not become healthy, inspect service state and recent
logs:

```bash
docker compose -f agenthound-compose.yml -p agenthound ps
docker compose -f agenthound-compose.yml -p agenthound logs --tail=100 agenthound graph-db app-db
```

## Capacity

Default Neo4j memory settings suit normal single-operator graphs. For larger projections, raise heap and page cache together and monitor container memory. Path traversals are bounded and do not require APOC-specific query authoring.

PostgreSQL normally needs no special tuning beyond durable storage and regular backups.

## Operational checklist

- Keep API, Neo4j, and PostgreSQL on loopback or a protected private network.
- Change every matching database credential before the first shared deployment.
- Configure `AGENTHOUND_CORS_ORIGINS` for the browser URL.
- Back up PostgreSQL and Neo4j together.
- Store scan artifacts with restricted permissions; they can contain raw credentials and collected service content.
- Verify `/api/v1/health` after startup or upgrade.
- Use VPN, SSH, or authenticated reverse-proxy controls for remote access.
