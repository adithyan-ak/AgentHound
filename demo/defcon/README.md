# AgentHound DEF CON attendee lab

This lab reproduces the `augment -> customers-database` finding from the DEF
CON presentation. The collector and campaign run only inside an isolated
workstation container, so AgentHound never reads configuration from the host.
The host runs Docker and a browser; only the dashboard is published, at
<http://127.0.0.1:18080>.

The illustrated, checkpoint-by-checkpoint guide is
[`docs/labs/defcon34/AgentHound_DEFCON_demo_walkthrough.pdf`](../../docs/labs/defcon34/AgentHound_DEFCON_demo_walkthrough.pdf).

## Start from a clean clone

```bash
git clone https://github.com/adithyan-ak/AgentHound.git
cd AgentHound

export AGENTHOUND_DEMO_UID="$(id -u)"
export AGENTHOUND_DEMO_GID="$(id -g)"
```

Keep that terminal open. The UID/GID values make the container-generated,
private JSON files selectable by the host browser on macOS and Linux.

## Pull, build, and start

The first run needs internet access:

```bash
docker compose -f demo/defcon/compose.yml pull graph-db app-db
docker compose -f demo/defcon/compose.yml build devtools-mcp agenthound-server workstation
```

Start from empty lab databases. This targets only the named
`agenthound-defcon34` Compose project and its two volumes:

```bash
docker compose -f demo/defcon/compose.yml down --volumes --remove-orphans
docker compose -f demo/defcon/compose.yml up -d --wait --pull never
docker compose -f demo/defcon/compose.yml ps
curl -fsS http://127.0.0.1:18080/api/v1/health
```

Expected health response:

```text
{"neo4j":"ok","postgres":"ok","status":"ok"}
```

## Collect inside the isolated workstation

```bash
docker compose -f demo/defcon/compose.yml exec workstation bash
```

At the container prompt:

```bash
agenthound scan --config \
  --project-dir /home/demo/project \
  --output /demo/artifacts/config.json

agenthound scan --mcp \
  --project-dir /home/demo/project \
  --output /demo/artifacts/mcp.json

exit
```

The stable checkpoints are `11 nodes, 8 edges` and `7 nodes, 5 edges`.
Open the dashboard, import `config.json` and then `mcp.json` through **Scans ->
Import scan**. Open the `augment -> customers-database` finding. It must show
`DEFAULT / INFERRED / 60% CONF`. Copy its full 16-character ID from
**References**.

## Bind and run the bounded retest

From the host terminal:

```bash
printf 'Paste full Finding ID: '; IFS= read -r FINDING_ID

docker compose -f demo/defcon/compose.yml \
  exec -T agenthound-server \
  agenthound-server witness \
    --finding "$FINDING_ID" \
    --output - \
  > demo/defcon/artifacts/witness.json

test -s demo/defcon/artifacts/witness.json && \
  echo "Witness ready: demo/defcon/artifacts/witness.json"

docker compose -f demo/defcon/compose.yml \
  exec -T workstation \
  agenthound campaign \
    http://crm-mcp:8931/mcp \
    --scenario cred-reach \
    --witness /demo/artifacts/witness.json \
    --credential-env AGENTHOUND_CAMPAIGN_CREDENTIAL \
    --engagement-id DEFCON34-CRED-REACH \
    --commit \
    --output /demo/artifacts/campaign.json
```

The campaign must report `credential_gated_reach_verified`, `control=denied`,
`authed=allowed`, and `campaign.json nodes=2 edges=1`.

Import `campaign.json` in the dashboard and reopen the original finding. Its
full ID must be unchanged, while its state becomes `DEFAULT / VERIFIED / 100%
CONF`. The Campaign Verification panel must show the denied unauthenticated
control and allowed authenticated exact-resource read.

## Stop or reset

```bash
# Stop while retaining database volumes and JSON artifacts
docker compose -f demo/defcon/compose.yml down

# Or clear only this lab's database volumes
docker compose -f demo/defcon/compose.yml down --volumes --remove-orphans
```

The target data and bearer token are synthetic. The campaign is read-only and
verifies credential-gated reachability; it does not prove credential theft,
agent invocation, exfiltration, or impact.
