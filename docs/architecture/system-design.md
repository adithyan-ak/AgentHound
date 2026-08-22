# System design

AgentHound separates foothold-time collection from full-graph analysis.

```text
collection host                         analysis host

agenthound scan [scope]                agenthound-server ingest scan.json
  local evidence                         validate and normalize
  guarded discovery                      publish raw graph
  service collection                     rebuild composite analysis
  local planner                          persist findings and history
  immediate restoration                  serve API and dashboard
  one scan.json
```

## Collector

The collector is a static Go binary with no database or server dependency. A scan owns local configuration and instruction collection, contact-policy enforcement, network and protocol discovery, service collection, credential handling, deterministic candidate planning, access proof, recovery, and artifact checkpointing.

The planner uses in-memory indexes over nodes, edges, targets, credentials, capabilities, and completed candidate keys. New evidence can unlock work during the same scan. Read-only work may run concurrently; a reversible mutation holds an exclusive lease through confirmed restoration.

Every AgentHound-owned HTTP request and TCP connection passes through the scan's contact policy. The guard is applied during target admission and again after DNS resolution at the final dial boundary.

## Artifact

The collector writes ingest V1 as `{meta, graph}`. `meta.extra.scan_execution` stores mode, exclusions, status, action outcomes, and recovery records. The destination is replaced with a complete JSON document after each meaningful transition.

Raw credential material lives on Credential nodes in `properties.value`. `value_hash` provides stable identity and deduplication without becoming executable material itself.

## Analysis server

The server validates and scopes collector input, writes raw observations to Neo4j, rebuilds composite relationships, stores scan and finding state in PostgreSQL, and publishes one coherent analysis revision. PostgreSQL and Neo4j are bound as one storage pair.

The REST API and embedded React application read the published projection for operator analysis. Raw administrative Cypher remains available through the server CLI and query API.

See [Server Analysis](server-analysis.md) for the publication lifecycle and [Graph Model](../reference/graph-model.md) for the data contract.
