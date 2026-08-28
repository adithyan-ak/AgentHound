# CLI reference

AgentHound ships a collector and an optional analysis server. Bare invocation shows help.

## Collector

```text
agenthound scan [CIDR|host|@targets-file]
agenthound revert <scan.json>
agenthound version
```

### `agenthound scan`

Local configuration, instruction, and credential collection always runs. One positional hostname, IP, CIDR, or `@targets-file` adds network scope.

| Flag | Default | Meaning |
|---|---:|---|
| `--deep` | `false` | Add bounded recursive and high-cost evidence collection. |
| `--exclude <value>` | none | Exclude an exact hostname, IP, or CIDR; repeatable. |
| `--insecure` | `false` | Skip TLS certificate verification. |
| `--output <path>` | `scan-<scan_id>.json` | Write the artifact to a file, replacing an existing file at that path. Directories and `-` are rejected. |
| `--quiet` | `false` | Suppress non-error progress, discovered-secret output, and instruction-signal excerpts. |
| `--stealth` | `false` | Keep the scan read-only and disable credential reuse and active probes. |
| `--timeout <duration>` | `15m` | Set the overall scan deadline. |

Success exits `0`. Invalid input, checkpoint failure, fatal scan failure, or unresolved cleanup exits nonzero. Independent collection failures remain recorded in the artifact and do not necessarily make the whole scan fail.

For every non-clean instruction file, normal output includes its path, line, primary rule, and a bounded excerpt. The complete structured evidence remains in the JSON artifact; `--quiet` suppresses the terminal summary only.

### `agenthound revert`

```text
agenthound revert <scan.json>
```

Retries unresolved recovery records newest-first using endpoint, TLS, exclusion, and credential data in the artifact. Restored records are skipped. The command exits nonzero while any record remains unresolved.

### `agenthound version`

Prints the collector version and build commit. `agenthound --version` provides the same version string.

## Analysis server

```text
agenthound-server serve
agenthound-server ingest <file.json | ->
agenthound-server query [cypher] [flags]
agenthound-server version
```

All server commands accept these global flags:

| Flag | Default | Meaning |
|---|---:|---|
| `--bind <host:port>` | `127.0.0.1:8080` | API and dashboard bind address. |
| `--cors-origins <list>` | loopback browser origins | Comma-separated allowed browser origins. |
| `--log-level <level>` | `info` | `debug`, `info`, `warn`, or `error`. |
| `--neo4j-uri <uri>` | `bolt://localhost:7687` | Neo4j connection URI. |
| `--neo4j-user <user>` | `neo4j` | Neo4j username. |
| `--neo4j-password <value>` | `agenthound` | Neo4j password. |
| `--pg-uri <uri>` | local AgentHound database | PostgreSQL connection URI. |

### `agenthound-server serve`

Starts the REST API and embedded dashboard after validating the PostgreSQL and Neo4j pair.

### `agenthound-server ingest`

Ingests a complete JSON envelope from a file. `-` reads a complete envelope from standard input for automation.

```bash
agenthound-server ingest scan.json
```

A completed ingest prints the collector version, artifact contract, and running
server version. Unsupported-contract errors include the same compatibility
details, reject the artifact before database bootstrap or writes, and tell the
operator to upgrade the server.

### `agenthound-server query`

Select exactly one query mode:

```bash
agenthound-server query 'MATCH (n:MCPServer) RETURN n.name'
agenthound-server query --prebuilt agents-shell-access
agenthound-server query --findings --severity high
agenthound-server query --diff scan-a,scan-b
agenthound-server query --shortest-path \
  --from AgentInstance:operator-agent \
  --to MCPResource:customer-records
```

| Flag | Meaning |
|---|---|
| `--prebuilt <id>` | Run a registered prebuilt query. |
| `--findings` | List findings. |
| `--severity <level>` | Filter findings by `critical`, `high`, `medium`, or `low`. |
| `--diff <scanA,scanB>` | Compare the findings from two scans. |
| `--shortest-path` | Find a path between `--from` and `--to`. |
| `--from <Kind:name>` | Select the path source. |
| `--to <Kind:name>` | Select the path destination. |
| `--path-mode <mode>` | Use directed `security` traversal or undirected `topology`; default `security`. |
| `--format <format>` | Emit `table` or `json`; default `table`. |
| `--fail-on <level>` | Exit `1` when a non-suppressed finding meets the severity threshold. |
| `--all-findings` | Include accepted-risk and false-positive findings in output. |

### `agenthound-server version`

Prints the server version and build commit. `agenthound-server --version` provides the same version string.
