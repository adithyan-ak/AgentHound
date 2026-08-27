# Install AgentHound

Install the collector on the system where the scan will run. Deploy the analysis server only where you want to ingest and inspect artifacts.

## Requirements

| Goal | Supported environment |
|---|---|
| Install with the shell installer | macOS or Linux on amd64 or arm64, with a POSIX shell, `curl`, `tar`, and either `sha256sum` or `shasum` |
| Install with Homebrew | macOS or Linux with Homebrew |
| Install on Windows | Download the amd64 or arm64 zip from [GitHub Releases](https://github.com/adithyan-ak/AgentHound/releases) and place `agenthound.exe` on `PATH` |
| Run the analysis stack | Docker with Compose v2 |

## Collector

The release installer selects the platform archive and installs `agenthound` under `$HOME/.local/bin` by default:

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.1/install.sh \
  | AGENTHOUND_VERSION=1.1.1 sh
export PATH="$HOME/.local/bin:$PATH"
agenthound version
```

Homebrew is also supported:

```bash
brew install adithyan-ak/agenthound/agenthound
```

The collector is a static binary and does not require Neo4j, PostgreSQL, Node.js, or a running AgentHound server.

## Analysis server

Docker Compose provides `agenthound-server`, Neo4j, and PostgreSQL:

```bash
curl -sSfL \
  https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.1/docker/docker-compose.public.yml \
  -o agenthound-compose.yml
docker compose -f agenthound-compose.yml -p agenthound up -d --wait
```

Open `http://127.0.0.1:8080`. The server binds to loopback by default.

Use the collector and server from the same release. Releases after `1.1.1` pin
the exact server image in Compose. Older Compose files retain their historical
`latest` reference. The collector still runs offline and does not need a live
server while it scans.

Homebrew packages the server separately:

```bash
brew install adithyan-ak/agenthound/agenthound-server
```

Homebrew installs only the server binary. You must provide Neo4j and PostgreSQL
and configure the [server connection settings](../reference/configuration.md#analysis-server)
yourself. Use Docker Compose unless you already operate those databases.

## Build from source

```bash
git clone https://github.com/adithyan-ak/agenthound.git
cd agenthound
make build-collector
make build-server
```

The binaries are written to `bin/`. Building the server also builds and embeds the React UI. See [Development setup](../contributing/dev-setup.md) for toolchain requirements and validation commands.

## Verify a release

The installer always verifies the selected archive against `checksums.txt`. If
`cosign` is on `PATH`, it also downloads and verifies the Sigstore bundle.

To verify the signed checksum file yourself, download both files from the same
release and run:

```bash
VERSION="$(agenthound --version | awk '{print $3}')"
BASE_URL="https://github.com/adithyan-ak/AgentHound/releases/download/$VERSION"
curl -sSfLO "$BASE_URL/checksums.txt"
curl -sSfLO "$BASE_URL/checksums.txt.sigstore.json"
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/adithyan-ak/AgentHound/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Release archives also include SPDX SBOMs.

## Upgrade or remove the collector

To upgrade an installer-managed collector, rerun the pinned install command with
the desired version. For Homebrew, run `brew upgrade agenthound`.

Remove the default installer-managed binary with:

```bash
rm -f "$HOME/.local/bin/agenthound"
```

For Homebrew installations, run `brew uninstall agenthound` or
`brew uninstall agenthound-server`.

Continue with the [Quickstart](quickstart.md).
