# Install AgentHound

Install the collector on the system where the scan will run. Deploy the analysis server only where you want to ingest and inspect artifacts.

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

Homebrew packages the server separately:

```bash
brew install adithyan-ak/agenthound/agenthound-server
```

## Build from source

```bash
git clone https://github.com/adithyan-ak/agenthound.git
cd agenthound
make build-collector
make build-server
```

The binaries are written to `bin/`. Building the server also builds and embeds the React UI. See [Development setup](../contributing/dev-setup.md) for toolchain requirements and validation commands.

## Verify a release

Release archives include checksums, a Sigstore bundle, and SPDX SBOMs. Verify the checksum bundle with cosign:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/adithyan-ak/AgentHound/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
```

Continue with the [Quickstart](quickstart.md).
