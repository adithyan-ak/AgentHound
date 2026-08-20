.PHONY: build build-collector build-server build-all test lint check security-check integration upstream-test cross-build docker docker-collector docker-server docker-standard up down clean seed release ui-build ui-check ui-dev ui-test standard standard-run standard-stop deps-check size-check version-check sync-version docs-check prerelease preflight-build preflight-collector preflight-server preflight-docker preflight-docker-compose preflight-server-running

# Release tooling is pinned independently of the project's Go version.
# Go may download the tool's newer required toolchain on the first local run.
GORELEASER := go run github.com/goreleaser/goreleaser/v2@v2.15.4
GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4
GOVULNCHECK := go run golang.org/x/vuln/cmd/govulncheck@v1.7.0
GO_LICENSES := go run github.com/google/go-licenses@v1.6.0
ALLOWED_LICENSES := Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,Unlicense,Zlib

# Preflight gates. Verify required tools are present and at the expected
# major versions BEFORE attempting a build, so newcomers get a friendly
# error instead of a cryptic "command not found" deep in the chain.
# Set AGENTHOUND_SKIP_PREFLIGHT=1 to bypass.
preflight-build:
	@bash scripts/preflight.sh build

preflight-collector:
	@bash scripts/preflight.sh build-collector

preflight-server:
	@bash scripts/preflight.sh build-server

preflight-docker:
	@bash scripts/preflight.sh docker

preflight-docker-compose:
	@bash scripts/preflight.sh docker-compose

preflight-server-running:
	@bash scripts/preflight.sh server-running

ui-build:
	cd server/ui && npm ci --ignore-scripts && npm run build
	# Preserve dist/.gitkeep (committed so go:embed all:ui/dist works on
	# fresh clones); clear other contents and copy in the freshly-built UI.
	find server/internal/api/ui/dist -mindepth 1 -not -name .gitkeep -delete
	mkdir -p server/internal/api/ui/dist
	cp -r server/ui/dist/. server/internal/api/ui/dist/

ui-check:
	cd server/ui && npm ci --ignore-scripts && npm run lint && npm test && npm run build
	find server/internal/api/ui/dist -mindepth 1 -not -name .gitkeep -delete
	mkdir -p server/internal/api/ui/dist
	cp -r server/ui/dist/. server/internal/api/ui/dist/

ui-dev:
	cd server/ui && npm run dev

ui-test:
	cd server/ui && npm test

build-collector: preflight-collector
	go build -o bin/agenthound ./collector/cmd/agenthound

build-server: preflight-server ui-build
	go build -o bin/agenthound-server ./server/cmd/agenthound-server

build-all: build-collector build-server

# `build` keeps its name and now produces both binaries.
build: build-all

test:
	go test ./... -v -race -count=1

lint:
	$(GOLANGCI_LINT) run ./...

# Fast local equivalent of the required non-Docker PR gates.
check: preflight-build
	$(MAKE) lint
	go test ./... -short -race -count=1
	$(MAKE) deps-check
	$(MAKE) size-check
	$(MAKE) ui-check
	mkdir -p bin
	go build -o bin/agenthound ./collector/cmd/agenthound
	go build -o bin/agenthound-server ./server/cmd/agenthound-server

security-check:
	$(GOVULNCHECK) ./...
	$(GO_LICENSES) check --allowed_licenses=$(ALLOWED_LICENSES) ./collector/cmd/agenthound/... ./server/cmd/agenthound-server/...
	cd server/ui && npm audit --package-lock-only --omit=dev --audit-level=high

integration: preflight-docker-compose
	@bash test-infra/run-smoke.sh

upstream-test: preflight-docker-compose
	@bash test-infra/run-tests.sh

cross-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /dev/null ./collector/cmd/agenthound
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /dev/null ./server/cmd/agenthound-server
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o /dev/null ./collector/cmd/agenthound
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o /dev/null ./server/cmd/agenthound-server
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /dev/null ./collector/cmd/agenthound
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /dev/null ./server/cmd/agenthound-server

docker-collector: preflight-docker
	docker build -f docker/Dockerfile.agenthound -t agenthound:collector .

docker-server: preflight-docker
	docker build -f docker/Dockerfile.agenthound-server -t agenthound:server .

docker-standard: preflight-docker
	docker build -f docker/Dockerfile.standard -t agenthound:standard .

# `docker` builds both split images (server + collector). The all-in-one
# standard image is built explicitly via `make docker-standard` (or `make standard`).
docker: docker-collector docker-server

up: preflight-docker-compose
	docker compose -f docker/docker-compose.yml up -d

down: preflight-docker-compose
	docker compose -f docker/docker-compose.yml down

clean:
	rm -rf bin/ coverage.out server/ui/dist
	# Clear built UI but keep the .gitkeep marker.
	find server/internal/api/ui/dist -mindepth 1 -not -name .gitkeep -delete 2>/dev/null || true

seed: preflight-server-running
	@bash scripts/seed-test-data.sh

release: ui-build
	$(GORELEASER) check
	$(GORELEASER) release --clean --snapshot

standard: preflight-docker
	docker build -f docker/Dockerfile.standard -t agenthound:latest .

standard-run: preflight-docker
	# Build the image first if it doesn't exist locally. agenthound:latest
	# is built by `make standard`; running `make standard-run` on a fresh
	# checkout without that image would otherwise fail (or worse, pull an
	# unrelated image from a default registry).
	@if ! docker image inspect agenthound:latest >/dev/null 2>&1; then \
		echo ">>> agenthound:latest not found locally; building first (this takes a few minutes)"; \
		$(MAKE) standard; \
	fi
	# Bind on loopback only — the server has no application-layer auth.
	# Override with -p 0.0.0.0:8080:8080 only inside a network you trust.
	docker run -d --name agenthound -p 127.0.0.1:8080:8080 \
		-v agenthound-data:/data --restart unless-stopped agenthound:latest

standard-stop: preflight-docker
	docker stop agenthound && docker rm agenthound

deps-check:
	@bash scripts/deps-check.sh

size-check:
	@bash scripts/size-check.sh

# Assert the install.sh + README version pins match the CHANGELOG (the version
# source of truth). Also runs inside `make prerelease`, so release.yml enforces
# it at tag time too.
version-check:
	@bash scripts/version-check.sh
	@bash scripts/release-process-test.sh

# Rewrite the install.sh + README version pins from the CHANGELOG top header
# (or VERSION=). Usage: make sync-version   or   make sync-version VERSION=0.7.1
sync-version:
	@bash scripts/sync-version.sh $(VERSION)

# Build the MkDocs site in --strict mode (orphan pages, broken links, bad
# anchors). Mirrors the path-filtered Docs CI; needs the docs toolchain.
docs-check:
	@bash scripts/docs-check.sh

# Pre-release gate — run BEFORE tagging a release. Mirrors the CI checks that
# gate every release; fails fast on first error. Usage: make prerelease
# (Docs `mkdocs build --strict` is enforced separately by the path-filtered
# Docs workflow + `make docs-check`, so it is intentionally NOT folded in here
# to keep this gate Go/Node-only.)
prerelease:
	@echo "=== [1/4] version-check ==="
	$(MAKE) version-check
	@echo "=== [2/4] contributor checks ==="
	$(MAKE) check
	@echo "=== [3/4] security checks ==="
	$(MAKE) security-check
	@echo "=== [4/4] canonical cross-builds ==="
	$(MAKE) cross-build
	@echo ""
	@echo "=== ALL GATES PASS — safe to tag ==="
