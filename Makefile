.PHONY: build build-collector build-server build-all test lint docker docker-collector docker-server docker-standard up down clean seed demo release ui-build ui-dev ui-test standard standard-run standard-stop deps-check size-check slop-check prerelease preflight-build preflight-collector preflight-server preflight-docker preflight-docker-compose preflight-server-running preflight-demo

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

preflight-demo:
	@bash scripts/preflight.sh demo

ui-build:
	cd server/ui && npm ci --ignore-scripts && npm run build
	# Preserve dist/.gitkeep (committed so go:embed all:ui/dist works on
	# fresh clones); clear other contents and copy in the freshly-built UI.
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
	golangci-lint run ./...

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

demo: preflight-demo
	@bash scripts/seed-demo.sh

release: ui-build
	goreleaser release --clean --snapshot

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
	docker run -d --name agenthound -p 127.0.0.1:8080:8080 -v agenthound-data:/data --restart unless-stopped agenthound:latest

standard-stop: preflight-docker
	docker stop agenthound && docker rm agenthound

deps-check:
	@bash scripts/deps-check.sh

size-check:
	@bash scripts/size-check.sh

# UI design-system regression gate — fails if banned slop patterns reappear.
# Override individual rules with SLOP_SKIP="rule1,rule2".
slop-check:
	@bash scripts/slop-check.sh

# Pre-release gate — run BEFORE tagging a release. Covers everything CI
# checks across all job types (push + PR). Fails fast on first error.
# Usage: make prerelease
prerelease:
	@echo "=== [1/12] gofmt ==="
	@test -z "$$(gofmt -l .)" || (echo "FAIL: gofmt found unformatted files:" && gofmt -l . && exit 1)
	@echo "=== [2/12] golangci-lint ==="
	golangci-lint run ./...
	@echo "=== [3/12] go vet ==="
	go vet ./...
	@echo "=== [4/12] govulncheck ==="
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	@echo "=== [5/12] go-licenses ==="
	go run github.com/google/go-licenses@latest check --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,Unlicense,Zlib ./collector/cmd/agenthound/... ./server/cmd/agenthound-server/...
	@echo "=== [6/12] go build ==="
	go build ./...
	@echo "=== [7/12] go test -race -short ==="
	go test ./... -race -short -count=1
	@echo "=== [8/12] deps-check ==="
	@bash scripts/deps-check.sh
	@echo "=== [9/12] size-check ==="
	@bash scripts/size-check.sh
	@echo "=== [10/12] slop-check ==="
	@bash scripts/slop-check.sh
	@echo "=== [11/12] UI build ==="
	cd server/ui && npm run build
	@echo "=== [12/12] cross-compile (linux/amd64 + darwin/arm64) ==="
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /dev/null ./collector/cmd/agenthound
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o /dev/null ./collector/cmd/agenthound
	@echo ""
	@echo "=== ALL GATES PASS — safe to tag ==="
