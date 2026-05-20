.PHONY: build build-collector build-server build-all test lint docker docker-collector docker-server docker-standard up down clean seed demo release ui-build ui-dev ui-test standard standard-run standard-stop deps-check size-check prerelease

ui-build:
	cd server/ui && npm ci --ignore-scripts && npm run build
	# Preserve dist/.gitkeep (committed so go:embed all:ui/dist works on
	# fresh clones); clear other contents and copy in the freshly-built UI.
	find server/internal/api/ui/dist -mindepth 1 -not -name .gitkeep -delete 2>/dev/null || true
	mkdir -p server/internal/api/ui/dist
	cp -r server/ui/dist/. server/internal/api/ui/dist/

ui-dev:
	cd server/ui && npm run dev

ui-test:
	cd server/ui && npm test

build-collector:
	go build -o bin/agenthound ./collector/cmd/agenthound

build-server: ui-build
	go build -o bin/agenthound-server ./server/cmd/agenthound-server

build-all: build-collector build-server

# `build` keeps its name and now produces both binaries.
build: build-all

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

docker-collector:
	docker build -f docker/Dockerfile.agenthound -t agenthound:collector .

docker-server:
	docker build -f docker/Dockerfile.agenthound-server -t agenthound:server .

docker-standard:
	docker build -f docker/Dockerfile.standard -t agenthound:standard .

# `docker` builds both split images (server + collector). The all-in-one
# standard image is built explicitly via `make docker-standard` (or `make standard`).
docker: docker-collector docker-server

up:
	docker compose -f docker/docker-compose.yml up -d

down:
	docker compose -f docker/docker-compose.yml down

clean:
	rm -rf bin/ coverage.out server/ui/dist
	# Clear built UI but keep the .gitkeep marker.
	find server/internal/api/ui/dist -mindepth 1 -not -name .gitkeep -delete 2>/dev/null || true

seed:
	@bash scripts/seed-test-data.sh

demo:
	@bash scripts/seed-demo.sh

release:
	goreleaser release --clean --snapshot

standard:
	docker build -f docker/Dockerfile.standard -t agenthound:latest .

standard-run:
	# Bind on loopback only — the server has no application-layer auth.
	# Override with -p 0.0.0.0:8080:8080 only inside a network you trust.
	docker run -d --name agenthound -p 127.0.0.1:8080:8080 -v agenthound-data:/data --restart unless-stopped agenthound:latest

standard-stop:
	docker stop agenthound && docker rm agenthound

deps-check:
	@bash scripts/deps-check.sh

size-check:
	@bash scripts/size-check.sh

# Pre-release gate — run BEFORE tagging a release. Covers everything CI
# checks across all job types (push + PR). Fails fast on first error.
# Usage: make prerelease
prerelease:
	@echo "=== [1/8] gofmt ==="
	@test -z "$$(gofmt -l .)" || (echo "FAIL: gofmt found unformatted files:" && gofmt -l . && exit 1)
	@echo "=== [2/8] go vet ==="
	go vet ./...
	@echo "=== [3/8] go build ==="
	go build ./...
	@echo "=== [4/8] go test -race -short ==="
	go test ./... -race -short -count=1
	@echo "=== [5/8] deps-check ==="
	@bash scripts/deps-check.sh
	@echo "=== [6/8] size-check ==="
	@bash scripts/size-check.sh
	@echo "=== [7/8] UI build ==="
	cd server/ui && npm run build
	@echo "=== [8/8] cross-compile (linux/amd64 + darwin/arm64) ==="
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /dev/null ./collector/cmd/agenthound
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o /dev/null ./collector/cmd/agenthound
	@echo ""
	@echo "=== ALL GATES PASS — safe to tag ==="
