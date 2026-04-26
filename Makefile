.PHONY: build build-collector build-server build-all test lint docker up down clean seed demo release ui-build ui-dev ui-test standard standard-run standard-stop

ui-build:
	cd server/ui && npm install && npm run build
	rm -rf server/internal/api/ui/dist
	mkdir -p server/internal/api/ui
	cp -r server/ui/dist server/internal/api/ui/dist

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

docker:
	docker build -f docker/Dockerfile -t agenthound:dev .

up:
	docker compose -f docker/docker-compose.yml up -d

down:
	docker compose -f docker/docker-compose.yml down

clean:
	rm -rf bin/ coverage.out server/ui/dist server/internal/api/ui/dist

seed:
	@bash scripts/seed-test-data.sh

demo:
	@bash scripts/seed-demo.sh

release:
	goreleaser release --clean --snapshot

standard:
	docker build -f docker/Dockerfile.standard -t agenthound:latest .

standard-run:
	docker run -d --name agenthound -p 8080:8080 -v agenthound-data:/data --restart unless-stopped agenthound:latest

standard-stop:
	docker stop agenthound && docker rm agenthound
