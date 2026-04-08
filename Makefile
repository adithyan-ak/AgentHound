.PHONY: build test lint docker up down clean seed ui-build ui-dev ui-test

ui-build:
	cd ui && npm install && npm run build
	rm -rf internal/api/ui/dist
	mkdir -p internal/api/ui
	cp -r ui/dist internal/api/ui/dist

ui-dev:
	cd ui && npm run dev

ui-test:
	cd ui && npm test

build: ui-build
	go build -o bin/agenthound ./cmd/agenthound

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
	rm -rf bin/ coverage.out ui/dist internal/api/ui/dist

seed:
	@bash scripts/seed-test-data.sh
