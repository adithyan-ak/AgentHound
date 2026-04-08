.PHONY: build test lint docker up down clean seed

build:
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
	rm -rf bin/ coverage.out

seed:
	@bash scripts/seed-test-data.sh
