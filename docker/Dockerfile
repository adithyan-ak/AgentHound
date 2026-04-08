FROM node:20-alpine AS ui-builder
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ .
RUN npm run build

FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui-builder /ui/dist ./internal/api/ui/dist
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/agenthound ./cmd/agenthound

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/agenthound /usr/local/bin/agenthound
EXPOSE 8080
ENTRYPOINT ["agenthound"]
CMD ["serve"]
