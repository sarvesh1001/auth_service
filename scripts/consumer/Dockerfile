# ==========================================
# File: scripts/consumer/Dockerfile
# Purpose: Kafka → ClickHouse + Elasticsearch Consumer
# ==========================================

# ---- Build stage ----
    FROM golang:1.25.1-alpine AS builder
    WORKDIR /app
    RUN apk add --no-cache git ca-certificates tzdata && update-ca-certificates
    
    # Copy Go module files
    COPY go.mod go.sum ./
    RUN go mod download
    
    # Copy consumer source
    COPY scripts/consumer/ ./scripts/consumer/
    
    # Build the binary
    RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" \
        -o /app/consumer ./scripts/consumer/main.go
    
    # ---- Runtime stage ----
    FROM alpine:3.20
    WORKDIR /app
    RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates
    
    # Copy built binary
    COPY --from=builder /app/consumer /consumer
    
    # Default environment vars
    ENV KAFKA_BROKERS=kafka:9092
    ENV CLICKHOUSE_DSN=clickhouse://auth_svc_user:Vu8eeS4ahtha3Aithae1ie2IeMae4ee1oo1o@clickhouse:9000/auth_analytics
    ENV ES_URL=http://elasticsearch:9200
    
    ENTRYPOINT ["/consumer"]
    