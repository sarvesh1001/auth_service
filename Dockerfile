# Build stage
FROM golang:1.25.1-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy all source code
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Runtime stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates wget

WORKDIR /root/

# Copy the compiled binary
COPY --from=builder /app/main .

# Copy certs from your project (scripts/certs)
COPY scripts/certs ./certs

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider https://localhost:8443/health || exit 1

CMD ["./main"]
# # Build stage
# FROM golang:1.21-alpine AS builder
# WORKDIR /app
# RUN apk add --no-cache git ca-certificates tzdata && update-ca-certificates
# COPY go.mod go.sum ./
# RUN go mod download && go mod verify
# COPY . .
# RUN CGO_ENABLED=0 GOOS=linux go build \
#     -a -installsuffix cgo \
#     -ldflags="-w -s -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
#     -o main ./cmd/server

# # Create non-root user
# RUN addgroup -g 1001 -S appuser && \
#     adduser -u 1001 -S appuser -G appuser

# FROM alpine:latest
# RUN apk --no-cache add ca-certificates tzdata && update-ca-certificates
# WORKDIR /app
# RUN mkdir -p /app && chown -R 1001:1001 /app
# COPY --from=builder /app/main /app/main
# COPY --from=builder /app/certs /app/certs
# USER 1001
# EXPOSE 8443
# HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
#     CMD wget --no-verbose --tries=1 --spider https://localhost:8443/health || exit 1
# CMD ["./main"]
