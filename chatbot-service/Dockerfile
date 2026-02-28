# ---------- BUILD STAGE ----------
    FROM golang:1.25-alpine AS builder

    WORKDIR /app
    
    RUN apk add --no-cache git
    
    COPY go.mod go.sum ./
    RUN go mod download
    
    COPY . .
    
    RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o chatbot ./cmd/main.go
    
    
    # ---------- RUNTIME STAGE ----------
    FROM alpine:latest
    
    WORKDIR /app
    
    RUN apk add --no-cache ca-certificates
    
    COPY --from=builder /app/chatbot .
    
    EXPOSE 9090
    
    CMD ["./chatbot"]