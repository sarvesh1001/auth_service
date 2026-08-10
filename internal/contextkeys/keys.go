package contextkeys

// internal/contextkeys/keys.go

type contextKey string

const (
	IdempotencyKey contextKey = "idempotency_key"
	ClientIP       contextKey = "client_ip"
	// ... other keys
)
