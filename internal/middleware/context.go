package middleware

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const (
	ContextCompanyID contextKey = "company_id"
	ContextUserID    contextKey = "user_id"
	ContextActorType contextKey = "actor_type"
)

func GetCompanyIDFromContext(ctx context.Context) uuid.UUID {
	if v, ok := ctx.Value(ContextCompanyID).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}

func GetUserIDFromContext(ctx context.Context) uuid.UUID {
	// ✅ Preferred: set by EnhancedCompanyAccessMiddleware
	if v, ok := ctx.Value("current_user_id").(uuid.UUID); ok {
		return v
	}

	// ♻️ Fallback: JWT middleware (string)
	if v := ctx.Value("user_id"); v != nil {
		switch raw := v.(type) {
		case uuid.UUID:
			return raw
		case string:
			id, err := uuid.Parse(raw)
			if err == nil {
				return id
			}
		}
	}

	return uuid.Nil
}

func GetSessionTypeFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ContextActorType).(string); ok {
		return v
	}
	return ""
}
