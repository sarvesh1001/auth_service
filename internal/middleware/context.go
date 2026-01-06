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
	if v, ok := ctx.Value(ContextUserID).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}

func GetSessionTypeFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ContextActorType).(string); ok {
		return v
	}
	return ""
}
