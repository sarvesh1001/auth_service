package handler

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

var ErrAdminRequired = errors.New("admin access required")

// RequireAdmin follows RBAC-style context handling:
// - session_type: string
// - user_id: string (UUID)
// - UUID parsed here
func RequireAdmin(ctx context.Context) (uuid.UUID, error) {
	// 1. Check admin session
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok || sessionType != "admin" {
		return uuid.Nil, ErrAdminRequired
	}

	// 2. Read user_id as string (RBAC style)
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, ErrAdminRequired
	}

	// 3. Parse UUID
	adminID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, ErrAdminRequired
	}

	return adminID, nil
}
