// internal/service/phone_validator.go
package service

import (
	"context"

	"github.com/google/uuid"
)

type PhoneValidator interface {
	GetAdminIDByPhone(ctx context.Context, phoneNumber string) (uuid.UUID, error)
	GetUserIDByPhone(ctx context.Context, phoneNumber string) (uuid.UUID, error) // Add this method
	IsAdminPhoneRegistered(ctx context.Context, phoneNumber string) (bool, error)
	// NEW — User-only phone check
	IsUserPhoneRegistered(ctx context.Context, phoneNumber string) (bool, error)
}

