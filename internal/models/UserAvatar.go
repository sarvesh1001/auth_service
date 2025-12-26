package models

import (
	"time"

	"github.com/google/uuid"
)

type UserAvatar struct {
	AvatarID        uuid.UUID `db:"avatar_id"`
	UserID          uuid.UUID `db:"user_id"`

	AvatarType      string    `db:"avatar_type"`
	AvatarHash      string    `db:"avatar_hash"`
	AvatarObjectKey string    `db:"avatar_object_key"`
	AvatarMimeType  string    `db:"avatar_mime_type"`

	IsActive        bool      `db:"is_active"`
	IsPrimary       bool      `db:"is_primary"`

	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}
