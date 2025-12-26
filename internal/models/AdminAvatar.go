package models

import (
	"time"

	"github.com/google/uuid"
)

type AdminAvatar struct {
	AvatarID        uuid.UUID `db:"avatar_id"`
	AdminID         uuid.UUID `db:"admin_id"`

	AvatarType      string    `db:"avatar_type"`       // uploaded
	AvatarHash      string    `db:"avatar_hash"`
	AvatarObjectKey string    `db:"avatar_object_key"` // file path / S3 key
	AvatarMimeType  string    `db:"avatar_mime_type"`

	IsActive        bool      `db:"is_active"`
	IsPrimary       bool      `db:"is_primary"`

	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

// Add this to models/admin_user.go or create a new file

// AdminAvatarInfo represents basic avatar information for API responses
type AdminAvatarInfo struct {
    AdminID   uuid.UUID      `json:"admin_id"`
    HasAvatar bool           `json:"has_avatar"`
    Avatar    *AdminAvatar   `json:"avatar,omitempty"`
    Initials  string         `json:"initials,omitempty"`
}