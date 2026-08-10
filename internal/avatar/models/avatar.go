package models

import (
	"time"

	"github.com/google/uuid"
)

// AvatarType defines the source of the avatar
type AvatarType string

const (
	AvatarTypeUploaded AvatarType = "uploaded"
	AvatarTypeDefault  AvatarType = "default"
	AvatarTypeExternal AvatarType = "external"
)

// Avatar represents a user avatar record
type Avatar struct {
	ID        uuid.UUID         `json:"id"`
	UserID    uuid.UUID         `json:"userId"`
	Type      AvatarType        `json:"type"`
	Hash      string            `json:"hash,omitempty"`
	ObjectKey string            `json:"objectKey"` // original uploaded file key
	MimeType  string            `json:"mimeType,omitempty"`
	IsActive  bool              `json:"isActive"`
	IsPrimary bool              `json:"isPrimary"`
	Variants  map[string]string `json:"variants"` // size -> objectKey
	CreatedAt time.Time         `json:"createdAt"`
	UpdatedAt time.Time         `json:"updatedAt"`
}
