package models

import (
	"time"

	"auth-service/internal/kyc/models/enums"

	"github.com/google/uuid"
)

type KYCDocument struct {
	ID                uuid.UUID                  `json:"id"`
	UserID            uuid.UUID                  `json:"userId"`
	DocumentType      enums.DocumentType         `json:"documentType"`
	FileKey           string                     `json:"fileKey"`
	FileMetadata      JSONB                      `json:"fileMetadata"`
	UploadStatus      enums.DocumentUploadStatus `json:"uploadStatus"`
	VerificationNotes *string                    `json:"verificationNotes,omitempty"`
	VerifiedBy        *uuid.UUID                 `json:"verifiedBy,omitempty"`
	VerifiedAt        *time.Time                 `json:"verifiedAt,omitempty"`
	ExpiresAt         *time.Time                 `json:"expiresAt,omitempty"`
	CreatedAt         time.Time                  `json:"createdAt"`
	UpdatedAt         time.Time                  `json:"updatedAt"`
}
