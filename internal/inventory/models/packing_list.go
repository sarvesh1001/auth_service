package models

import (
	"time"

	"github.com/google/uuid"
)

type PackingList struct {
	PackingListID uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"packingListId"`
	CompanyID     uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	ShipmentID    uuid.UUID  `gorm:"type:uuid;not null" json:"shipmentId"`
	Status        string     `gorm:"type:varchar(20);not null;default:'created'" json:"status"`
	PackedBy      *uuid.UUID `gorm:"type:uuid" json:"packedBy,omitempty"`
	CreatedAt     time.Time  `gorm:"default:now()" json:"createdAt"`
	PackedAt      *time.Time `gorm:"type:timestamptz" json:"packedAt,omitempty"`
	VerifiedAt    *time.Time `gorm:"type:timestamptz" json:"verifiedAt,omitempty"`
	CompletedAt   *time.Time `gorm:"type:timestamptz" json:"completedAt,omitempty"` // <-- ADD

}

func (PackingList) TableName() string { return "packing_lists" }
