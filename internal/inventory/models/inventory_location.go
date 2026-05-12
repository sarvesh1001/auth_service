package models

import (
	"time"

	"github.com/google/uuid"
)

type InventoryLocation struct {
	LocationID       uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"locationId"`
	CompanyID        uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	Code             string     `gorm:"type:varchar(50);not null" json:"code"`
	Name             string     `gorm:"type:varchar(255);not null" json:"name"`
	LocationType     *string    `gorm:"type:varchar(50)" json:"locationType,omitempty"`
	ParentLocationID *uuid.UUID `gorm:"type:uuid" json:"parentLocationId,omitempty"`
	IsActive         bool       `gorm:"not null;default:true" json:"isActive"`
	CreatedAt        time.Time  `gorm:"not null;default:now()" json:"createdAt"`
}

func (InventoryLocation) TableName() string {
	return "inventory_locations"
}
