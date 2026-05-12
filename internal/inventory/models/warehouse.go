package models

import (
	"time"

	"github.com/google/uuid"
)

type Warehouse struct {
	WarehouseID uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"warehouseId"`
	CompanyID   uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	Code        string     `gorm:"type:varchar(50);not null" json:"code"`
	Name        string     `gorm:"type:varchar(255);not null" json:"name"`
	Location    *string    `gorm:"type:text" json:"location,omitempty"`
	IsActive    bool       `gorm:"not null;default:true" json:"isActive"`
	CreatedAt   time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt   time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy   *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy   *uuid.UUID `gorm:"type:uuid" json:"updatedBy,omitempty"`

	// New fields (already present)
	LocationID         *uuid.UUID `gorm:"type:uuid" json:"locationId,omitempty"`
	WarehouseType      *string    `gorm:"type:varchar(50)" json:"warehouseType,omitempty"`
	AllowNegativeStock bool       `gorm:"not null;default:false" json:"allowNegativeStock"`

	// Missing field – now added
	IsDefault bool `gorm:"not null;default:false" json:"isDefault"`
}
