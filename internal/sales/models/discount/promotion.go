package discount

import (
	"time"

	"github.com/google/uuid"
)

type Promotion struct {
	PromotionID uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"promotionId"`
	CompanyID   uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	Name        string     `gorm:"type:varchar(255);not null" json:"name"`
	Description *string    `gorm:"type:text" json:"description,omitempty"`
	StartDate   time.Time  `gorm:"type:timestamptz;not null" json:"startDate"`
	EndDate     time.Time  `gorm:"type:timestamptz;not null" json:"endDate"`
	IsActive    bool       `gorm:"not null;default:true" json:"isActive"`
	Priority    *int       `gorm:"type:int;default:0" json:"priority,omitempty"`
	CreatedAt   time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt   time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy   *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy   *uuid.UUID `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
