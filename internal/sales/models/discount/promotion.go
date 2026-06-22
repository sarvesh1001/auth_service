package discount

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Promotion represents a sales promotion with rules and usage limits.
type Promotion struct {
	PromotionID  uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"promotionId"`
	CompanyID    uuid.UUID `gorm:"type:uuid;not null" json:"companyId"`
	Name         string    `gorm:"type:varchar(255);not null" json:"name"`
	Description  *string   `gorm:"type:text" json:"description,omitempty"`
	StartDate    time.Time `gorm:"type:timestamptz;not null" json:"startDate"`
	EndDate      time.Time `gorm:"type:timestamptz;not null" json:"endDate"`
	IsActive     bool      `gorm:"not null;default:true" json:"isActive"`
	Priority     *int      `gorm:"type:int;default:0" json:"priority,omitempty"`
	StackingType string    `gorm:"type:varchar(20);not null;default:'stackable'" json:"stackingType"`

	// New fields for usage limits and soft delete
	UsageLimit   *int       `gorm:"type:int" json:"usageLimit,omitempty"`
	PerUserLimit *int       `gorm:"type:int;default:1" json:"perUserLimit,omitempty"`
	DeletedAt    *time.Time `gorm:"type:timestamptz;index" json:"deletedAt,omitempty"`

	CreatedAt time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy *uuid.UUID `gorm:"type:uuid" json:"updatedBy,omitempty"`
}

// TableName overrides the table name for GORM.
func (Promotion) TableName() string {
	return "sales.promotions"
}

// BeforeCreate hook to auto-generate UUID if not set (optional, GORM handles default)
func (p *Promotion) BeforeCreate(tx *gorm.DB) error {
	if p.PromotionID == uuid.Nil {
		p.PromotionID = uuid.New()
	}
	return nil
}
