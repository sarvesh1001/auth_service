package discount

import (
	"time"

	"github.com/google/uuid"
)

type DiscountPriority struct {
	PriorityID   uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"priorityId"`
	CompanyID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"companyId"`
	DiscountType string     `gorm:"type:varchar(30);not null" json:"discountType"`
	DiscountID   *uuid.UUID `gorm:"type:uuid" json:"discountId,omitempty"` // NULL means all discounts of that type
	Priority     int        `gorm:"not null" json:"priority"`
	CreatedAt    time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt    time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy    *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy    *uuid.UUID `gorm:"type:uuid" json:"updatedBy,omitempty"`
}

func (DiscountPriority) TableName() string {
	return "sales.discount_priorities"
}
