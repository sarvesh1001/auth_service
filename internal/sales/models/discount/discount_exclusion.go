package discount

import (
	"time"

	"github.com/google/uuid"
)

type DiscountExclusion struct {
	ExclusionID   uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"exclusionId"`
	CompanyID     uuid.UUID  `gorm:"type:uuid;not null;index" json:"companyId"`
	DiscountTypeA string     `gorm:"type:varchar(30);not null" json:"discountTypeA"`
	DiscountIDA   uuid.UUID  `gorm:"type:uuid;not null" json:"discountIdA"`
	DiscountTypeB string     `gorm:"type:varchar(30);not null" json:"discountTypeB"`
	DiscountIDB   uuid.UUID  `gorm:"type:uuid;not null" json:"discountIdB"`
	CreatedAt     time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	CreatedBy     *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
}

func (DiscountExclusion) TableName() string {
	return "sales.discount_exclusions"
}
