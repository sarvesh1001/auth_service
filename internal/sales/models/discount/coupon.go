package discount

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"gorm.io/datatypes"
)

type Coupon struct {
	CouponID          uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"couponId"`
	CompanyID         uuid.UUID          `gorm:"type:uuid;not null" json:"companyId"`
	Code              string             `gorm:"type:varchar(100);not null;uniqueIndex:idx_coupon_code" json:"code"`
	DiscountType      enums.DiscountType `gorm:"type:discount_type;not null" json:"discountType"`
	DiscountValue     decimal.Decimal    `gorm:"type:numeric(14,4);not null" json:"discountValue"`
	MaxDiscountAmount *decimal.Decimal   `gorm:"type:numeric(14,4)" json:"maxDiscountAmount,omitempty"`
	StartDate         time.Time          `gorm:"type:timestamptz;not null" json:"startDate"`
	EndDate           time.Time          `gorm:"type:timestamptz;not null" json:"endDate"`
	UsageLimit        *int               `gorm:"type:int" json:"usageLimit,omitempty"`
	PerUserLimit      *int               `gorm:"type:int;default:1" json:"perUserLimit,omitempty"`
	MinOrderAmount    *decimal.Decimal   `gorm:"type:numeric(14,4)" json:"minOrderAmount,omitempty"`
	ApplicableItems   datatypes.JSON     `gorm:"type:jsonb" json:"applicableItems,omitempty"`
	IsActive          bool               `gorm:"not null;default:true" json:"isActive"`
	DeletedAt         *time.Time         `gorm:"index" json:"deletedAt,omitempty"` // ← ADD THIS LINE
	StackingType      string             `gorm:"type:varchar(20);not null;default:'stackable'" json:"stackingType"`
	CreatedAt         time.Time          `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt         time.Time          `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy         *uuid.UUID         `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy         *uuid.UUID         `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
