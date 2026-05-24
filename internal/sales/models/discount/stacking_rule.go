package discount

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"gorm.io/datatypes"
)

type DiscountStackingRule struct {
	RuleID              uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"ruleId"`
	CompanyID           uuid.UUID        `gorm:"type:uuid;not null;index" json:"companyId"`
	RuleName            string           `gorm:"type:varchar(100);not null" json:"ruleName"`
	IsActive            bool             `gorm:"not null;default:true" json:"isActive"`
	PrimaryDiscountType string           `gorm:"type:varchar(30);not null" json:"primaryDiscountType"`
	PrimaryDiscountID   uuid.UUID        `gorm:"type:uuid;not null" json:"primaryDiscountId"`
	AllowedTypes        datatypes.JSON   `gorm:"type:jsonb;not null" json:"allowedTypes"`
	MaxTotalDiscount    *decimal.Decimal `gorm:"type:numeric(14,4)" json:"maxTotalDiscount,omitempty"`
	CreatedAt           time.Time        `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt           time.Time        `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy           *uuid.UUID       `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy           *uuid.UUID       `gorm:"type:uuid" json:"updatedBy,omitempty"`
}

func (DiscountStackingRule) TableName() string {
	return "sales.discount_stacking_rules"
}
