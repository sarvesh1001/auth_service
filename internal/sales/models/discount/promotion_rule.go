package discount

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"gorm.io/datatypes"
)

type PromotionRule struct {
	RuleID        uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"ruleId"`
	PromotionID   uuid.UUID          `gorm:"type:uuid;not null" json:"promotionId"`
	RuleType      string             `gorm:"type:varchar(50);not null" json:"ruleType"`
	RuleConfig    datatypes.JSON     `gorm:"type:jsonb;not null" json:"ruleConfig"`
	DiscountType  enums.DiscountType `gorm:"type:discount_type;not null" json:"discountType"`
	DiscountValue decimal.Decimal    `gorm:"type:numeric(14,4);not null" json:"discountValue"`
	MaxDiscount   *decimal.Decimal   `gorm:"type:numeric(14,4)" json:"maxDiscount,omitempty"`
	CreatedAt     time.Time          `gorm:"not null;default:now()" json:"createdAt"`
}
