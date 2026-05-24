package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DiscountStackingUsage struct {
	ID                    int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID             uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_stacking_usage_company_rule_date,priority:1" json:"companyId"`
	RuleID                uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_stacking_usage_company_rule_date,priority:2" json:"ruleId"`
	Date                  time.Time       `gorm:"type:date;not null;uniqueIndex:idx_stacking_usage_company_rule_date,priority:3" json:"date"`
	TimesUsed             int             `gorm:"not null;default:0" json:"timesUsed"`
	TotalCombinedDiscount decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalCombinedDiscount"`
	UpdatedAt             time.Time       `gorm:"not null;default:now()" json:"updatedAt"`
}

func (DiscountStackingUsage) TableName() string {
	return "sales_analytics.discount_stacking_usage"
}
