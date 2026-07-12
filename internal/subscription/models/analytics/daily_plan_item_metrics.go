package analytics

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DailyPlanItemMetrics struct {
	CompanyID           uuid.UUID       `gorm:"type:uuid;primaryKey" json:"companyId"`
	PlanItemID          uuid.UUID       `gorm:"type:uuid;primaryKey" json:"planItemId"`
	Date                time.Time       `gorm:"type:date;primaryKey" json:"date"`
	TotalQuantity       decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalQuantity"`
	ActiveSubscriptions int             `gorm:"not null;default:0" json:"activeSubscriptions"`
	Revenue             decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"revenue"`
	UpdatedAt           time.Time       `gorm:"default:now()" json:"updatedAt"`
}
