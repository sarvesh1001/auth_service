package analytics

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DailyPlanMetrics struct {
	CompanyID        uuid.UUID       `gorm:"type:uuid;primaryKey" json:"companyId"`
	PlanID           uuid.UUID       `gorm:"type:uuid;primaryKey" json:"planId"`
	Date             time.Time       `gorm:"type:date;primaryKey" json:"date"`
	ActiveCount      int             `gorm:"not null;default:0" json:"activeCount"`
	NewCount         int             `gorm:"not null;default:0" json:"newCount"`
	CancelledCount   int             `gorm:"not null;default:0" json:"cancelledCount"`
	Revenue          decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"revenue"`
	MRR              decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"mrr"`
	UpdatedAt        time.Time       `gorm:"default:now()" json:"updatedAt"`
}
