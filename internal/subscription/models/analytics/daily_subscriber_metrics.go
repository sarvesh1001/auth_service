package analytics

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DailySubscriberMetrics struct {
	CompanyID           uuid.UUID       `gorm:"type:uuid;primaryKey" json:"companyId"`
	SubscriberType      string          `gorm:"type:varchar(20);primaryKey" json:"subscriberType"`
	Date                time.Time       `gorm:"type:date;primaryKey" json:"date"`
	ActiveSubscriptions int             `gorm:"not null;default:0" json:"activeSubscriptions"`
	NewSubscriptions    int             `gorm:"not null;default:0" json:"newSubscriptions"`
	TotalSpent          decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"totalSpent"`
	UpdatedAt           time.Time       `gorm:"default:now()" json:"updatedAt"`
}
