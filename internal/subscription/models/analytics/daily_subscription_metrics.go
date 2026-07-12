package analytics

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DailySubscriptionMetrics struct {
	CompanyID             uuid.UUID       `gorm:"type:uuid;primaryKey" json:"companyId"`
	Date                  time.Time       `gorm:"type:date;primaryKey" json:"date"`
	NewSubscriptions      int             `gorm:"not null;default:0" json:"newSubscriptions"`
	ActiveSubscriptions   int             `gorm:"not null;default:0" json:"activeSubscriptions"`
	CancelledSubscriptions int            `gorm:"not null;default:0" json:"cancelledSubscriptions"`
	ExpiredSubscriptions  int             `gorm:"not null;default:0" json:"expiredSubscriptions"`
	PausedSubscriptions   int             `gorm:"not null;default:0" json:"pausedSubscriptions"`
	TrialStarts           int             `gorm:"not null;default:0" json:"trialStarts"`
	TrialConversions      int             `gorm:"not null;default:0" json:"trialConversions"`
	TrialExpirations      int             `gorm:"not null;default:0" json:"trialExpirations"`
	MRR                   decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"mrr"`
	ARR                   decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"arr"`
	TotalRevenue          decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"totalRevenue"`
	ChurnedSubscriptions  int             `gorm:"not null;default:0" json:"churnedSubscriptions"`
	UpdatedAt             time.Time       `gorm:"default:now()" json:"updatedAt"`
}
