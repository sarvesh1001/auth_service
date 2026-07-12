package analytics

import (
	"time"

	"github.com/google/uuid"
)

// DailyBenefitMetrics aggregates daily counts per benefit.
type DailyBenefitMetrics struct {
	CompanyID   uuid.UUID `gorm:"type:uuid;primaryKey" json:"companyId"`
	BenefitID   uuid.UUID `gorm:"type:uuid;primaryKey" json:"benefitId"`
	Date        time.Time `gorm:"type:date;primaryKey" json:"date"`
	ActiveCount int       `gorm:"not null;default:0" json:"activeCount"` // subscriptions with this benefit active
	NewCount    int       `gorm:"not null;default:0" json:"newCount"`    // new attachments on that date
	// TotalDiscount decimal.Decimal `gorm:"type:numeric(14,2)" json:"totalDiscount,omitempty"` // optional
	UpdatedAt time.Time `gorm:"default:now()" json:"updatedAt"`
}

// TableName specifies the table name.
func (DailyBenefitMetrics) TableName() string {
	return "subscription_analytics.daily_benefit_metrics"
}
