package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// PromotionUsageFact records each time a promotion is applied to an order or invoice.
type PromotionUsageFact struct {
	ID             int64            `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID      uuid.UUID        `gorm:"type:uuid;not null" json:"companyId"`
	PromotionID    uuid.UUID        `gorm:"type:uuid;not null" json:"promotionId"`
	EntityType     string           `gorm:"type:varchar(20);not null" json:"entityType"` // 'order', 'invoice'
	EntityID       uuid.UUID        `gorm:"type:uuid;not null" json:"entityId"`
	CustomerID     *uuid.UUID       `gorm:"type:uuid" json:"customerId,omitempty"`
	DiscountAmount decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"discountAmount"`
	OrderSubtotal  *decimal.Decimal `gorm:"type:numeric(14,4)" json:"orderSubtotal,omitempty"`
	UsedAt         time.Time        `gorm:"type:timestamptz;not null" json:"usedAt"`
	CreatedAt      time.Time        `gorm:"default:now()" json:"createdAt"`
}

func (PromotionUsageFact) TableName() string {
	return "sales_analytics.promotion_usage_fact"
}

// DailyPromotionMetric aggregates promotion usage per day.
type DailyPromotionMetric struct {
	ID                  int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID           uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_daily_promotion_metrics_unique,priority:1" json:"companyId"`
	PromotionID         uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_daily_promotion_metrics_unique,priority:2" json:"promotionId"`
	Date                time.Time       `gorm:"type:date;not null;uniqueIndex:idx_daily_promotion_metrics_unique,priority:3" json:"date"`
	TimesApplied        int             `gorm:"not null;default:0" json:"timesApplied"`
	TotalDiscountAmount decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalDiscountAmount"`
	TotalOrderValue     decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalOrderValue"`
	UniqueCustomers     int             `gorm:"not null;default:0" json:"uniqueCustomers"`
	UpdatedAt           time.Time       `gorm:"not null;default:now()" json:"updatedAt"`
}

func (DailyPromotionMetric) TableName() string {
	return "sales_analytics.daily_promotion_metrics"
}

// DailyPromotionUniqueCustomer tracks distinct customers using a promotion on a given day.
type DailyPromotionUniqueCustomer struct {
	CompanyID   uuid.UUID `gorm:"type:uuid;primaryKey" json:"companyId"`
	PromotionID uuid.UUID `gorm:"type:uuid;primaryKey" json:"promotionId"`
	Date        time.Time `gorm:"type:date;primaryKey" json:"date"`
	CustomerID  uuid.UUID `gorm:"type:uuid;primaryKey" json:"customerId"`
}

func (DailyPromotionUniqueCustomer) TableName() string {
	return "sales_analytics.daily_promotion_unique_customers"
}

// PromotionPerformanceSummary holds overall promotion performance.
type PromotionPerformanceSummary struct {
	PromotionID        uuid.UUID        `gorm:"type:uuid;primaryKey" json:"promotionId"`
	CompanyID          uuid.UUID        `gorm:"type:uuid;not null;index" json:"companyId"`
	TotalTimesUsed     int64            `gorm:"not null;default:0" json:"totalTimesUsed"`
	TotalDiscountGiven decimal.Decimal  `gorm:"type:numeric(14,4);not null;default:0" json:"totalDiscountGiven"`
	AvgDiscountPerUse  *decimal.Decimal `gorm:"type:numeric(14,4)" json:"avgDiscountPerUse,omitempty"`
	UniqueCustomers    int              `gorm:"not null;default:0" json:"uniqueCustomers"`
	LastUsedAt         *time.Time       `gorm:"type:timestamptz" json:"lastUsedAt,omitempty"`
	UpdatedAt          time.Time        `gorm:"default:now()" json:"updatedAt"`
}

func (PromotionPerformanceSummary) TableName() string {
	return "sales_analytics.promotion_performance_summary"
}

// CustomerPromotionUsage tracks per‑customer promotion usage for per‑user limits and cohort analysis.
type CustomerPromotionUsage struct {
	CompanyID     uuid.UUID       `gorm:"type:uuid;primaryKey" json:"companyId"`
	PromotionID   uuid.UUID       `gorm:"type:uuid;primaryKey" json:"promotionId"`
	CustomerID    uuid.UUID       `gorm:"type:uuid;primaryKey" json:"customerId"`
	UsageCount    int             `gorm:"not null;default:0" json:"usageCount"`
	TotalDiscount decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalDiscount"`
	FirstUsedAt   *time.Time      `gorm:"type:timestamptz" json:"firstUsedAt,omitempty"`
	LastUsedAt    *time.Time      `gorm:"type:timestamptz" json:"lastUsedAt,omitempty"`
}

func (CustomerPromotionUsage) TableName() string {
	return "sales_analytics.customer_promotion_usage"
}

// PromotionRedemptionRateDaily tracks daily redemption rates if total_available is known.
type PromotionRedemptionRateDaily struct {
	ID             int64            `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID      uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_promotion_redemption_rate_unique,priority:1" json:"companyId"`
	PromotionID    uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_promotion_redemption_rate_unique,priority:2" json:"promotionId"`
	Date           time.Time        `gorm:"type:date;not null;uniqueIndex:idx_promotion_redemption_rate_unique,priority:3" json:"date"`
	TotalAvailable *int             `gorm:"type:int" json:"totalAvailable,omitempty"`
	TimesUsed      int              `gorm:"not null;default:0" json:"timesUsed"`
	RedemptionRate *decimal.Decimal `gorm:"type:numeric(5,2)" json:"redemptionRate,omitempty"`
	UpdatedAt      time.Time        `gorm:"default:now()" json:"updatedAt"`
}

func (PromotionRedemptionRateDaily) TableName() string {
	return "sales_analytics.promotion_redemption_rate_daily"
}

// PromotionUniqueCustomer tracks lifetime unique customers per promotion.
type PromotionUniqueCustomer struct {
	CompanyID   uuid.UUID `gorm:"type:uuid;primaryKey"`
	PromotionID uuid.UUID `gorm:"type:uuid;primaryKey"`
	CustomerID  uuid.UUID `gorm:"type:uuid;primaryKey"`
}

func (PromotionUniqueCustomer) TableName() string {
	return "sales_analytics.promotion_unique_customers"
}
