package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// SalesRepTargetAchievement represents the sales_analytics.sales_rep_target_achievement table.
type SalesRepTargetAchievement struct {
	ID             int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID      uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_company_rep_period,priority:1" json:"companyId"`
	SalesRepID     uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_company_rep_period,priority:2" json:"salesRepId"`
	PeriodStart    time.Time       `gorm:"type:date;not null;uniqueIndex:idx_company_rep_period,priority:3" json:"periodStart"`
	PeriodEnd      time.Time       `gorm:"type:date;not null;uniqueIndex:idx_company_rep_period,priority:4" json:"periodEnd"`
	TargetAmount   decimal.Decimal `gorm:"type:numeric(14,2);not null" json:"targetAmount"`
	ActualRevenue  decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"actualRevenue"`
	AchievementPct decimal.Decimal `gorm:"->" json:"achievementPct"` // generated column
	Currency       string          `gorm:"type:varchar(3);not null;default:'USD'" json:"currency"`
	CreatedAt      time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt      time.Time       `gorm:"not null;default:now()" json:"updatedAt"`
}

func (SalesRepTargetAchievement) TableName() string {
	return "sales_analytics.sales_rep_target_achievement"
}

// SalesRepCommissionFact represents the sales_analytics.sales_rep_commission_fact table.
type SalesRepCommissionFact struct {
	ID               int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID        uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_company_entity,priority:1" json:"companyId"`
	SalesRepID       uuid.UUID       `gorm:"type:uuid;not null;index:idx_commission_fact_rep" json:"salesRepId"`
	EntityType       string          `gorm:"type:varchar(20);not null;uniqueIndex:idx_company_entity,priority:2" json:"entityType"` // 'order', 'invoice', 'payment'
	EntityID         uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_company_entity,priority:3" json:"entityId"`
	CommissionBase   decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"commissionBase"`
	CommissionRate   decimal.Decimal `gorm:"type:numeric(5,2);not null" json:"commissionRate"`
	CommissionAmount decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"commissionAmount"`
	EarnedAt         time.Time       `gorm:"type:timestamptz;not null;index:idx_commission_fact_earned" json:"earnedAt"`
	PaidAt           *time.Time      `gorm:"type:timestamptz;index:idx_commission_fact_paid" json:"paidAt,omitempty"`
	CreatedAt        time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}

func (SalesRepCommissionFact) TableName() string {
	return "sales_analytics.sales_rep_commission_fact"
}

// SalesRepLeaderboardSnapshot represents the sales_analytics.sales_rep_leaderboard_snapshot table.
type SalesRepLeaderboardSnapshot struct {
	ID           int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID    uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_company_snapshot_rep,priority:1" json:"companyId"`
	SnapshotDate time.Time       `gorm:"type:date;not null;uniqueIndex:idx_company_snapshot_rep,priority:2;index:idx_leaderboard_snapshot_company_date" json:"snapshotDate"`
	PeriodStart  time.Time       `gorm:"type:date;not null" json:"periodStart"`
	PeriodEnd    time.Time       `gorm:"type:date;not null" json:"periodEnd"`
	SalesRepID   uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_company_snapshot_rep,priority:3;index:idx_leaderboard_snapshot_rep" json:"salesRepId"`
	Rank         int             `gorm:"not null" json:"rank"`
	Revenue      decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"revenue"`
	OrdersCount  int             `gorm:"not null" json:"ordersCount"`
	AverageDeal  decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"averageDeal"`
	CreatedAt    time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}

func (SalesRepLeaderboardSnapshot) TableName() string {
	return "sales_analytics.sales_rep_leaderboard_snapshot"
}
