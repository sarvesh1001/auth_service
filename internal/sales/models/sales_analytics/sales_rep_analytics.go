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
// Updated with plan_id and rule_id columns.
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
	PlanID           *uuid.UUID      `gorm:"type:uuid;index:idx_commission_fact_plan" json:"planId,omitempty"`
	RuleID           *uuid.UUID      `gorm:"type:uuid;index:idx_commission_fact_rule" json:"ruleId,omitempty"`
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

// CommissionPlanDaily represents the sales_analytics.commission_plan_daily table.
type CommissionPlanDaily struct {
	ID                     int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID              uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_commission_plan_daily_company_plan_date,priority:1" json:"companyId"`
	PlanID                 uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_commission_plan_daily_company_plan_date,priority:2" json:"planId"`
	Date                   time.Time       `gorm:"type:date;not null;uniqueIndex:idx_commission_plan_daily_company_plan_date,priority:3" json:"date"`
	TotalCommissionsEarned decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalCommissionsEarned"`
	TotalCommissionsPaid   decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalCommissionsPaid"`
	CommissionCount        int             `gorm:"not null;default:0" json:"commissionCount"`
	AverageRate            decimal.Decimal `gorm:"type:numeric(10,2);not null;default:0" json:"averageRate"`
	UniqueSalesReps        int             `gorm:"not null;default:0" json:"uniqueSalesReps"`
	UpdatedAt              time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (CommissionPlanDaily) TableName() string {
	return "sales_analytics.commission_plan_daily"
}

// CommissionRuleFact represents the sales_analytics.commission_rule_fact table.
type CommissionRuleFact struct {
	ID                    int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID             uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_commission_rule_fact_company_rule_date,priority:1" json:"companyId"`
	RuleID                uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_commission_rule_fact_company_rule_date,priority:2" json:"ruleId"`
	PlanID                uuid.UUID       `gorm:"type:uuid;not null;index:idx_commission_rule_fact_plan" json:"planId"`
	Date                  time.Time       `gorm:"type:date;not null;uniqueIndex:idx_commission_rule_fact_company_rule_date,priority:3" json:"date"`
	TimesApplied          int             `gorm:"not null;default:0" json:"timesApplied"`
	TotalCommissionBase   decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalCommissionBase"`
	TotalCommissionAmount decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalCommissionAmount"`
	AvgRate               decimal.Decimal `gorm:"type:numeric(10,2);not null;default:0" json:"avgRate"`
	UpdatedAt             time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (CommissionRuleFact) TableName() string {
	return "sales_analytics.commission_rule_fact"
}

// CommissionAssignmentFact represents the sales_analytics.commission_assignment_fact table.
type CommissionAssignmentFact struct {
	ID           int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID    uuid.UUID  `gorm:"type:uuid;not null;index:idx_assignment_fact_company" json:"companyId"`
	SalesRepID   uuid.UUID  `gorm:"type:uuid;not null;index:idx_assignment_fact_rep" json:"salesRepId"`
	PlanID       uuid.UUID  `gorm:"type:uuid;not null;index:idx_assignment_fact_plan" json:"planId"`
	AssignedAt   time.Time  `gorm:"type:date;not null" json:"assignedAt"`
	RemovedAt    *time.Time `gorm:"type:date" json:"removedAt,omitempty"`
	DurationDays int        `gorm:"->" json:"durationDays"` // generated column
	AssignedBy   *uuid.UUID `gorm:"type:uuid" json:"assignedBy,omitempty"`
	CreatedAt    time.Time  `gorm:"default:now()" json:"createdAt"`
}

func (CommissionAssignmentFact) TableName() string {
	return "sales_analytics.commission_assignment_fact"
}

// CommissionLifecycle represents the sales_analytics.commission_lifecycle table.
type CommissionLifecycle struct {
	CommissionID       uuid.UUID  `gorm:"type:uuid;primaryKey" json:"commissionId"`
	CompanyID          uuid.UUID  `gorm:"type:uuid;not null;index" json:"companyId"`
	SalesRepID         uuid.UUID  `gorm:"type:uuid;not null;index" json:"salesRepId"`
	ReferenceType      string     `gorm:"type:varchar(20);not null" json:"referenceType"`
	ReferenceID        uuid.UUID  `gorm:"type:uuid;not null" json:"referenceId"`
	EarnedAt           time.Time  `gorm:"type:timestamptz;not null" json:"earnedAt"`
	ApprovedAt         *time.Time `gorm:"type:timestamptz" json:"approvedAt,omitempty"`
	PaidAt             *time.Time `gorm:"type:timestamptz" json:"paidAt,omitempty"`
	RejectedAt         *time.Time `gorm:"type:timestamptz" json:"rejectedAt,omitempty"`
	ApprovalDelayHours *float64   `gorm:"->" json:"approvalDelayHours,omitempty"` // generated column
	PaymentDelayHours  *float64   `gorm:"->" json:"paymentDelayHours,omitempty"`  // generated column
	CurrentStatus      string     `gorm:"type:varchar(20);not null;index:idx_commission_lifecycle_status" json:"currentStatus"`
	UpdatedAt          time.Time  `gorm:"default:now()" json:"updatedAt"`
}

func (CommissionLifecycle) TableName() string {
	return "sales_analytics.commission_lifecycle"
}

// CommissionForecastSnapshot represents the sales_analytics.commission_forecast_snapshot table.
type CommissionForecastSnapshot struct {
	ID                                 int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID                          uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_commission_forecast_company_date_rep,priority:1" json:"companyId"`
	SnapshotDate                       time.Time       `gorm:"type:date;not null;uniqueIndex:idx_commission_forecast_company_date_rep,priority:2" json:"snapshotDate"`
	SalesRepID                         uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_commission_forecast_company_date_rep,priority:3;index:idx_commission_forecast_rep" json:"salesRepId"`
	ExpectedCommissionFromOpenOrders   decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"expectedCommissionFromOpenOrders"`
	ExpectedCommissionFromOpenInvoices decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"expectedCommissionFromOpenInvoices"`
	TotalExpectedCommission            decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalExpectedCommission"`
	CreatedAt                          time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (CommissionForecastSnapshot) TableName() string {
	return "sales_analytics.commission_forecast_snapshot"
}
