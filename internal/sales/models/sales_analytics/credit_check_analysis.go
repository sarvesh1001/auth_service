package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// CreditCheckFact represents each credit eligibility check performed.
type CreditCheckFact struct {
	ID                 int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID          uuid.UUID       `gorm:"type:uuid;not null;index:idx_credit_check_fact_company_date,priority:1;index:idx_credit_check_fact_company" json:"companyId"`
	CustomerID         uuid.UUID       `gorm:"type:uuid;not null;index:idx_credit_check_fact_customer" json:"customerId"`
	CheckID            *uuid.UUID      `gorm:"type:uuid;index" json:"checkId,omitempty"`                                   // optional reference to credit_check_history
	CheckType          string          `gorm:"type:varchar(20);not null" json:"checkType"`                                 // customer_limit, order_eligibility, invoice_eligibility
	Result             string          `gorm:"type:varchar(20);not null;index:idx_credit_check_fact_result" json:"result"` // approved, denied, suspended
	RequestedAmount    decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"requestedAmount"`
	CurrentLimit       decimal.Decimal `gorm:"type:numeric(14,2);not null" json:"currentLimit"`
	CurrentOutstanding decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"currentOutstanding"`
	AvailableCredit    decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"availableCredit"`
	Reason             *string         `gorm:"type:text" json:"reason,omitempty"`
	CheckedAt          time.Time       `gorm:"type:timestamptz;not null;index:idx_credit_check_fact_company_date,priority:2" json:"checkedAt"`
	CreatedAt          time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (CreditCheckFact) TableName() string {
	return "sales_analytics.credit_check_fact"
}

// DailyCreditMetrics holds aggregated credit metrics per company per day.
type DailyCreditMetrics struct {
	ID                       int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID                uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_daily_credit_metrics_company_date,priority:1" json:"companyId"`
	Date                     time.Time       `gorm:"type:date;not null;uniqueIndex:idx_daily_credit_metrics_company_date,priority:2" json:"date"`
	TotalChecks              int             `gorm:"default:0" json:"totalChecks"`
	ChecksPassed             int             `gorm:"default:0" json:"checksPassed"`
	ChecksFailed             int             `gorm:"default:0" json:"checksFailed"`
	TotalOrderValueChecked   decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalOrderValueChecked"`
	TotalInvoiceValueChecked decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalInvoiceValueChecked"`
	AvgAvailableCredit       decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"avgAvailableCredit"`
	AvgCreditUtilization     decimal.Decimal `gorm:"type:numeric(5,2);default:0" json:"avgCreditUtilization"` // percentage
	UpdatedAt                time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (DailyCreditMetrics) TableName() string {
	return "sales_analytics.daily_credit_metrics"
}

// CreditHoldFact tracks when orders are placed on credit hold and when they are released.
type CreditHoldFact struct {
	ID              int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	OrderID         uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex:idx_credit_hold_fact_order_hold,priority:1" json:"orderId"`
	CompanyID       uuid.UUID  `gorm:"type:uuid;not null;index:idx_credit_hold_fact_company_date,priority:1;index:idx_credit_hold_fact_company" json:"companyId"`
	CustomerID      uuid.UUID  `gorm:"type:uuid;not null;index:idx_credit_hold_fact_customer" json:"customerId"`
	HoldStartedAt   time.Time  `gorm:"type:timestamptz;not null;uniqueIndex:idx_credit_hold_fact_order_hold,priority:2;index:idx_credit_hold_fact_company_date,priority:2" json:"holdStartedAt"`
	HoldEndedAt     *time.Time `gorm:"type:timestamptz" json:"holdEndedAt,omitempty"`
	DurationSeconds *int64     `gorm:"->" json:"durationSeconds,omitempty"` // computed
	Reason          *string    `gorm:"type:text" json:"reason,omitempty"`
	CreatedAt       time.Time  `gorm:"default:now()" json:"createdAt"`
}

func (CreditHoldFact) TableName() string {
	return "sales_analytics.credit_hold_fact"
}

// CreditLimitChangeFact records detailed history of credit limit adjustments.
type CreditLimitChangeFact struct {
	ID            int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID     uuid.UUID       `gorm:"type:uuid;not null;index:idx_credit_limit_change_company,priority:1;index:idx_credit_limit_change_company_date" json:"companyId"`
	CustomerID    uuid.UUID       `gorm:"type:uuid;not null;index:idx_credit_limit_change_customer" json:"customerId"`
	PreviousLimit decimal.Decimal `gorm:"type:numeric(14,2);not null" json:"previousLimit"`
	NewLimit      decimal.Decimal `gorm:"type:numeric(14,2);not null" json:"newLimit"`
	ChangeAmount  decimal.Decimal `gorm:"->" json:"changeAmount"` // computed
	ChangeReason  *string         `gorm:"type:text" json:"changeReason,omitempty"`
	ChangedBy     *uuid.UUID      `gorm:"type:uuid" json:"changedBy,omitempty"`
	ChangedAt     time.Time       `gorm:"type:timestamptz;not null;index:idx_credit_limit_change_company,priority:2" json:"changedAt"`
	CreatedAt     time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (CreditLimitChangeFact) TableName() string {
	return "sales_analytics.credit_limit_change_fact"
}

// CustomerCreditDailySnapshot provides a point-in-time view of each customer’s credit situation.
type CustomerCreditDailySnapshot struct {
	SnapshotID         int64           `gorm:"primaryKey;autoIncrement" json:"snapshotId"`
	CompanyID          uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_customer_credit_snapshot_unique,priority:1;index:idx_customer_credit_snapshot_company_date" json:"companyId"`
	CustomerID         uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_customer_credit_snapshot_unique,priority:2;index:idx_customer_credit_snapshot_customer" json:"customerId"`
	SnapshotDate       time.Time       `gorm:"type:date;not null;uniqueIndex:idx_customer_credit_snapshot_unique,priority:3;index:idx_customer_credit_snapshot_company_date,priority:2" json:"snapshotDate"`
	CreditLimit        decimal.Decimal `gorm:"type:numeric(14,2);not null" json:"creditLimit"`
	OutstandingBalance decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"outstandingBalance"`
	AvailableCredit    decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"availableCredit"`
	UtilizationPct     decimal.Decimal `gorm:"->" json:"utilizationPct"` // computed
	IsSuspended        bool            `gorm:"default:false" json:"isSuspended"`
	CreatedAt          time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (CustomerCreditDailySnapshot) TableName() string {
	return "sales_analytics.customer_credit_daily_snapshot"
}

// CurrentCustomerCredit is a materialized view reflecting real-time credit status per customer.
type CurrentCustomerCredit struct {
	CustomerID         uuid.UUID       `gorm:"type:uuid;primaryKey;index:idx_current_credit_customer" json:"customerId"`
	CompanyID          uuid.UUID       `gorm:"type:uuid;not null;index:idx_current_credit_company" json:"companyId"`
	CreditLimit        decimal.Decimal `gorm:"type:numeric(14,2);not null" json:"creditLimit"`
	OutstandingBalance decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"outstandingBalance"`
	AvailableCredit    decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"availableCredit"`
	UtilizationPct     decimal.Decimal `gorm:"type:numeric(5,2)" json:"utilizationPct"` // computed in view
	IsSuspended        bool            `json:"isSuspended"`
}

func (CurrentCustomerCredit) TableName() string {
	return "sales_analytics.current_customer_credit"
}
