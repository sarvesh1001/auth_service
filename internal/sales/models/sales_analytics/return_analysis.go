package sales_analytics

import (
	"time"

	"auth-service/internal/sales/models/enums"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// DailyReturnMetrics aggregates return statistics per day per company.
type DailyReturnMetrics struct {
	ID                    int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID             uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_daily_return_metrics_unique,priority:1" json:"companyId"`
	Date                  time.Time       `gorm:"type:date;not null;uniqueIndex:idx_daily_return_metrics_unique,priority:2" json:"date"`
	TotalReturnsRequested int             `gorm:"default:0" json:"totalReturnsRequested"`
	TotalReturnsApproved  int             `gorm:"default:0" json:"totalReturnsApproved"`
	TotalReturnsCompleted int             `gorm:"default:0" json:"totalReturnsCompleted"`
	TotalReturnsRejected  int             `gorm:"default:0" json:"totalReturnsRejected"`
	TotalRefundAmount     decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalRefundAmount"`
	TotalCreditNoteAmount decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalCreditNoteAmount"`
	UniqueCustomers       int             `gorm:"default:0" json:"uniqueCustomers"`
	UpdatedAt             time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (DailyReturnMetrics) TableName() string {
	return "sales_analytics.daily_return_metrics"
}

// ReturnReasonFact stores reason details for each return item.
type ReturnReasonFact struct {
	ID               int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID        uuid.UUID       `gorm:"type:uuid;not null;index:idx_return_reason_fact_company_date,priority:1" json:"companyId"`
	ReturnID         uuid.UUID       `gorm:"type:uuid;not null" json:"returnId"`
	ReturnItemID     uuid.UUID       `gorm:"type:uuid;not null" json:"returnItemId"`
	ReasonCode       *string         `gorm:"type:varchar(100);index" json:"reasonCode,omitempty"`
	ReasonText       *string         `gorm:"type:text" json:"reasonText,omitempty"`
	ProductID        *uuid.UUID      `gorm:"type:uuid" json:"productId,omitempty"`
	QuantityReturned decimal.Decimal `gorm:"type:numeric(14,4)" json:"quantityReturned"`
	RefundAmount     decimal.Decimal `gorm:"type:numeric(14,4)" json:"refundAmount"`
	ReturnDate       time.Time       `gorm:"type:date;not null;index:idx_return_reason_fact_company_date,priority:2" json:"returnDate"`
	CreatedAt        time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (ReturnReasonFact) TableName() string {
	return "sales_analytics.return_reason_fact"
}

// ReturnProcessingTimeFact tracks time spent in each return status.
type ReturnProcessingTimeFact struct {
	ID              int64              `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID       uuid.UUID          `gorm:"type:uuid;not null" json:"companyId"`
	ReturnID        uuid.UUID          `gorm:"type:uuid;not null;index" json:"returnId"`
	Status          enums.ReturnStatus `gorm:"type:sales.return_status;not null;index" json:"status"`
	EnteredAt       time.Time          `gorm:"type:timestamptz;not null" json:"enteredAt"`
	ExitedAt        *time.Time         `gorm:"type:timestamptz" json:"exitedAt,omitempty"`
	DurationSeconds int64              `gorm:"->" json:"durationSeconds"`
	CreatedAt       time.Time          `gorm:"default:now()" json:"createdAt"`
}

func (ReturnProcessingTimeFact) TableName() string {
	return "sales_analytics.return_processing_time_fact"
}

// CreditNoteFact stores facts about credit notes issued against returns.
type CreditNoteFact struct {
	ID                 int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID          uuid.UUID       `gorm:"type:uuid;not null;index:idx_credit_note_fact_company_date,priority:1" json:"companyId"`
	CreditNoteID       uuid.UUID       `gorm:"type:uuid;not null" json:"creditNoteId"`
	ReturnID           *uuid.UUID      `gorm:"type:uuid;index" json:"returnId,omitempty"`
	IssuedDate         time.Time       `gorm:"type:date;not null;index:idx_credit_note_fact_company_date,priority:2" json:"issuedDate"`
	IssuedAmount       decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"issuedAmount"`
	AppliedAmount      decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"appliedAmount"`
	AppliedToInvoiceID *uuid.UUID      `gorm:"type:uuid" json:"appliedToInvoiceId,omitempty"`
	AppliedDate        *time.Time      `gorm:"type:date" json:"appliedDate,omitempty"`
	Status             string          `gorm:"type:varchar(20);default:'issued'" json:"status"`
	CreatedAt          time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (CreditNoteFact) TableName() string {
	return "sales_analytics.credit_note_fact"
}

// RefundFact stores facts about monetary refunds issued for returns.
type RefundFact struct {
	ID           int64                `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID    uuid.UUID            `gorm:"type:uuid;not null;index:idx_refund_fact_company_date,priority:1" json:"companyId"`
	RefundID     uuid.UUID            `gorm:"type:uuid;not null" json:"refundId"`
	ReturnID     uuid.UUID            `gorm:"type:uuid;not null;index" json:"returnId"`
	PaymentID    uuid.UUID            `gorm:"type:uuid;not null" json:"paymentId"`
	Amount       decimal.Decimal      `gorm:"type:numeric(14,4);not null" json:"amount"`
	RefundDate   time.Time            `gorm:"type:date;not null;index:idx_refund_fact_company_date,priority:2" json:"refundDate"`
	RefundMethod *enums.PaymentMethod `gorm:"type:sales.payment_method" json:"refundMethod,omitempty"`
	Status       *string              `gorm:"type:varchar(20)" json:"status,omitempty"`
	CreatedAt    time.Time            `gorm:"default:now()" json:"createdAt"`
}

func (RefundFact) TableName() string {
	return "sales_analytics.refund_fact"
}

// ReturnProductCategoryFact aggregates returns by product category.
type ReturnProductCategoryFact struct {
	ID               int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID        uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	CategoryID       *uuid.UUID      `gorm:"type:uuid" json:"categoryId,omitempty"`
	CategoryName     *string         `gorm:"type:varchar(255)" json:"categoryName,omitempty"`
	ReturnDate       time.Time       `gorm:"type:date;not null" json:"returnDate"`
	QuantityReturned decimal.Decimal `gorm:"type:numeric(14,4)" json:"quantityReturned"`
	RefundAmount     decimal.Decimal `gorm:"type:numeric(14,4)" json:"refundAmount"`
	UniqueReturns    int             `gorm:"default:0" json:"uniqueReturns"`
	CreatedAt        time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (ReturnProductCategoryFact) TableName() string {
	return "sales_analytics.return_product_category_fact"
}

// DailyReturnUniqueCustomer tracks unique customers who made returns per day.
type DailyReturnUniqueCustomer struct {
	CompanyID  uuid.UUID `gorm:"type:uuid;not null;primaryKey" json:"companyId"`
	Date       time.Time `gorm:"type:date;not null;primaryKey" json:"date"`
	CustomerID uuid.UUID `gorm:"type:uuid;not null;primaryKey" json:"customerId"`
}

func (DailyReturnUniqueCustomer) TableName() string {
	return "sales_analytics.daily_return_unique_customers"
}
