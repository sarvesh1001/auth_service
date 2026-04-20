package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Return struct {
	ReturnID     uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"returnId"`
	CompanyID    uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	OrderID      uuid.UUID       `gorm:"type:uuid;not null" json:"orderId"`
	InvoiceID    *uuid.UUID      `gorm:"type:uuid" json:"invoiceId,omitempty"`
	CreditNoteID *uuid.UUID      `gorm:"type:uuid" json:"creditNoteId,omitempty"`
	ReturnNumber string          `gorm:"type:varchar(50);not null;uniqueIndex:idx_return_number" json:"returnNumber"`
	ReturnDate   time.Time       `gorm:"type:date;not null" json:"returnDate"`
	Reason       *string         `gorm:"type:text" json:"reason,omitempty"`
	Status       string          `gorm:"type:varchar(20);not null;default:'pending';check:status IN ('pending','approved','completed','rejected')" json:"status"`
	TotalRefund  decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalRefund"`
	ApprovedAt   *time.Time      `gorm:"type:timestamptz" json:"approvedAt,omitempty"`
	CompletedAt  *time.Time      `gorm:"type:timestamptz" json:"completedAt,omitempty"`
	CreatedAt    time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt    time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy    *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy    *uuid.UUID      `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
