package models

// models/credit_note.go

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type CreditNote struct {
	CreditNoteID     uuid.UUID              `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"creditNoteId"`
	CompanyID        uuid.UUID              `gorm:"type:uuid;not null;index" json:"companyId"`
	CustomerID       uuid.UUID              `gorm:"type:uuid;not null;index" json:"customerId"`
	CreditNoteNumber string                 `gorm:"type:varchar(50);not null;uniqueIndex" json:"creditNoteNumber"`
	InvoiceID        *uuid.UUID             `gorm:"type:uuid;index" json:"invoiceId,omitempty"` // original invoice (if any)
	ReturnID         *uuid.UUID             `gorm:"type:uuid;index" json:"returnId,omitempty"`  // linked return (if any)
	IssueDate        time.Time              `gorm:"type:date;not null" json:"issueDate"`
	Status           enums.CreditNoteStatus `gorm:"type:varchar(20);not null;default:'draft'" json:"status"`
	Currency         string                 `gorm:"type:varchar(3);not null;default:'USD'" json:"currency"`
	Subtotal         decimal.Decimal        `gorm:"type:numeric(14,4);not null" json:"subtotal"`
	TaxTotal         decimal.Decimal        `gorm:"type:numeric(14,4);not null" json:"taxTotal"`
	TotalAmount      decimal.Decimal        `gorm:"type:numeric(14,4);not null" json:"totalAmount"` // negative or positive? usually negative
	AmountApplied    decimal.Decimal        `gorm:"type:numeric(14,4);not null;default:0" json:"amountApplied"`
	RemainingAmount  decimal.Decimal        `gorm:"->;type:numeric(14,4)" json:"remainingAmount"`
	Reason           *string                `gorm:"type:text" json:"reason,omitempty"`
	Notes            *string                `gorm:"type:text" json:"notes,omitempty"`
	IssuedAt         *time.Time             `gorm:"type:timestamptz" json:"issuedAt,omitempty"`
	VoidedAt         *time.Time             `gorm:"type:timestamptz" json:"voidedAt,omitempty"`
	VoidReason       *string                `gorm:"type:text" json:"voidReason,omitempty"`
	CreatedAt        time.Time              `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt        time.Time              `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy        *uuid.UUID             `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy        *uuid.UUID             `gorm:"type:uuid" json:"updatedBy,omitempty"`
}

// models/credit_note_item.go
type CreditNoteItem struct {
	CreditNoteItemID    uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"creditNoteItemId"`
	CreditNoteID        uuid.UUID        `gorm:"type:uuid;not null;index" json:"creditNoteId"`
	InvoiceItemID       *uuid.UUID       `gorm:"type:uuid" json:"invoiceItemId,omitempty"`
	ProductID           *uuid.UUID       `gorm:"type:uuid;index" json:"productId,omitempty"`
	ProductNameSnapshot string           `gorm:"type:varchar(255);not null" json:"productNameSnapshot"`
	Quantity            decimal.Decimal  `gorm:"type:numeric(14,4);not null;check:quantity > 0" json:"quantity"`
	UnitPrice           decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"unitPrice"`
	TaxRate             *decimal.Decimal `gorm:"type:numeric(5,2)" json:"taxRate,omitempty"`
	TaxAmount           decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"taxAmount"`
	LineAmount          decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"lineAmount"`
	CreatedAt           time.Time        `gorm:"not null;default:now()" json:"createdAt"`
	CreatedBy           *uuid.UUID       `gorm:"type:uuid" json:"createdBy,omitempty"`
}

// models/credit_note_application.go
type CreditNoteApplication struct {
	ApplicationID uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"applicationId"`
	CreditNoteID  uuid.UUID       `gorm:"type:uuid;not null;index" json:"creditNoteId"`
	InvoiceID     uuid.UUID       `gorm:"type:uuid;not null;index" json:"invoiceId"`
	Amount        decimal.Decimal `gorm:"type:numeric(14,4);not null;check:amount > 0" json:"amount"`
	AppliedAt     time.Time       `gorm:"type:timestamptz;not null;default:now()" json:"appliedAt"`
	AppliedBy     *uuid.UUID      `gorm:"type:uuid" json:"appliedBy,omitempty"`
	CreatedAt     time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}
