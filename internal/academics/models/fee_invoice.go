package models

import (
	"time"

	"github.com/google/uuid"
)

type StudentFeeInvoice struct {
	InvoiceID      uuid.UUID  `json:"invoice_id"`
	StudentID      uuid.UUID  `json:"student_id"`
	FeeStructureID uuid.UUID  `json:"fee_structure_id"`
	InvoiceNo      string     `json:"invoice_no"`
	DueDate        time.Time  `json:"due_date"`
	TotalAmount    float64    `json:"total_amount"`
	PaidAmount     float64    `json:"paid_amount"`
	Balance        float64    `json:"balance"` // generated column
	Status         string     `json:"status"`  // unpaid, partial, paid, overdue, cancelled
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
}

type StudentFeeInvoiceItem struct {
	InvoiceItemID uuid.UUID  `json:"invoice_item_id"`
	InvoiceID     uuid.UUID  `json:"invoice_id"`
	FeeHead       string     `json:"fee_head"`
	Amount        float64    `json:"amount"`
	IsMandatory   bool       `json:"is_mandatory"`
	CreatedAt     time.Time  `json:"created_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
}
