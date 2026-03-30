package models

import (
	"time"

	"github.com/google/uuid"
)

type StudentFeePayment struct {
	PaymentID     uuid.UUID  `json:"payment_id"`
	InvoiceID     uuid.UUID  `json:"invoice_id"`
	PaymentDate   time.Time  `json:"payment_date"`
	Amount        float64    `json:"amount"`
	PaymentMode   string     `json:"payment_mode"` // cash, cheque, online, bank_transfer, card, other
	TransactionID string     `json:"transaction_id,omitempty"`
	ReceiptNo     string     `json:"receipt_no,omitempty"`
	Remarks       string     `json:"remarks,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
}

type FeeDiscount struct {
	DiscountID    uuid.UUID  `json:"discount_id"`
	StudentID     uuid.UUID  `json:"student_id"`
	DiscountType  string     `json:"discount_type"` // percentage, fixed
	DiscountValue float64    `json:"discount_value"`
	Reason        string     `json:"reason,omitempty"`
	ApprovedBy    *uuid.UUID `json:"approved_by,omitempty"`
	ValidFrom     *time.Time `json:"valid_from,omitempty"`
	ValidUntil    *time.Time `json:"valid_until,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
}

type FeePenalty struct {
	PenaltyID   uuid.UUID  `json:"penalty_id"`
	InvoiceID   uuid.UUID  `json:"invoice_id"`
	PenaltyDate time.Time  `json:"penalty_date"`
	Amount      float64    `json:"amount"`
	Reason      string     `json:"reason,omitempty"`
	Waived      bool       `json:"waived"`
	WaivedBy    *uuid.UUID `json:"waived_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

type FeeReceipt struct {
	ReceiptID   uuid.UUID              `json:"receipt_id"`
	PaymentID   uuid.UUID              `json:"payment_id"`
	ReceiptNo   string                 `json:"receipt_no"`
	ReceiptData map[string]interface{} `json:"receipt_data"` // JSONB
	GeneratedAt time.Time              `json:"generated_at"`
	CreatedAt   time.Time              `json:"created_at"`
	CreatedBy   *uuid.UUID             `json:"created_by,omitempty"`
}
