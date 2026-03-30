package models

import (
	"time"

	"github.com/google/uuid"
)

type LibraryFine struct {
	FineID      uuid.UUID  `json:"fine_id"`
	IssueID     uuid.UUID  `json:"issue_id"`
	FineAmount  float64    `json:"fine_amount"`
	Paid        bool       `json:"paid"`
	PaidDate    *time.Time `json:"paid_date,omitempty"`
	PaymentMode string     `json:"payment_mode,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}
