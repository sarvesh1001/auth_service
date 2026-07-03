package models

import (
	"time"

	"github.com/google/uuid"
)

type OffRequest struct {
	OffRequestID uuid.UUID  `json:"off_request_id" db:"off_request_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	RequestDates []string   `json:"request_dates" db:"request_dates"` // DATE[] as strings
	Status       string     `json:"status" db:"status"`
	RequestedBy  *uuid.UUID `json:"requested_by,omitempty" db:"requested_by"`
	ApprovedBy   *uuid.UUID `json:"approved_by,omitempty" db:"approved_by"`
	ApprovedAt   *time.Time `json:"approved_at,omitempty" db:"approved_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}
