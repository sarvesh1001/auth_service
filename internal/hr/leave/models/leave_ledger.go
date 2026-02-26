package models

import (
	"time"

	"github.com/google/uuid"
)

// LeaveLedger represents a ledger entry for leave
type LeaveLedger struct {
	LedgerID       uuid.UUID  `json:"ledger_id" db:"ledger_id"`
	EntitlementID  uuid.UUID  `json:"entitlement_id" db:"entitlement_id"`
	LeaveRequestID *uuid.UUID `json:"leave_request_id,omitempty" db:"leave_request_id"`
	EntryType      string     `json:"entry_type" db:"entry_type"`
	Days           int        `json:"days" db:"days"`
	EntryDate      time.Time  `json:"entry_date" db:"entry_date"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
}

// LeaveLedgerCreate represents data to create a ledger entry
type LeaveLedgerCreate struct {
	EntitlementID  uuid.UUID  `json:"entitlement_id"`
	LeaveRequestID *uuid.UUID `json:"leave_request_id,omitempty"`
	EntryType      string     `json:"entry_type"`
	Days           int        `json:"days"`
	EntryDate      time.Time  `json:"entry_date"`
}

// LeaveBalance represents current leave balance
type LeaveBalance struct {
	UserID        uuid.UUID `json:"user_id"`
	LeaveTypeID   uuid.UUID `json:"leave_type_id"`
	LeaveTypeCode string    `json:"leave_type_code"`
	LeaveTypeName string    `json:"leave_type_name"`

	TotalEntitled float64 `json:"total_entitled"` // was int
	Accrued       float64 `json:"accrued"`        // must be float64
	Consumed      float64 `json:"consumed"`       // must be float64
	Balance       float64 `json:"balance"`        // must be float64

	CarryForward *int `json:"carry_forward,omitempty"`
}

// LeaveTransaction represents a ledger transaction
type LeaveTransaction struct {
	TransactionID uuid.UUID  `json:"transaction_id"`
	UserID        uuid.UUID  `json:"user_id"`
	LeaveTypeID   uuid.UUID  `json:"leave_type_id"`
	EntryType     string     `json:"entry_type"`
	Days          int        `json:"days"`
	EntryDate     time.Time  `json:"entry_date"`
	ReferenceID   *uuid.UUID `json:"reference_id,omitempty"`
	ReferenceType *string    `json:"reference_type,omitempty"`
	Description   string     `json:"description"`
}

type LeavePolicyRuleUpdate struct {
	TotalDays         *int    `json:"total_days,omitempty"`
	AccrualMethod     *string `json:"accrual_method,omitempty"`
	CarryForwardLimit *int    `json:"carry_forward_limit,omitempty"`
}
