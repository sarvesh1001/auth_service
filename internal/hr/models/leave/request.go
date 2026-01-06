package leave

import (
	"time"

	"github.com/google/uuid"
)

type LeaveRequest struct {
	LeaveRequestID uuid.UUID `db:"leave_request_id"`
	CompanyID      uuid.UUID `db:"company_id"`
	UserID         uuid.UUID `db:"user_id"`
	LeaveTypeID    uuid.UUID `db:"leave_type_id"`
	StartDate      time.Time `db:"start_date"`
	EndDate        time.Time `db:"end_date"`
	Duration       float64   `db:"duration"`
	Reason         *string   `db:"reason"`
	Status         string    `db:"status"` // ENUM via constraint
	RequestedAt    time.Time `db:"requested_at"`
}

type LeaveApproval struct {
	ApprovalID     uuid.UUID `db:"approval_id"`
	LeaveRequestID uuid.UUID `db:"leave_request_id"`
	ApprovedBy     uuid.UUID `db:"approved_by"`
	Decision       string    `db:"decision"` // approved / rejected
	DecisionReason *string   `db:"decision_reason"`
	ApprovalLevel  int       `db:"approval_level"`
	DecidedAt      time.Time `db:"decided_at"`
}

const (
	LeavePending   = "pending"
	LeaveApproved  = "approved"
	LeaveRejected  = "rejected"
	LeaveCancelled = "cancelled"
	LeaveWithdrawn = "withdrawn"
)

type LeaveTransaction struct {
	TransactionID  uuid.UUID  `db:"transaction_id"`
	CompanyID      uuid.UUID  `db:"company_id"`
	UserID         uuid.UUID  `db:"user_id"`
	LeaveTypeID    uuid.UUID  `db:"leave_type_id"`
	LeaveRequestID *uuid.UUID `db:"leave_request_id"`
	ChangeAmount   float64    `db:"change_amount"` // + or -
	Reason         string     `db:"reason"`        // accrual | request | cancel | manual
	CreatedAt      time.Time  `db:"created_at"`
}

const (
	LeaveTxnAccrual = "accrual"
	LeaveTxnRequest = "request"
	LeaveTxnCancel  = "cancel"
	LeaveTxnManual  = "manual"
)
