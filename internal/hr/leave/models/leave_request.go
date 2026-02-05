package models

import (
	"time"

	"github.com/google/uuid"
)

// LeaveRequest represents a leave request
type LeaveRequest struct {
	LeaveRequestID uuid.UUID  `json:"leave_request_id" db:"leave_request_id"`
	CompanyID      uuid.UUID  `json:"company_id" db:"company_id"`
	UserID         uuid.UUID  `json:"user_id" db:"user_id"`
	LeaveTypeID    uuid.UUID  `json:"leave_type_id" db:"leave_type_id"`
	StartDate      time.Time  `json:"start_date" db:"start_date"`
	EndDate        time.Time  `json:"end_date" db:"end_date"`
	TotalDays      int        `json:"total_days" db:"total_days"`
	Status         string     `json:"status" db:"status"`
	RequestedBy    uuid.UUID  `json:"requested_by" db:"requested_by"`
	ApprovedBy     *uuid.UUID `json:"approved_by,omitempty" db:"approved_by"`
	RequestedAt    time.Time  `json:"requested_at" db:"requested_at"`
	ApprovedAt     *time.Time `json:"approved_at,omitempty" db:"approved_at"`
}

// LeaveRequestCreate represents data to create a leave request
type LeaveRequestCreate struct {
	CompanyID   uuid.UUID `json:"company_id"`
	UserID      uuid.UUID `json:"user_id"`
	LeaveTypeID uuid.UUID `json:"leave_type_id"`
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date"`
	TotalDays   int       `json:"total_days"`
	RequestedBy uuid.UUID `json:"requested_by"`
}

// LeaveRequestUpdate represents data to update a leave request
type LeaveRequestUpdate struct {
	Status     *string    `json:"status,omitempty"`
	ApprovedBy *uuid.UUID `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
}

// LeaveRequestFilter for searching leave requests
type LeaveRequestFilter struct {
	CompanyID   uuid.UUID  `json:"company_id"`
	UserID      *uuid.UUID `json:"user_id,omitempty"`
	LeaveTypeID *uuid.UUID `json:"leave_type_id,omitempty"`
	Status      *string    `json:"status,omitempty"`
	StartDate   *time.Time `json:"start_date,omitempty"`
	EndDate     *time.Time `json:"end_date,omitempty"`
	Page        int        `json:"page"`
	PageSize    int        `json:"page_size"`
}
