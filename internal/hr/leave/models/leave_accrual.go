package models

import (
	"time"

	"github.com/google/uuid"
)

// LeaveAccrual represents leave accrual entry
type LeaveAccrual struct {
	AccrualID     uuid.UUID `json:"accrual_id" db:"accrual_id"`
	EntitlementID uuid.UUID `json:"entitlement_id" db:"entitlement_id"`
	AccrualDate   time.Time `json:"accrual_date" db:"accrual_date"`
	DaysAccrued   int       `json:"days_accrued" db:"days_accrued"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// LeaveAccrualCreate represents data to create a leave accrual
type LeaveAccrualCreate struct {
	EntitlementID uuid.UUID `json:"entitlement_id"`
	AccrualDate   time.Time `json:"accrual_date"`
	DaysAccrued   int       `json:"days_accrued"`
}

// AccrualSchedule defines when accruals should happen
type AccrualSchedule struct {
	CompanyID     uuid.UUID `json:"company_id"`
	LeaveTypeID   uuid.UUID `json:"leave_type_id"`
	UserID        uuid.UUID `json:"user_id"`
	EntitlementID uuid.UUID `json:"entitlement_id"`
	AccrualDate   time.Time `json:"accrual_date"`
	DaysToAccrue  int       `json:"days_to_accrue"`
}
