package models

import "github.com/google/uuid"

// EmployeeAssignment — one row from hr.employee_assignment_history,
// projected for a specific date.
type EmployeeAssignment struct {
	PositionID        *uuid.UUID `json:"position_id,omitempty"`
	PrimaryLocationID *uuid.UUID `json:"primary_location_id,omitempty"`
}

// PositionHistoryRow — one row from hr.position_history, projected for a date.
type PositionHistoryRow struct {
	PositionID     uuid.UUID  `json:"position_id"`
	WorkCenterCode *string    `json:"work_center_code,omitempty"`
	LocationID     *uuid.UUID `json:"location_id,omitempty"`
}
