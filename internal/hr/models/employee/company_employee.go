package employee

import (
	"time"

	"github.com/google/uuid"
)

type CompanyEmployee struct {
	CompanyID  uuid.UUID  `json:"company_id"`
	UserID     uuid.UUID  `json:"user_id"`
	EmployeeID string     `json:"employee_id"`
	RoleID     uuid.UUID  `json:"role_id"`
	HireDate   time.Time  `json:"hire_date"`
	IsActive   bool       `json:"is_active"`
	ReportsTo  *uuid.UUID `json:"reports_to,omitempty"`
	PositionID *uuid.UUID `json:"position_id,omitempty"`

	// PrimaryLocationID is the employee's HR-assigned home location
	// (company_employees.primary_location_id). Used by the calendar
	// resolution chain as the second step when no work center is set.
	//
	// Nil when the employee has no primary location assigned.
	PrimaryLocationID *uuid.UUID `json:"primary_location_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
