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
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
