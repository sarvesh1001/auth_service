package employee

import (
	"time"

	"github.com/google/uuid"
)

type EmployeeDepartmentHistory struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	DepartmentID uuid.UUID  `json:"department_id" db:"department_id"`
	StartDate    time.Time  `json:"start_date" db:"start_date"`
	EndDate      *time.Time `json:"end_date" db:"end_date"`
	ChangeReason *string    `json:"change_reason" db:"change_reason"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}
