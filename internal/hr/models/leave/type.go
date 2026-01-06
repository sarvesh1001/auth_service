package leave

import (
	"time"

	"github.com/google/uuid"
)

type LeaveType struct {
	LeaveTypeID      uuid.UUID `json:"leave_type_id" db:"leave_type_id"`
	CompanyID        uuid.UUID `json:"company_id" db:"company_id"`
	LeaveCode        string    `json:"leave_code" db:"leave_code"`
	Name             string    `json:"name" db:"name"`
	Category         string    `json:"category" db:"category"`
	IsStatutory      bool      `json:"is_statutory" db:"is_statutory"`
	AffectsPay       bool      `json:"affects_pay" db:"affects_pay"`
	RequiresApproval bool      `json:"requires_approval" db:"requires_approval"`
	RequiresDocument bool      `json:"requires_document" db:"requires_document"`
	AllowHalfDay     bool      `json:"allow_half_day" db:"allow_half_day"`
	AllowHourly      bool      `json:"allow_hourly" db:"allow_hourly"`
	IsActive         bool      `json:"is_active" db:"is_active"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}
