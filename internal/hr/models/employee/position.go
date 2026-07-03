package employee

import (
	"time"

	"github.com/google/uuid"
)

type Position struct {
	PositionID         uuid.UUID `json:"position_id" db:"position_id"`
	CompanyID          uuid.UUID `json:"company_id" db:"company_id"`
	DepartmentID       uuid.UUID `json:"department_id" db:"department_id"`
	Title              *string   `json:"title" db:"title"`
	IsOpen             bool      `json:"is_open" db:"is_open"`
	IsSchedulable      bool      `json:"is_schedulable" db:"is_schedulable"`
	AttendanceRequired bool      `json:"attendance_required" db:"attendance_required"`
	OvertimeAllowed    bool      `json:"overtime_allowed" db:"overtime_allowed"`
	WorkCenterCode     *string   `json:"work_center_code" db:"work_center_code"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}
