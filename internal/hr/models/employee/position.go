package employee

import (
	"time"

	"github.com/google/uuid"
)

// Position is a "seat": one headcount slot at one location, holding one job.
//
// The definition of the role ("Cashier", "Line Operator") lives on the
// `jobs` table; this struct only carries what is specific to this seat:
//   - which job it implements
//   - which location it belongs to
//   - an optional title override (falls back to jobs.job_title)
//   - its work center (sub-area within the location) for attendance
type Position struct {
	PositionID     uuid.UUID  `json:"position_id"     db:"position_id"`
	CompanyID      uuid.UUID  `json:"company_id"      db:"company_id"`
	DepartmentID   uuid.UUID  `json:"department_id"   db:"department_id"`
	JobID          uuid.UUID  `json:"job_id"          db:"job_id"`
	LocationID     *uuid.UUID `json:"location_id"     db:"location_id"`
	TitleOverride  *string    `json:"title_override"  db:"title_override"`
	IsOpen         bool       `json:"is_open"         db:"is_open"`
	WorkCenterCode *string    `json:"work_center_code" db:"work_center_code"`
	CreatedAt      time.Time  `json:"created_at"      db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"      db:"updated_at"`
}

// PositionView is the read model for anything that needs the joined
// job title + attendance flags + human-readable names.
//
// EffectiveTitle returns title_override when set, else job_title.
type PositionView struct {
	Position
	JobCode            string  `json:"job_code"            db:"job_code"`
	JobTitle           string  `json:"job_title"           db:"job_title"`
	IsSchedulable      bool    `json:"is_schedulable"      db:"is_schedulable"`
	AttendanceRequired bool    `json:"attendance_required" db:"attendance_required"`
	OvertimeAllowed    bool    `json:"overtime_allowed"    db:"overtime_allowed"`
	DepartmentName     *string `json:"department_name"     db:"department_name"`
	LocationName       *string `json:"location_name"       db:"location_name"`
	WorkCenterName     *string `json:"work_center_name"    db:"work_center_name"`
}

func (p *PositionView) EffectiveTitle() string {
	if p.TitleOverride != nil && *p.TitleOverride != "" {
		return *p.TitleOverride
	}
	return p.JobTitle
}
