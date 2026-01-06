package leave

import (
	"time"

	"github.com/google/uuid"
)

type LeaveBalance struct {
	CompanyID   uuid.UUID `json:"company_id" db:"company_id"`
	UserID      uuid.UUID `json:"user_id" db:"user_id"`
	LeaveTypeID uuid.UUID `json:"leave_type_id" db:"leave_type_id"`
	Balance     float64   `json:"balance" db:"balance"`
	AsOf        time.Time `json:"as_of" db:"as_of"`
	GeneratedAt time.Time `json:"generated_at" db:"generated_at"`
}
