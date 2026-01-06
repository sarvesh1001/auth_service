package attendance

import (
	"time"

	"github.com/google/uuid"
)

// EmployeeRFIDMapping maps RFID tags to employees
type EmployeeRFIDMapping struct {
	RFIDID       uuid.UUID  `json:"rfid_id" db:"rfid_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	RFIDTag      string     `json:"rfid_tag" db:"rfid_tag"`
	IsActive     bool       `json:"is_active" db:"is_active"`
	AssignedAt   time.Time  `json:"assigned_at" db:"assigned_at"`
	UnassignedAt *time.Time `json:"unassigned_at" db:"unassigned_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}
