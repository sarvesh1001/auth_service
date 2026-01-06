package employee

import (
	"time"

	"github.com/google/uuid"
)

type EmployeeRoleHistory struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	RoleID    uuid.UUID  `json:"role_id" db:"role_id"`
	StartDate *time.Time `json:"start_date" db:"start_date"`
	EndDate   *time.Time `json:"end_date" db:"end_date"`
	Reason    *string    `json:"reason" db:"reason"`
}
