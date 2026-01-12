package attendance

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceSource struct {
	SourceID      uuid.UUID  `json:"source_id" db:"source_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	SourceType    string     `json:"source_type" db:"source_type"`
	Name          string     `json:"name" db:"name"`
	ReferenceType *string    `json:"reference_type" db:"reference_type"`
	ReferenceID   *uuid.UUID `json:"reference_id" db:"reference_id"`
	IsActive      bool       `json:"is_active" db:"is_active"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	CreatedBy     *uuid.UUID `json:"created_by" db:"created_by"`
}
