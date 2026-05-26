package models

import (
	"time"

	"github.com/google/uuid"
)

type SalesRepCommissionAssignment struct {
	AssignmentID  uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CompanyID     uuid.UUID  `gorm:"type:uuid;not null;index"`
	SalesRepID    uuid.UUID  `gorm:"type:uuid;not null;index"`
	PlanID        uuid.UUID  `gorm:"type:uuid;not null"`
	EffectiveFrom time.Time  `gorm:"type:date;not null"`
	EffectiveTo   *time.Time `gorm:"type:date"`
	AssignedBy    *uuid.UUID
	CreatedAt     time.Time `gorm:"default:now()"`
}
