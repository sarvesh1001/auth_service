package models

import (
	"time"

	"github.com/google/uuid"
)

type CommissionPlan struct {
	PlanID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CompanyID     uuid.UUID  `gorm:"type:uuid;not null;index"`
	Code          string     `gorm:"type:varchar(50);not null;uniqueIndex:idx_plan_company_code"`
	Name          string     `gorm:"type:varchar(255);not null"`
	Description   *string    `gorm:"type:text"`
	EffectiveFrom time.Time  `gorm:"type:date;not null"`
	EffectiveTo   *time.Time `gorm:"type:date"`
	IsActive      bool       `gorm:"default:true"`
	CreatedAt     time.Time  `gorm:"default:now()"`
	UpdatedAt     time.Time  `gorm:"autoUpdateTime"`
	CreatedBy     *uuid.UUID
	UpdatedBy     *uuid.UUID
}
