package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Benefit struct {
	BenefitID          uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	PlanItemID         uuid.UUID      `gorm:"type:uuid;not null;index"`
	BenefitType        string         `gorm:"size:50;not null;check:benefit_type IN ('discount','freebie','access','service','other')"`
	BenefitDescription *string        `gorm:"type:text"`
	Value              datatypes.JSON `gorm:"type:jsonb;not null"`
	CreatedAt          time.Time      `gorm:"not null;default:now()"`
	UpdatedAt          time.Time      `gorm:"not null;default:now()"`

	PlanItem PlanItem `gorm:"foreignKey:PlanItemID"`
}

func (Benefit) TableName() string { return "benefits" }
