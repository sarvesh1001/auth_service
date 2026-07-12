package models

import (
	"time"
	"github.com/google/uuid"
	"auth-service/internal/subscription/models/enums"
)

type Benefit struct {
	BenefitID          uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"benefitId"`
	PlanItemID         uuid.UUID          `gorm:"type:uuid;not null;index" json:"planItemId"`
	BenefitType        enums.BenefitType  `gorm:"type:varchar(50);not null" json:"benefitType"`
	BenefitDescription *string            `gorm:"type:text" json:"benefitDescription,omitempty"`
	Value              JSONB              `gorm:"type:jsonb;not null" json:"value"`
	CreatedAt          time.Time          `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt          time.Time          `gorm:"autoUpdateTime" json:"updatedAt"`
}
