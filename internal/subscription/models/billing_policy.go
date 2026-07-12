package models

import (
	"time"

	"github.com/google/uuid"
)

type BillingPolicy struct {
	BillingPolicyID uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"billingPolicyId"`
	CompanyID       uuid.UUID  `gorm:"type:uuid;not null;index" json:"companyId"`
	Name            string     `gorm:"type:varchar(100);not null" json:"name"`
	FrequencyID     int16      `gorm:"type:smallint;not null" json:"frequencyId"` // references billing_frequency
	BillingInterval int        `gorm:"not null;default:1" json:"billingInterval"`
	ModelID         int16      `gorm:"type:smallint;not null" json:"modelId"` // references pricing_model
	AdvanceDays     int        `gorm:"not null;default:0" json:"advanceDays"`
	IsActive        bool       `gorm:"not null;default:true" json:"isActive"`
	CreatedAt       time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt       time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	DeletedAt       *time.Time `gorm:"index" json:"deletedAt,omitempty"`
}
