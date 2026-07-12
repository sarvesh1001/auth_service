package models

import (
	"time"

	"github.com/google/uuid"
)

type PausePolicy struct {
	PausePolicyID  uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"pausePolicyId"`
	CompanyID      uuid.UUID  `gorm:"type:uuid;not null;index" json:"companyId"`
	Name           string     `gorm:"type:varchar(100);not null" json:"name"`
	MaxPauseDays   int        `gorm:"not null;default:0" json:"maxPauseDays"`
	AllowedReasons []string   `gorm:"type:text[]" json:"allowedReasons"`
	FreezeDays     int        `gorm:"not null;default:0" json:"freezeDays"`
	IsActive       bool       `gorm:"not null;default:true" json:"isActive"`
	CreatedAt      time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt      time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	DeletedAt      *time.Time `gorm:"index" json:"deletedAt,omitempty"`
}
