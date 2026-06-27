package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RenewalPolicy struct {
	RenewalPolicyID uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID       uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name            string         `gorm:"size:100;not null"`
	AutoRenew       bool           `gorm:"not null;default:true"`
	GraceDays       int            `gorm:"not null;default:0"`
	LateFeePercent  float64        `gorm:"type:numeric(5,2);default:0"`
	NoticeDays      int            `gorm:"not null;default:0"`
	IsActive        bool           `gorm:"not null;default:true"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`

	Company Company `gorm:"foreignKey:CompanyID"`
}

func (RenewalPolicy) TableName() string { return "renewal_policies" }
