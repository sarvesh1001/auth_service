package models

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type RenewalPolicy struct {
	RenewalPolicyID uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"renewalPolicyId"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	Name            string          `gorm:"type:varchar(100);not null" json:"name"`
	AutoRenew       bool            `gorm:"not null;default:true" json:"autoRenew"`
	GraceDays       int             `gorm:"not null;default:0" json:"graceDays"`
	LateFeePercent  decimal.Decimal `gorm:"type:numeric(5,2);default:0" json:"lateFeePercent"`
	NoticeDays      int             `gorm:"not null;default:0" json:"noticeDays"`
	IsActive        bool            `gorm:"not null;default:true" json:"isActive"`
	CreatedAt       time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt       time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	DeletedAt       *time.Time      `gorm:"index" json:"deletedAt,omitempty"`
}
