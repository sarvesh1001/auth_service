package models

import (
	"time"
	"github.com/google/uuid"
	"auth-service/internal/subscription/models/enums"
)

type ProrationPolicy struct {
	ProrationPolicyID uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"prorationPolicyId"`
	CompanyID         uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	Name              string          `gorm:"type:varchar(100);not null" json:"name"`
	UpgradeType       enums.UpgradeType   `gorm:"type:varchar(20);not null" json:"upgradeType"`
	DowngradeType     enums.DowngradeType `gorm:"type:varchar(20);not null" json:"downgradeType"`
	IsActive          bool            `gorm:"not null;default:true" json:"isActive"`
	CreatedAt         time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt         time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	DeletedAt         *time.Time      `gorm:"index" json:"deletedAt,omitempty"`
}
