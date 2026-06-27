package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/datatypes"
)

type Plan struct {
	PlanID             uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID          uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name               string         `gorm:"size:255;not null"`
	BusinessModelID    int16          `gorm:"not null"`
	Description        *string        `gorm:"type:text"`
	BillingPolicyID    uuid.UUID      `gorm:"type:uuid;not null"`
	RenewalPolicyID    uuid.UUID      `gorm:"type:uuid;not null"`
	PausePolicyID      uuid.UUID      `gorm:"type:uuid;not null"`
	ProrationPolicyID  uuid.UUID      `gorm:"type:uuid;not null"`
	DurationDays       int            `gorm:"not null;default:365"`
	CancellationPolicy *string        `gorm:"type:text"`
	Metadata           datatypes.JSON `gorm:"type:jsonb"`
	IsActive           bool           `gorm:"not null;default:true"`
	CreatedAt          time.Time      `gorm:"not null;default:now()"`
	UpdatedAt          time.Time      `gorm:"not null;default:now()"`
	DeletedAt          gorm.DeletedAt `gorm:"index"`

	// relationships
	Company          Company           `gorm:"foreignKey:CompanyID"`
	BusinessModel    BusinessModel     `gorm:"foreignKey:BusinessModelID"`
	BillingPolicy    BillingPolicy     `gorm:"foreignKey:BillingPolicyID"`
	RenewalPolicy    RenewalPolicy     `gorm:"foreignKey:RenewalPolicyID"`
	PausePolicy      PausePolicy       `gorm:"foreignKey:PausePolicyID"`
	ProrationPolicy  ProrationPolicy   `gorm:"foreignKey:ProrationPolicyID"`
	PlanItems        []PlanItem        `gorm:"foreignKey:PlanID"`
	Subscriptions    []Subscription    `gorm:"foreignKey:PlanID"`
}

func (Plan) TableName() string { return "plans" }
