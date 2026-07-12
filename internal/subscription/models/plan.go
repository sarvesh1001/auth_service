package models

import (
	"time"
	"github.com/google/uuid"
	"auth-service/internal/subscription/models/enums"
)

type Plan struct {
	PlanID            uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"planId"`
	CompanyID         uuid.UUID          `gorm:"type:uuid;not null;index" json:"companyId"`
	Name              string             `gorm:"type:varchar(255);not null" json:"name"`
	PlanType          enums.PlanType     `gorm:"type:varchar(30);not null" json:"planType"`
	Description       *string            `gorm:"type:text" json:"description,omitempty"`
	BillingPolicyID   uuid.UUID          `gorm:"type:uuid;not null" json:"billingPolicyId"`
	RenewalPolicyID   uuid.UUID          `gorm:"type:uuid;not null" json:"renewalPolicyId"`
	PausePolicyID     uuid.UUID          `gorm:"type:uuid;not null" json:"pausePolicyId"`
	ProrationPolicyID uuid.UUID          `gorm:"type:uuid;not null" json:"prorationPolicyId"`
	DurationDays      int                `gorm:"not null;default:365" json:"durationDays"`
	CancellationPolicy *string           `gorm:"type:text" json:"cancellationPolicy,omitempty"`
	Metadata          JSONB              `gorm:"type:jsonb" json:"metadata,omitempty"`
	IsActive          bool               `gorm:"not null;default:true" json:"isActive"`
	Version           int                `gorm:"not null;default:1" json:"version"`
	PublishedAt       *time.Time         `gorm:"type:timestamptz" json:"publishedAt,omitempty"`
	PublishedBy       *uuid.UUID         `gorm:"type:uuid" json:"publishedBy,omitempty"`
	CreatedAt         time.Time          `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt         time.Time          `gorm:"autoUpdateTime" json:"updatedAt"`
	DeletedAt         *time.Time         `gorm:"index" json:"deletedAt,omitempty"`
}
