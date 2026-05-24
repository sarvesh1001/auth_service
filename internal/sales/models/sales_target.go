package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type SalesTarget struct {
	TargetID     uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"targetId"`
	CompanyID    uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	SalesRepID   uuid.UUID       `gorm:"type:uuid;not null" json:"salesRepId"`
	PeriodStart  time.Time       `gorm:"type:date;not null" json:"periodStart"`
	PeriodEnd    time.Time       `gorm:"type:date;not null" json:"periodEnd"`
	TargetAmount decimal.Decimal `gorm:"type:numeric(14,2);not null" json:"targetAmount"`
	Currency     string          `gorm:"type:varchar(3);not null;default:'USD'" json:"currency"`
	CreatedAt    time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt    time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy    *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy    *uuid.UUID      `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
