package models

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type SalesCommission struct {
	CommissionID     uuid.UUID                     `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CompanyID        uuid.UUID                     `gorm:"type:uuid;not null;index"`
	SalesRepID       uuid.UUID                     `gorm:"type:uuid;not null;index"`
	ReferenceType    enums.CommissionReferenceType `gorm:"type:varchar(20);not null"`
	ReferenceID      uuid.UUID                     `gorm:"type:uuid;not null"`
	CommissionBase   decimal.Decimal               `gorm:"type:numeric(14,4);not null"`
	CommissionRate   decimal.Decimal               `gorm:"type:numeric(14,4);not null"`
	CommissionAmount decimal.Decimal               `gorm:"type:numeric(14,4);not null"`
	Status           enums.CommissionStatus        `gorm:"type:varchar(20);default:'pending'"`
	EarnedAt         time.Time                     `gorm:"type:timestamptz;not null"`
	PaidAt           *time.Time                    `gorm:"type:timestamptz"`
	ApprovedAt       *time.Time                    `gorm:"type:timestamptz"`
	RejectedAt       *time.Time                    `gorm:"type:timestamptz"`
	RejectReason     *string                       `gorm:"type:text"`
	Notes            *string                       `gorm:"type:text"`
	RuleID           *uuid.UUID                    `gorm:"type:uuid"`
	CreatedAt        time.Time                     `gorm:"default:now()"`
	UpdatedAt        time.Time                     `gorm:"autoUpdateTime"`
	CreatedBy        *uuid.UUID
	UpdatedBy        *uuid.UUID
}
