package models

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type CommissionRule struct {
	RuleID       uuid.UUID                `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CompanyID    uuid.UUID                `gorm:"type:uuid;not null;index"`
	PlanID       uuid.UUID                `gorm:"type:uuid;not null;index"`
	RuleType     enums.CommissionRuleType `gorm:"type:varchar(20);not null"`
	AppliesTo    enums.CommissionBaseType `gorm:"type:sales.commission_base_type;not null"`
	ProductID    *uuid.UUID               `gorm:"type:uuid"`
	TierMin      *decimal.Decimal         `gorm:"type:numeric(14,4)"`
	TierMax      *decimal.Decimal         `gorm:"type:numeric(14,4)"`
	Rate         decimal.Decimal          `gorm:"type:numeric(14,4);not null"`
	IsPercentage bool                     `gorm:"default:true"`
	Priority     int                      `gorm:"default:0"`
	CreatedAt    time.Time                `gorm:"default:now()"`
	UpdatedAt    time.Time                `gorm:"autoUpdateTime"`
	CreatedBy    *uuid.UUID
	UpdatedBy    *uuid.UUID
}
