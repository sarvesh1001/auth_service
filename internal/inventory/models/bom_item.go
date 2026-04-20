package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type BOMItem struct {
	BOMItemID       uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"bomItemId"`
	BOMID           uuid.UUID        `gorm:"type:uuid;not null" json:"bomId"`
	ComponentItemID uuid.UUID        `gorm:"type:uuid;not null" json:"componentItemId"`
	Quantity        decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"quantity"`
	ScrapPercentage *decimal.Decimal `gorm:"type:numeric(5,2);default:0" json:"scrapPercentage,omitempty"`
	CreatedAt       time.Time        `gorm:"not null;default:now()" json:"createdAt"`
}
