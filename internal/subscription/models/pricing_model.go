package models

import (
	"time"
)

type PricingModel struct {
	ModelID   int16     `gorm:"primaryKey" json:"modelId"`
	Code      string    `gorm:"type:varchar(30);not null;unique" json:"code"`
	Name      string    `gorm:"type:varchar(100);not null" json:"name"`
	CreatedAt time.Time `gorm:"default:now()" json:"createdAt"`
}
