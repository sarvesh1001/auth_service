package models

import (
	"time"
)

type BillingFrequency struct {
	FrequencyID int16     `gorm:"primaryKey" json:"frequencyId"`
	Code        string    `gorm:"type:varchar(20);not null;unique" json:"code"`
	Name        string    `gorm:"type:varchar(50);not null" json:"name"`
	CreatedAt   time.Time `gorm:"default:now()" json:"createdAt"`
}
