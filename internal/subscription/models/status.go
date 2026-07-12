package models

import (
	"time"
)

type Status struct {
	StatusID  int16     `gorm:"primaryKey" json:"statusId"`
	Code      string    `gorm:"type:varchar(30);not null" json:"code"`
	Category  string    `gorm:"type:varchar(30);not null" json:"category"`
	Name      string    `gorm:"type:varchar(100);not null" json:"name"`
	CreatedAt time.Time `gorm:"default:now()" json:"createdAt"`
}
