package models

type Status struct {
	StatusID int16  `gorm:"primaryKey"`
	Code     string `gorm:"size:30;not null"`
	Category string `gorm:"size:30;not null"`
	Name     string `gorm:"size:100;not null"`
}

func (Status) TableName() string { return "statuses" }
