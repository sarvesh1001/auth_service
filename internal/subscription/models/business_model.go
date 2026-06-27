package models

type BusinessModel struct {
	BusinessModelID int16  `gorm:"primaryKey"`
	Code            string `gorm:"size:30;not null;unique"`
	Name            string `gorm:"size:100;not null"`
}

func (BusinessModel) TableName() string { return "business_models" }
