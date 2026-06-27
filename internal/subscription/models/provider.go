package models

type Provider struct {
	ProviderID int16  `gorm:"primaryKey"`
	Code       string `gorm:"size:30;not null;unique"`
	Name       string `gorm:"size:100;not null"`
}

func (Provider) TableName() string { return "providers" }
