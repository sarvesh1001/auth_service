package models

type BillingType struct {
	BillingTypeID int16  `gorm:"primaryKey"`
	Code          string `gorm:"size:30;not null;unique"`
	Name          string `gorm:"size:100;not null"`
}

func (BillingType) TableName() string { return "billing_types" }
