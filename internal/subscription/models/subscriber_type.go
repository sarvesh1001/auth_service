package models

type SubscriberType struct {
	SubscriberTypeID int16  `gorm:"primaryKey"`
	Code             string `gorm:"size:30;not null;unique"`
	Name             string `gorm:"size:100;not null"`
}

func (SubscriberType) TableName() string { return "subscriber_types" }
