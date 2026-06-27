package models

type ScheduleType struct {
	ScheduleTypeID int16  `gorm:"primaryKey"`
	Code           string `gorm:"size:30;not null;unique"`
	Name           string `gorm:"size:100;not null"`
}

func (ScheduleType) TableName() string { return "schedule_types" }
