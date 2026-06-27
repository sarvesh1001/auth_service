package enums

type StatusCategory string

const (
	CategorySubscription StatusCategory = "subscription"
	CategoryItem         StatusCategory = "item"
	CategorySchedule     StatusCategory = "schedule"
	CategoryResource     StatusCategory = "resource"
	CategoryWaitlist     StatusCategory = "waitlist"
)

type Status struct {
	ID       int16          `gorm:"primaryKey"`
	Code     string         `gorm:"not null"`
	Category StatusCategory `gorm:"not null"`
	Name     string         `gorm:"not null"`
}

func (Status) TableName() string { return "statuses" }
