package enums

type ScheduleType string

const (
	Class        ScheduleType = "class"
	Appointment  ScheduleType = "appointment"
	Meeting      ScheduleType = "meeting"
	Delivery     ScheduleType = "delivery"
	Visit        ScheduleType = "visit"
	Workshop     ScheduleType = "workshop"
	Event        ScheduleType = "event"
	ServiceVisit ScheduleType = "service"
	Maintenance  ScheduleType = "maintenance"
)

func (st ScheduleType) String() string { return string(st) }
