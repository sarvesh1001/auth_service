package enums

type BusinessModel string

const (
	Membership        BusinessModel = "membership"
	RecurringProduct  BusinessModel = "recurring_product"
	RecurringService  BusinessModel = "recurring_service"
	UsageBased        BusinessModel = "usage_based"
	Rental            BusinessModel = "rental"
	Contract          BusinessModel = "contract"
	Course            BusinessModel = "course"
	SeatLicense       BusinessModel = "seat_license"
	Insurance         BusinessModel = "insurance"
	Leasing           BusinessModel = "leasing"
	Custom            BusinessModel = "custom"
)

func (bm BusinessModel) String() string { return string(bm) }
