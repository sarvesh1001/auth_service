package enums

type PricingModel string

const (
	PricingFlat      PricingModel = "flat"
	PricingPerUser   PricingModel = "per_user"
	PricingPerSeat   PricingModel = "per_seat"
	PricingPerVisit  PricingModel = "per_visit"
	PricingPerUsage  PricingModel = "per_usage"
	PricingTiered    PricingModel = "tiered"
	PricingMetered   PricingModel = "metered"
)

func (p PricingModel) IsValid() bool {
	switch p {
	case PricingFlat, PricingPerUser, PricingPerSeat, PricingPerVisit, PricingPerUsage, PricingTiered, PricingMetered:
		return true
	}
	return false
}
