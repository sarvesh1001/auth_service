package enums

type BillingFrequency string

const (
	FrequencyDaily     BillingFrequency = "daily"
	FrequencyWeekly    BillingFrequency = "weekly"
	FrequencyMonthly   BillingFrequency = "monthly"
	FrequencyQuarterly BillingFrequency = "quarterly"
	FrequencyHalfYear  BillingFrequency = "half_yearly"
	FrequencyYearly    BillingFrequency = "yearly"
)

func (f BillingFrequency) IsValid() bool {
	switch f {
	case FrequencyDaily, FrequencyWeekly, FrequencyMonthly, FrequencyQuarterly, FrequencyHalfYear, FrequencyYearly:
		return true
	}
	return false
}
