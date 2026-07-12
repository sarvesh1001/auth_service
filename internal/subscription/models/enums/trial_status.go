package enums

type TrialStatus string

const (
	TrialActive    TrialStatus = "active"
	TrialExpired   TrialStatus = "expired"
	TrialConverted TrialStatus = "converted"
	TrialCancelled TrialStatus = "cancelled"
)

func (t TrialStatus) IsValid() bool {
	switch t {
	case TrialActive, TrialExpired, TrialConverted, TrialCancelled:
		return true
	}
	return false
}
