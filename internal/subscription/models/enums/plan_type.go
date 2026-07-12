package enums

type PlanType string

const (
	PlanTypeRecurring PlanType = "recurring"
	PlanTypeOneTime   PlanType = "one_time"
	PlanTypeUsageBased PlanType = "usage_based"
	PlanTypeContract  PlanType = "contract"
)

func (p PlanType) IsValid() bool {
	switch p {
	case PlanTypeRecurring, PlanTypeOneTime, PlanTypeUsageBased, PlanTypeContract:
		return true
	}
	return false
}
