package enums

type LimitPeriod string

const (
	LimitPeriodDay      LimitPeriod = "day"
	LimitPeriodWeek     LimitPeriod = "week"
	LimitPeriodMonth    LimitPeriod = "month"
	LimitPeriodYear     LimitPeriod = "year"
	LimitPeriodLifetime LimitPeriod = "lifetime"
)

func (p LimitPeriod) IsValid() bool {
	switch p {
	case LimitPeriodDay, LimitPeriodWeek, LimitPeriodMonth, LimitPeriodYear, LimitPeriodLifetime:
		return true
	}
	return false
}
