package enums

type ValuationMethod string

const (
	ValuationMethodFIFO            ValuationMethod = "fifo"
	ValuationMethodLIFO            ValuationMethod = "lifo"
	ValuationMethodWeightedAverage ValuationMethod = "weighted_average"
	ValuationMethodStandardCost    ValuationMethod = "standard_cost"
)

// ValidValuationMethods returns all valid valuation methods.
func ValidValuationMethods() []ValuationMethod {
	return []ValuationMethod{
		ValuationMethodFIFO,
		ValuationMethodLIFO,
		ValuationMethodWeightedAverage,
		ValuationMethodStandardCost,
	}
}

// IsValid checks if the valuation method is valid.
func (v ValuationMethod) IsValid() bool {
	switch v {
	case ValuationMethodFIFO, ValuationMethodLIFO, ValuationMethodWeightedAverage, ValuationMethodStandardCost:
		return true
	}
	return false
}

func (v ValuationMethod) String() string {
	return string(v)
}
