package enums

type CommissionBaseType string

const (
	CommissionBaseRevenue    CommissionBaseType = "revenue"
	CommissionBaseProfit     CommissionBaseType = "profit"
	CommissionBaseOrderTotal CommissionBaseType = "order_total"
)

func (c CommissionBaseType) IsValid() bool {
	switch c {
	case CommissionBaseRevenue, CommissionBaseProfit, CommissionBaseOrderTotal:
		return true
	}
	return false
}
