package discount

type DiscountType string

const (
	DiscountTypePercentage DiscountType = "percentage"
	DiscountTypeFixed      DiscountType = "fixed_amount"
	DiscountTypeBuyXGetY   DiscountType = "buy_x_get_y"
)

func (d DiscountType) IsValid() bool {
	switch d {
	case DiscountTypePercentage, DiscountTypeFixed, DiscountTypeBuyXGetY:
		return true
	}
	return false
}

func (d DiscountType) String() string {
	return string(d)
}
