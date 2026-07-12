package enums

type DowngradeType string

const (
	DowngradeCreditNext DowngradeType = "credit_next"
	DowngradeRefund     DowngradeType = "refund"
	DowngradeNone       DowngradeType = "none"
)

func (d DowngradeType) IsValid() bool {
	switch d {
	case DowngradeCreditNext, DowngradeRefund, DowngradeNone:
		return true
	}
	return false
}
