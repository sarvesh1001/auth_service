package enums

type UpgradeType string

const (
	UpgradeChargeDiff UpgradeType = "charge_difference"
	UpgradeRefund     UpgradeType = "refund"
	UpgradeCreditNote UpgradeType = "credit_note"
)

func (u UpgradeType) IsValid() bool {
	switch u {
	case UpgradeChargeDiff, UpgradeRefund, UpgradeCreditNote:
		return true
	}
	return false
}
