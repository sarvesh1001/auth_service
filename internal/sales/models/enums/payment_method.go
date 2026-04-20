package enums

type PaymentMethod string

const (
	PaymentMethodCash          PaymentMethod = "cash"
	PaymentMethodCard          PaymentMethod = "card"
	PaymentMethodBankTransfer  PaymentMethod = "bank_transfer"
	PaymentMethodDigitalWallet PaymentMethod = "digital_wallet"
	PaymentMethodCoupon        PaymentMethod = "coupon"
	PaymentMethodOther         PaymentMethod = "other"
)

func (m PaymentMethod) IsValid() bool {
	switch m {
	case PaymentMethodCash, PaymentMethodCard, PaymentMethodBankTransfer,
		PaymentMethodDigitalWallet, PaymentMethodCoupon, PaymentMethodOther:
		return true
	}
	return false
}

func (m PaymentMethod) String() string { return string(m) }
