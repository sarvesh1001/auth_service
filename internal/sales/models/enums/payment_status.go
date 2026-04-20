package enums

type PaymentStatus string

const (
	PaymentStatusPending           PaymentStatus = "pending"
	PaymentStatusProcessing        PaymentStatus = "processing"
	PaymentStatusCompleted         PaymentStatus = "completed"
	PaymentStatusFailed            PaymentStatus = "failed"
	PaymentStatusRefunded          PaymentStatus = "refunded"
	PaymentStatusPartiallyRefunded PaymentStatus = "partially_refunded"
)

func (s PaymentStatus) IsValid() bool {
	switch s {
	case PaymentStatusPending, PaymentStatusProcessing, PaymentStatusCompleted,
		PaymentStatusFailed, PaymentStatusRefunded, PaymentStatusPartiallyRefunded:
		return true
	}
	return false
}

func (s PaymentStatus) String() string { return string(s) }
