package enums

type CreditCheckStatus string

const (
	CreditCheckPending  CreditCheckStatus = "pending"
	CreditCheckApproved CreditCheckStatus = "approved"
	CreditCheckRejected CreditCheckStatus = "rejected"
	CreditCheckHold     CreditCheckStatus = "hold"
)

func (s CreditCheckStatus) IsValid() bool {
	switch s {
	case CreditCheckPending, CreditCheckApproved, CreditCheckRejected, CreditCheckHold:
		return true
	}
	return false
}
