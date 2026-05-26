package enums

type CommissionReferenceType string

const (
	CommissionReferenceTypeOrder   CommissionReferenceType = "order"
	CommissionReferenceTypeInvoice CommissionReferenceType = "invoice"
	CommissionReferenceTypePayment CommissionReferenceType = "payment"
)

type CommissionStatus string

const (
	CommissionStatusPending  CommissionStatus = "pending"
	CommissionStatusApproved CommissionStatus = "approved"
	CommissionStatusPaid     CommissionStatus = "paid"
	CommissionStatusRejected CommissionStatus = "rejected"
	CommissionStatusReversed CommissionStatus = "reversed"
)

type CommissionRuleType string

const (
	CommissionRuleTypeFlat     CommissionRuleType = "flat"
	CommissionRuleTypeTiered   CommissionRuleType = "tiered"
	CommissionRuleTypeProduct  CommissionRuleType = "product"
	CommissionRuleTypeCategory CommissionRuleType = "category"
)
