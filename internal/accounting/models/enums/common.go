package enums

const (
	JournalStatusDraft    = "draft"
	JournalStatusPosted   = "posted"
	JournalStatusReversed = "reversed"
	JournalStatusDeleted  = "deleted" // ADD THIS

	ComplianceStatusDraft     = "draft"
	ComplianceStatusSubmitted = "submitted"
	ComplianceStatusFiled     = "filed"
	ComplianceStatusAmended   = "amended"

	FilingStatusSubmitted  = "submitted"
	TaxActionApplyTax      = "apply_tax"
	TaxActionExempt        = "exempt"
	TaxActionReverseCharge = "reverse_charge"
)

const (
	TaxSchemeAccrual = "accrual"
	TaxSchemeCash    = "cash"
)
