package enums

type ComplianceReturnStatus string

const (
	ReturnStatusDraft     ComplianceReturnStatus = "draft"
	ReturnStatusSubmitted ComplianceReturnStatus = "submitted"
	ReturnStatusFiled     ComplianceReturnStatus = "filed"
	ReturnStatusAmended   ComplianceReturnStatus = "amended"
)

type ComplianceFilingStatus string

const (
	FilingStatusPending  ComplianceFilingStatus = "pending"
	FilingStatusAccepted ComplianceFilingStatus = "accepted"
	FilingStatusRejected ComplianceFilingStatus = "rejected"
)
