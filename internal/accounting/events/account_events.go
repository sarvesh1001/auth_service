package events

const (
	EventAccountCreated       = "account.created"
	EventAccountUpdated       = "account.updated"
	EventAccountStatusChanged = "account.status_changed"
	EventAccountMoved         = "account.moved"
	EventAccountDeleted       = "account.deleted"
)

type AccountPayload struct {
	AccountID   string  `json:"account_id"`
	CompanyID   string  `json:"company_id"`
	AccountCode string  `json:"account_code"`
	AccountName string  `json:"account_name"`
	AccountType string  `json:"account_type"`
	ParentID    *string `json:"parent_id,omitempty"`
	IsActive    bool    `json:"is_active"`
	Description *string `json:"description,omitempty"`
}
