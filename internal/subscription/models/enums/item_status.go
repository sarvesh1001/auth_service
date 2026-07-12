package enums

type ItemStatus string

const (
	ItemStatusActive   ItemStatus = "active"
	ItemStatusInactive ItemStatus = "inactive"
)

func (s ItemStatus) IsValid() bool {
	switch s {
	case ItemStatusActive, ItemStatusInactive:
		return true
	}
	return false
}

// internal/subscription/models/enums/item_status.go
func (s ItemStatus) ToStatusID() int {
	switch s {
	case ItemStatusActive:
		return 7 // from your statuses table
	case ItemStatusInactive:
		return 8
	default:
		return 7 // fallback
	}
}
