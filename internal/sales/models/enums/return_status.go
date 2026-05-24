package enums

type ReturnStatus string

const (
	ReturnStatusPending   ReturnStatus = "pending"
	ReturnStatusApproved  ReturnStatus = "approved"
	ReturnStatusCompleted ReturnStatus = "completed"
	ReturnStatusRejected  ReturnStatus = "rejected"
)

func (s ReturnStatus) IsValid() bool {
	switch s {
	case ReturnStatusPending, ReturnStatusApproved, ReturnStatusCompleted, ReturnStatusRejected:
		return true
	}
	return false
}
func (s ReturnStatus) String() string {
	return string(s)
}
