package enums

type SubscriptionStatus string

const (
	SubStatusActive    SubscriptionStatus = "active"
	SubStatusPaused    SubscriptionStatus = "paused"
	SubStatusExpired   SubscriptionStatus = "expired"
	SubStatusCancelled SubscriptionStatus = "cancelled"
	SubStatusTrial     SubscriptionStatus = "trial"
	SubStatusPending   SubscriptionStatus = "pending"
)

func (s SubscriptionStatus) IsValid() bool {
	switch s {
	case SubStatusActive, SubStatusPaused, SubStatusExpired, SubStatusCancelled, SubStatusTrial, SubStatusPending:
		return true
	}
	return false
}
