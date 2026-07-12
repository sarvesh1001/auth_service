package enums

type TimelineEvent string

const (
	EventCreated   TimelineEvent = "created"
	EventActivated TimelineEvent = "activated"
	EventPaused    TimelineEvent = "paused"
	EventResumed   TimelineEvent = "resumed"
	EventCancelled TimelineEvent = "cancelled"
	EventExpired   TimelineEvent = "expired"
	EventRenewed   TimelineEvent = "renewed"
	EventChanged   TimelineEvent = "changed"
	EventTrialStart TimelineEvent = "trial_start"
	EventTrialEnd   TimelineEvent = "trial_end"
)

func (e TimelineEvent) IsValid() bool {
	switch e {
	case EventCreated, EventActivated, EventPaused, EventResumed, EventCancelled, EventExpired, EventRenewed, EventChanged, EventTrialStart, EventTrialEnd:
		return true
	}
	return false
}
