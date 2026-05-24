package enums

type QuoteStatus string

const (
	QuoteStatusDraft     QuoteStatus = "draft"
	QuoteStatusSent      QuoteStatus = "sent"
	QuoteStatusAccepted  QuoteStatus = "accepted"
	QuoteStatusRejected  QuoteStatus = "rejected"
	QuoteStatusExpired   QuoteStatus = "expired"
	QuoteStatusConverted QuoteStatus = "converted"
)

func (s QuoteStatus) IsValid() bool {
	switch s {
	case QuoteStatusDraft, QuoteStatusSent, QuoteStatusAccepted,
		QuoteStatusRejected, QuoteStatusExpired, QuoteStatusConverted:
		return true
	}
	return false
}
