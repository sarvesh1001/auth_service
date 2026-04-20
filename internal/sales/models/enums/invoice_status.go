package enums

type InvoiceStatus string

const (
	InvoiceStatusDraft     InvoiceStatus = "draft"
	InvoiceStatusIssued    InvoiceStatus = "issued"
	InvoiceStatusPaid      InvoiceStatus = "paid"
	InvoiceStatusOverdue   InvoiceStatus = "overdue"
	InvoiceStatusCancelled InvoiceStatus = "cancelled"
	InvoiceStatusCredited  InvoiceStatus = "credited"
)

func (s InvoiceStatus) IsValid() bool {
	switch s {
	case InvoiceStatusDraft, InvoiceStatusIssued, InvoiceStatusPaid,
		InvoiceStatusOverdue, InvoiceStatusCancelled, InvoiceStatusCredited:
		return true
	}
	return false
}

func (s InvoiceStatus) String() string { return string(s) }
