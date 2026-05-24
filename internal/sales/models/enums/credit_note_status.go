// models/enums/credit_note_status.go
package enums

type CreditNoteStatus string

const (
	CreditNoteDraft         CreditNoteStatus = "draft"
	CreditNoteIssued        CreditNoteStatus = "issued"
	CreditNotePartiallyUsed CreditNoteStatus = "partially_used"
	CreditNoteFullyUsed     CreditNoteStatus = "fully_used"
	CreditNoteVoided        CreditNoteStatus = "voided"
)

func (s CreditNoteStatus) IsValid() bool {
	switch s {
	case CreditNoteDraft, CreditNoteIssued, CreditNotePartiallyUsed,
		CreditNoteFullyUsed, CreditNoteVoided:
		return true
	}
	return false
}
