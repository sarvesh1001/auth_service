package enums

const (
	JournalTypeSales    = "sales"
	JournalTypePurchase = "purchase"
	JournalTypePayment  = "payment"
	JournalTypeReceipt  = "receipt"
	JournalTypeGeneral  = "general"
	JournalTypeContra   = "contra"
)

var ValidJournalTypes = []string{
	JournalTypeSales, JournalTypePurchase, JournalTypePayment,
	JournalTypeReceipt, JournalTypeGeneral, JournalTypeContra,
}
