package events

import "time"

// Accounting event types
const (
	EventJournalCreated  = "journal.created"
	EventJournalUpdated  = "journal.updated"
	EventJournalPosted   = "journal.posted"
	EventJournalReversed = "journal.reversed"
	EventJournalDeleted  = "journal.deleted"
)

// JournalEventPayload carries the journal entry and its lines
type JournalEventPayload struct {
	JournalEntryID string        `json:"journal_entry_id"`
	CompanyID      string        `json:"company_id"`
	JournalType    string        `json:"journal_type"`
	EntryDate      time.Time     `json:"entry_date"`
	TotalDebit     string        `json:"total_debit"` // decimal as string
	TotalCredit    string        `json:"total_credit"`
	Status         string        `json:"status"`
	Lines          []LinePayload `json:"lines"`
	ReversalOf     string        `json:"reversal_of,omitempty"` // ADD THIS
}

type LinePayload struct {
	AccountID    string `json:"account_id"`
	DebitAmount  string `json:"debit_amount"`
	CreditAmount string `json:"credit_amount"`
	Description  string `json:"description,omitempty"`
}

// Add these constants
const (
	EventLedgerUpdated  = "ledger.updated"  // when account balances change
	EventLedgerReversed = "ledger.reversed" // when a reversal affects balances
)

// LedgerEventPayload describes balance changes for one or more accounts
type LedgerEventPayload struct {
	CompanyID   string               `json:"company_id"`
	JournalID   string               `json:"journal_id"`
	PostingDate time.Time            `json:"posting_date"`
	Entries     []LedgerEntryPayload `json:"entries"`
}

type LedgerEntryPayload struct {
	AccountID     string `json:"account_id"`
	Amount        string `json:"amount"` // positive for debit, negative for credit
	BalanceBefore string `json:"balance_before"`
	BalanceAfter  string `json:"balance_after"`
	FiscalYear    int    `json:"fiscal_year"`
	Period        int    `json:"period"`
}
