package events

import "time"

// Compliance event types
const (
	EventReturnCreated   = "compliance.return.created"
	EventReturnUpdated   = "compliance.return.updated"
	EventReturnSubmitted = "compliance.return.submitted"
	EventReturnFiled     = "compliance.return.filed"
	EventReturnAmended   = "compliance.return.amended"
	EventReturnDeleted   = "compliance.return.deleted"
	EventFilingCreated   = "compliance.filing.created"
	EventFilingUpdated   = "compliance.filing.updated"
)

// ComplianceReturnPayload carries the return data
type ComplianceReturnPayload struct {
	ReturnID       string              `json:"return_id"`
	CompanyID      string              `json:"company_id"`
	ReturnType     string              `json:"return_type"`
	PeriodStart    time.Time           `json:"period_start"`
	PeriodEnd      time.Time           `json:"period_end"`
	DueDate        time.Time           `json:"due_date"`
	Status         string              `json:"status"`
	TotalLiability string              `json:"total_liability"`
	TotalPaid      string              `json:"total_paid"`
	Lines          []ReturnLinePayload `json:"lines,omitempty"`
}

type ReturnLinePayload struct {
	LineType      string `json:"line_type"`
	TaxRateID     string `json:"tax_rate_id,omitempty"`
	TaxableAmount string `json:"taxable_amount"`
	TaxAmount     string `json:"tax_amount"`
	Description   string `json:"description,omitempty"`
}

// ComplianceFilingPayload for filing events
type ComplianceFilingPayload struct {
	FilingID          string    `json:"filing_id"`
	ReturnID          string    `json:"return_id"`
	SubmissionDate    time.Time `json:"submission_date"`
	AcknowledgementNo string    `json:"acknowledgement_no,omitempty"`
	FilingStatus      string    `json:"filing_status"`
	ErrorMessage      string    `json:"error_message,omitempty"`
}
