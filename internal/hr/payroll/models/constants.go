package models

const (
	// PayrollRunStatus
	PayrollStatusDraft      = "draft"
	PayrollStatusCalculated = "calculated"
	PayrollStatusApproved   = "approved"
	PayrollStatusPaid       = "paid"

	// ComponentType
	ComponentTypeEarning   = "earning"
	ComponentTypeDeduction = "deduction"

	// CalculationType
	CalculationTypeFlat       = "flat"
	CalculationTypePercentage = "percentage"
	CalculationTypeFormula    = "formula"

	// Standard Component Codes
	ComponentCodeBasic = "BASIC"
	ComponentCodeHRA   = "HRA"
	ComponentCodePF    = "PF"
	ComponentCodeTDS   = "TDS"
)
