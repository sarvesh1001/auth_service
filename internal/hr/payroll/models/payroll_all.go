package models

import (
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Constants
// ============================================================================

const (
	// PayrollRun statuses
	PayrollStatusDraft              = "draft"
	PayrollStatusProcessing         = "processing"
	PayrollStatusCalculated         = "calculated"
	PayrollStatusApproved           = "approved"
	PayrollStatusPaid               = "paid"
	PayrollStatusFailed             = "failed"
	PayrollStatusPartiallyProcessed = "partially_processed"

	// Component types
	ComponentTypeEarning   = "earning"
	ComponentTypeDeduction = "deduction"

	// Calculation types (salary structure)
	CalculationTypeFixed      = "fixed"
	CalculationTypeFlat       = "flat"
	CalculationTypePercentage = "percentage"
	CalculationTypeFormula    = "formula"

	// Adjustment types
	AdjustmentTypeAddition  = "addition"
	AdjustmentTypeDeduction = "deduction"

	// Standard component codes (non‑statutory)
	ComponentCodeBasic = "BASIC"
	ComponentCodeHRA   = "HRA"

	// Contribution sides
	ContributionSideEmployee = "employee"
	ContributionSideEmployer = "employer"
	ContributionSideNone     = "none"

	// Pay types
	PayTypeMonthly   = "monthly"
	PayTypeDailyWage = "daily_wage"
	PayTypeHourly    = "hourly"

	// Attendance rule types
	RuleTypeOvertime = "overtime"
	RuleTypeLate     = "late"
	RuleTypeAbsent   = "absent"

	CalculationTypeMultiplier = "multiplier"

	BasedOnDaily  = "daily"
	BasedOnHourly = "hourly"

	// Statutory calculation bases
	StatutoryCalculationBasisBasic         = "basic"
	StatutoryCalculationBasisGross         = "gross"
	StatutoryCalculationBasisCTC           = "ctc"
	StatutoryCalculationBasisTaxableIncome = "taxable_income"

	CalculationTypeSlab = "slab"

	// Loan status
	LoanStatusActive    = "active"
	LoanStatusClosed    = "closed"
	LoanStatusDefaulted = "defaulted"

	// EMI status
	EmiStatusPending = "pending"
	EmiStatusPaid    = "paid"
	EmiStatusWaived  = "waived"

	// Tax declaration status
	DeclarationStatusPending  = "pending"
	DeclarationStatusVerified = "verified"
	DeclarationStatusRejected = "rejected"
)

// ============================================================================
// payroll_component (company‑specific)
// ============================================================================

type PayrollComponent struct {
	CompanyID        uuid.UUID `json:"company_id" db:"company_id"`
	ComponentCode    string    `json:"component_code" db:"component_code"`
	ComponentType    string    `json:"component_type" db:"component_type"`
	Description      string    `json:"description,omitempty" db:"description"`
	IsTaxable        bool      `json:"is_taxable" db:"is_taxable"`
	IsSystem         bool      `json:"is_system" db:"is_system"`
	IsActive         bool      `json:"is_active" db:"is_active"`
	ContributionSide string    `json:"contribution_side" db:"contribution_side"`
}

type ComponentFilter struct {
	ComponentType *string
	IsTaxable     *bool
	IsSystem      *bool
	IsActive      *bool
}

// ============================================================================
// salary_structure & related
// ============================================================================

type SalaryStructure struct {
	SalaryStructureID uuid.UUID  `json:"salary_structure_id" db:"salary_structure_id"`
	CompanyID         uuid.UUID  `json:"company_id" db:"company_id"`
	StructureName     string     `json:"structure_name" db:"structure_name"`
	CurrencyCode      string     `json:"currency_code" db:"currency_code"`
	IsActive          bool       `json:"is_active" db:"is_active"`
	Version           int        `json:"version" db:"version"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	CreatedBy         *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
	UpdatedBy         *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
	DeactivatedAt     *time.Time `json:"deactivated_at,omitempty" db:"deactivated_at"`
	DeactivatedBy     *uuid.UUID `json:"deactivated_by,omitempty" db:"deactivated_by"`
}

type SalaryStructureComponent struct {
	MappingID         uuid.UUID `json:"mapping_id" db:"mapping_id"`
	SalaryStructureID uuid.UUID `json:"salary_structure_id" db:"salary_structure_id"`
	CompanyID         uuid.UUID `json:"company_id,omitempty"` // for ownership validation
	ComponentCode     string    `json:"component_code" db:"component_code"`
	CalculationType   string    `json:"calculation_type" db:"calculation_type"`
	Value             float64   `json:"value" db:"value"`
	BasedOnComponent  *string   `json:"based_on_component,omitempty" db:"based_on_component"`
	SequenceOrder     int       `json:"sequence_order" db:"sequence_order"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

type SalaryStructureSnapshot struct {
	Structure  SalaryStructure            `json:"structure"`
	Components []SalaryStructureComponent `json:"components"`
	ResolvedAt time.Time                  `json:"resolved_at"`
	Currency   string                     `json:"currency"`
	MonthlyCTC float64                    `json:"monthly_ctc"`
	PayType    string                     `json:"pay_type"`
	UserID     uuid.UUID                  `json:"user_id,omitempty"`
	CompanyID  uuid.UUID                  `json:"company_id,omitempty"`
}

// ============================================================================
// employee_salary
// ============================================================================

type EmployeeSalary struct {
	EmployeeSalaryID  uuid.UUID `json:"employee_salary_id" db:"employee_salary_id"`
	CompanyID         uuid.UUID `json:"company_id" db:"company_id"`
	UserID            uuid.UUID `json:"user_id" db:"user_id"`
	SalaryStructureID uuid.UUID `json:"salary_structure_id" db:"salary_structure_id"`
	MonthlyCTC        float64   `json:"monthly_ctc" db:"monthly_ctc"`

	PayType string `json:"pay_type" db:"pay_type"`

	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	IsActive      bool       `json:"is_active" db:"is_active"`
	Version       int        `json:"version" db:"version"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty" db:"deactivated_at"`
	DeactivatedBy *uuid.UUID `json:"deactivated_by,omitempty" db:"deactivated_by"`
}

// ============================================================================
// payroll_run & related
// ============================================================================

type PayrollRun struct {
	PayrollRunID    uuid.UUID  `json:"payroll_run_id" db:"payroll_run_id"`
	CompanyID       uuid.UUID  `json:"company_id" db:"company_id"`
	PeriodStart     time.Time  `json:"period_start" db:"period_start"`
	PeriodEnd       time.Time  `json:"period_end" db:"period_end"`
	Status          string     `json:"status" db:"status"`
	TotalEmployees  *int       `json:"total_employees,omitempty" db:"total_employees"`
	ProcessedCount  *int       `json:"processed_count,omitempty" db:"processed_count"`
	FailedCount     *int       `json:"failed_count,omitempty" db:"failed_count"`
	LastProcessedAt *time.Time `json:"last_processed_at,omitempty" db:"last_processed_at"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

type PayrollRunFilter struct {
	CompanyID   uuid.UUID
	Status      *string
	PeriodStart *time.Time
	PeriodEnd   *time.Time
	Page        int
	PageSize    int
}

type PayrollRunSummary struct {
	PayrollRunID    uuid.UUID `json:"payroll_run_id"`
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	Status          string    `json:"status"`
	TotalEmployees  int       `json:"total_employees"`
	TotalGross      float64   `json:"total_gross"`
	TotalNet        float64   `json:"total_net"`
	TotalDeductions float64   `json:"total_deductions"`
	CreatedAt       time.Time `json:"created_at"`
}

// ============================================================================
// payroll_item & payroll_ledger
// ============================================================================

type PayrollItem struct {
	PayrollItemID uuid.UUID `json:"payroll_item_id" db:"payroll_item_id"`
	PayrollRunID  uuid.UUID `json:"payroll_run_id" db:"payroll_run_id"`
	UserID        uuid.UUID `json:"user_id" db:"user_id"`

	PayableDays float64 `json:"payable_days" db:"payable_days"`
	UnpaidDays  float64 `json:"unpaid_days" db:"unpaid_days"`

	GrossAmount float64 `json:"gross_amount" db:"gross_amount"`
	NetAmount   float64 `json:"net_amount" db:"net_amount"`

	VersionNumber int        `json:"version_number" db:"version_number"`
	IsSuperseded  bool       `json:"is_superseded" db:"is_superseded"`
	SupersededAt  *time.Time `json:"superseded_at,omitempty" db:"superseded_at"`
	SupersededBy  *uuid.UUID `json:"superseded_by,omitempty" db:"superseded_by"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type PayrollItemDetail struct {
	PayrollItem
	Username       string              `json:"username"`
	FullName       string              `json:"full_name"`
	EmployeeID     string              `json:"employee_id"`
	PositionTitle  *string             `json:"position_title,omitempty"`
	DepartmentName *string             `json:"department_name,omitempty"`
	Components     []PayrollLedgerItem `json:"components"`
}

type PayrollLedger struct {
	LedgerID      uuid.UUID `json:"ledger_id" db:"ledger_id"`
	PayrollItemID uuid.UUID `json:"payroll_item_id" db:"payroll_item_id"`
	ComponentCode string    `json:"component_code" db:"component_code"`
	Amount        float64   `json:"amount" db:"amount"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type PayrollLedgerItem struct {
	ComponentCode string  `json:"component_code"`
	ComponentType string  `json:"component_type"`
	Description   string  `json:"description,omitempty"`
	Amount        float64 `json:"amount"`
	IsTaxable     bool    `json:"is_taxable"`
}

type LedgerSummary struct {
	ComponentCode    string  `json:"component_code"`
	ComponentType    string  `json:"component_type"`
	Description      string  `json:"description"`
	TotalAmount      float64 `json:"total_amount"`
	IsTaxable        bool    `json:"is_taxable"`
	ContributionSide string  `json:"contribution_side"`
}

// ============================================================================
// payroll_snapshot & payslip
// ============================================================================

type PayrollSnapshot struct {
	SnapshotID   uuid.UUID  `json:"snapshot_id" db:"snapshot_id"`
	PayrollRunID uuid.UUID  `json:"payroll_run_id" db:"payroll_run_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	SnapshotType string     `json:"snapshot_type" db:"snapshot_type"` // run, item, salary, tax, statutory
	SnapshotData []byte     `json:"snapshot_data" db:"snapshot_data"` // JSONB
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	CreatedBy    uuid.UUID  `json:"created_by" db:"created_by"`
	RuleSetID    *uuid.UUID `json:"rule_set_id,omitempty" db:"rule_set_id"`
	RuleHash     *string    `json:"rule_hash,omitempty" db:"rule_hash"`
}

// Payslip is used for API responses (enriched with computed data).
type Payslip struct {
	PayslipID    uuid.UUID          `json:"payslip_id"`
	CompanyID    uuid.UUID          `json:"company_id"`
	UserID       uuid.UUID          `json:"user_id"`
	PayrollRunID uuid.UUID          `json:"payroll_run_id"`
	PeriodStart  time.Time          `json:"period_start"`
	PeriodEnd    time.Time          `json:"period_end"`
	Earnings     []PayslipComponent `json:"earnings"`
	Deductions   []PayslipComponent `json:"deductions"`
	GrossAmount  float64            `json:"gross_amount"`
	TotalTax     float64            `json:"total_tax"`
	NetAmount    float64            `json:"net_amount"`
	GeneratedAt  time.Time          `json:"generated_at"`
}

// PayslipRecord corresponds to the database table payroll.payslip.
// ============================================================================
// statutory rule set
// ============================================================================

type StatutoryRuleSet struct {
	RuleSetID     uuid.UUID  `json:"rule_set_id" db:"rule_set_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	CountryCode   string     `json:"country_code" db:"country_code"`
	VersionLabel  string     `json:"version_label" db:"version_label"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	IsActive      bool       `json:"is_active" db:"is_active"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// ============================================================================
// statutory component mapping
// ============================================================================

type StatutoryComponentMapping struct {
	MappingID     uuid.UUID  `json:"mapping_id" db:"mapping_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	StatutoryCode string     `json:"statutory_code" db:"statutory_code"`
	ComponentCode string     `json:"component_code" db:"component_code"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	IsActive      bool       `json:"is_active" db:"is_active"`
	Version       int        `json:"version" db:"version"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty" db:"deactivated_at"`
	DeactivatedBy *uuid.UUID `json:"deactivated_by,omitempty" db:"deactivated_by"`
	RuleSetID     *uuid.UUID `json:"rule_set_id,omitempty" db:"rule_set_id"`
}

// ============================================================================
// statutory tax slab
// ============================================================================

type StatutoryTaxSlab struct {
	SlabID        uuid.UUID  `json:"slab_id" db:"slab_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	StatutoryCode string     `json:"statutory_code" db:"statutory_code"`
	MinAmount     float64    `json:"min_income" db:"min_income"`
	MaxAmount     *float64   `json:"max_income,omitempty" db:"max_income"`
	Rate          float64    `json:"tax_percentage" db:"tax_percentage"`
	IsPercentage  bool       `json:"is_percentage" db:"is_percentage"`
	SlabOrder     int        `json:"slab_order" db:"slab_order"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	IsActive      bool       `json:"is_active" db:"is_active"`
	Version       int        `json:"version" db:"version"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty" db:"deactivated_at"`
	DeactivatedBy *uuid.UUID `json:"deactivated_by,omitempty" db:"deactivated_by"`
	RuleSetID     *uuid.UUID `json:"rule_set_id,omitempty" db:"rule_set_id"`
}

// ============================================================================
// statutory deduction limit (exactly as per SQL)
// ============================================================================

type StatutoryDeductionLimit struct {
	LimitID    uuid.UUID `json:"limit_id" db:"limit_id"`
	CompanyID  uuid.UUID `json:"company_id" db:"company_id"`
	RuleSetID  uuid.UUID `json:"rule_set_id" db:"rule_set_id"`
	LimitCode  string    `json:"limit_code" db:"limit_code"`
	LimitValue float64   `json:"limit_value" db:"limit_value"`
	Metadata   []byte    `json:"metadata,omitempty" db:"metadata"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// ============================================================================
// employee statutory profile
// ============================================================================

type EmployeeStatutoryProfile struct {
	ProfileID       uuid.UUID  `json:"profile_id" db:"profile_id"`
	CompanyID       uuid.UUID  `json:"company_id" db:"company_id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	StatutoryCode   string     `json:"statutory_code" db:"statutory_code"`
	OptIn           bool       `json:"opt_in" db:"opt_in"`
	SpecialCategory *string    `json:"special_category,omitempty" db:"special_category"`
	Regime          *string    `json:"regime,omitempty" db:"regime"`
	EffectiveFrom   time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo     *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	IsActive        bool       `json:"is_active" db:"is_active"`
	Version         int        `json:"version" db:"version"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	DeactivatedAt   *time.Time `json:"deactivated_at,omitempty" db:"deactivated_at"`
	DeactivatedBy   *uuid.UUID `json:"deactivated_by,omitempty" db:"deactivated_by"`
	RuleSetID       *uuid.UUID `json:"rule_set_id,omitempty" db:"rule_set_id"`
}

// ============================================================================
// employee statutory contribution
// ============================================================================

type EmployeeStatutoryContribution struct {
	ContributionID uuid.UUID `json:"contribution_id" db:"contribution_id"`
	CompanyID      uuid.UUID `json:"company_id" db:"company_id"`
	UserID         uuid.UUID `json:"user_id" db:"user_id"`
	StatutoryCode  string    `json:"statutory_code" db:"statutory_code"`
	PeriodStart    time.Time `json:"period_start" db:"period_start"`
	PeriodEnd      time.Time `json:"period_end" db:"period_end"`
	EmployeeAmount float64   `json:"employee_amount" db:"employee_amount"`
	EmployerAmount float64   `json:"employer_amount" db:"employer_amount"`
	TotalAmount    float64   `json:"total_amount" db:"total_amount"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type StatutoryContributionSummary struct {
	CompanyID      uuid.UUID `json:"company_id" db:"company_id"`
	StatutoryCode  string    `json:"statutory_code" db:"statutory_code"`
	PeriodStart    time.Time `json:"period_start" db:"period_start"`
	PeriodEnd      time.Time `json:"period_end" db:"period_end"`
	TotalEmployees int       `json:"total_employees" db:"total_employees"`
	TotalAmount    float64   `json:"total_amount" db:"total_amount"`
	EmployeeShare  float64   `json:"employee_share" db:"employee_share"`
	EmployerShare  float64   `json:"employer_share" db:"employer_share"`
	GeneratedAt    time.Time `json:"generated_at" db:"generated_at"`
}

// ============================================================================
// YTD statutory summary
// ============================================================================

type YTDStatutorySummary struct {
	CompanyID          uuid.UUID `json:"company_id"`
	UserID             uuid.UUID `json:"user_id"`
	StatutoryCode      string    `json:"statutory_code"`
	FinancialYearStart time.Time `json:"financial_year_start"`
	AsOf               time.Time `json:"as_of"`
	YTDEmployeeAmount  float64   `json:"ytd_employee_amount"`
	YTDEmployerAmount  float64   `json:"ytd_employer_amount"`
	YTDTotalAmount     float64   `json:"ytd_total_amount"`
}

// ============================================================================
// statutory snapshot (audit‑safe)
// ============================================================================

type StatutoryBreakdownItem struct {
	StatutoryCode    string  `json:"statutory_code"`
	ContributionSide string  `json:"contribution_side"` // employee | employer
	Amount           float64 `json:"amount"`
}

type StatutorySnapshot struct {
	SnapshotID   uuid.UUID
	PayrollRunID uuid.UUID
	CompanyID    uuid.UUID
	UserID       uuid.UUID
	RuleSetID    uuid.UUID
	RuleHash     string
	PeriodStart  time.Time
	PeriodEnd    time.Time
	Breakdown    []StatutoryBreakdownItem
	CreatedAt    time.Time
	CreatedBy    *uuid.UUID
}

// ============================================================================
// payroll period lock & adjustment
// ============================================================================

type PayrollPeriodLock struct {
	LockID      uuid.UUID  `json:"lock_id" db:"lock_id"`
	CompanyID   uuid.UUID  `json:"company_id" db:"company_id"`
	PeriodStart time.Time  `json:"period_start" db:"period_start"`
	PeriodEnd   time.Time  `json:"period_end" db:"period_end"`
	LockedBy    *uuid.UUID `json:"locked_by,omitempty" db:"locked_by"`
	LockedAt    time.Time  `json:"locked_at" db:"locked_at"`
	Reason      *string    `json:"reason,omitempty" db:"reason"`
}

type PayrollAdjustment struct {
	AdjustmentID    uuid.UUID  `json:"adjustment_id" db:"adjustment_id"`
	CompanyID       uuid.UUID  `json:"company_id" db:"company_id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	ComponentCode   string     `json:"component_code" db:"component_code"`
	Amount          float64    `json:"amount" db:"amount"`
	AdjustmentType  string     `json:"adjustment_type" db:"adjustment_type"` // addition / deduction
	Reason          *string    `json:"reason,omitempty" db:"reason"`
	ApplicableMonth time.Time  `json:"applicable_month" db:"applicable_month"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// ============================================================================
// (Deleted models: CompanyStatutoryConfig, CompanyTaxSlab, TaxProfile, TaxRule, CalculatedTax)
// ============================================================================

type StatutoryYTDContext struct {
	FinancialYearStart time.Time
	YTDStatutoryBase   map[string]float64
	YTDStatutoryAmount map[string]float64
}

// ============================================================================
// Statutory Profile Input / Output Types (used by the service interface)
// ============================================================================

type CreateStatutoryProfileInput struct {
	CompanyID     uuid.UUID
	UserID        uuid.UUID
	StatutoryCode string
	OptIn         bool
	EffectiveFrom time.Time
	CreatedBy     uuid.UUID
}

type UpdateStatutoryProfileInput struct {
	ProfileID     uuid.UUID
	OptIn         *bool
	EffectiveFrom time.Time
	UpdatedBy     uuid.UUID
}

type ChangeTaxRegimeInput struct {
	CompanyID     uuid.UUID
	UserID        uuid.UUID
	TaxRegimeCode string
	EffectiveFrom time.Time
	ChangedBy     uuid.UUID
}

type StatutoryProfileFilter struct {
	CompanyID     uuid.UUID
	UserID        *uuid.UUID
	StatutoryCode *string
	ActiveOn      *time.Time
	Page          int
	PageSize      int
}

type StatutoryProfileVersion struct {
	ProfileID     uuid.UUID
	CompanyID     uuid.UUID
	UserID        uuid.UUID
	StatutoryCode string
	OptIn         bool
	EffectiveFrom time.Time
	EffectiveTo   *time.Time
	IsActive      bool
	CreatedAt     time.Time
	CreatedBy     uuid.UUID
}

// ============================================================================
// Dashboard / Analytics structs
// ============================================================================

type PayrollRunDashboard struct {
	RunID           uuid.UUID
	CompanyID       uuid.UUID
	PeriodStart     time.Time
	PeriodEnd       time.Time
	Status          string
	TotalEmployees  int
	ProcessedCount  int
	FailedCount     int
	TotalGross      float64
	TotalNet        float64
	TotalDeductions float64
	TotalEmployer   float64
	CreatedAt       time.Time
}

type PayrollExecutionStatus struct {
	RunID          uuid.UUID
	Status         string
	TotalEmployees int
	ProcessedCount int
	FailedCount    int
	ProgressPct    float64
	LastUpdatedAt  *time.Time
}

type EmployeeYTDSummary struct {
	UserID             uuid.UUID
	TotalGross         float64
	TotalNet           float64
	TotalDeductions    float64
	TotalTax           float64
	TotalEmployer      float64
	ComponentBreakdown []LedgerSummary
}

type EmployeeStatutorySummary struct {
	UserID                uuid.UUID
	EmployeeContributions map[string]float64
	EmployerContributions map[string]float64
	TotalEmployee         float64
	TotalEmployer         float64
}

type StatutoryAggregate struct {
	StatutoryCode string
	EmployeeTotal float64
	EmployerTotal float64
	CombinedTotal float64
}

type PayrollTrendPoint struct {
	PeriodStart time.Time
	PeriodEnd   time.Time
	TotalGross  float64
	TotalNet    float64
}

type ComponentTrendPoint struct {
	PeriodStart   time.Time
	ComponentCode string
	TotalAmount   float64
}

// ============================================================================
// Payroll Adjustment Inputs
// ============================================================================

type CreatePayrollAdjustmentInput struct {
	CompanyID       uuid.UUID
	UserID          uuid.UUID
	ComponentCode   string
	Amount          float64
	AdjustmentType  string
	Reason          string
	ApplicableMonth time.Time
	CreatedBy       uuid.UUID
}

type UpdatePayrollAdjustmentInput struct {
	AdjustmentID uuid.UUID
	Amount       *float64
	Reason       *string
	UpdatedBy    uuid.UUID
}

type PayrollAdjustmentFilter struct {
	CompanyID      uuid.UUID
	UserID         *uuid.UUID
	ComponentCode  *string
	AdjustmentType *string
	FromMonth      *time.Time
	ToMonth        *time.Time
	Page           int
	PageSize       int
}

// ============================================================================
// Salary Structure Input / Output Types
// ============================================================================

type CreateSalaryStructureInput struct {
	CompanyID     uuid.UUID
	StructureName string
	CurrencyCode  string
	CreatedBy     uuid.UUID
}

type UpdateSalaryStructureInput struct {
	StructureID   uuid.UUID
	CompanyID     uuid.UUID
	StructureName string
	CurrencyCode  string
	UpdatedBy     uuid.UUID
}

type SalaryStructureDetail struct {
	SalaryStructure
	Components []SalaryStructureComponent `json:"components"`
}

type SalaryStructureFilter struct {
	CompanyID       uuid.UUID
	IncludeInactive bool
}

type AddSalaryStructureComponentInput struct {
	StructureID      uuid.UUID
	CompanyID        uuid.UUID // needed for ownership validation
	ComponentCode    string
	CalculationType  string
	Value            float64
	BasedOnComponent *string
	SequenceOrder    int
}

type UpdateSalaryStructureComponentInput struct {
	MappingID     uuid.UUID
	Value         float64
	SequenceOrder int
}

type AssignSalaryStructureInput struct {
	CompanyID     uuid.UUID
	UserID        uuid.UUID
	StructureID   uuid.UUID
	MonthlyCTC    float64
	PayType       string
	EffectiveFrom time.Time
	ActorID       uuid.UUID
}

type BulkAssignSalaryStructureInput struct {
	CompanyID     uuid.UUID
	UserIDs       []uuid.UUID
	StructureID   uuid.UUID
	MonthlyCTC    float64
	PayType       string
	EffectiveFrom time.Time
	ActorID       uuid.UUID
}

type ChangeSalaryStructureInput struct {
	CompanyID      uuid.UUID
	UserID         uuid.UUID
	NewStructureID uuid.UUID
	MonthlyCTC     float64
	PayType        string
	EffectiveFrom  time.Time
	ActorID        uuid.UUID
}

type EmployeeSalaryStructure struct {
	EmployeeSalary
}

type StructureStatus string

const (
	StructureDraft     StructureStatus = "draft"
	StructurePublished StructureStatus = "published"
	StructureArchived  StructureStatus = "archived"
)

// ============================================================================
// Statutory Rule Set Inputs
// ============================================================================

type CreateStatutoryRuleSetInput struct {
	CompanyID     uuid.UUID
	CountryCode   string
	VersionLabel  string
	EffectiveFrom time.Time
	CreatedBy     uuid.UUID
}

type UpdateStatutoryRuleSetInput struct {
	RuleSetID     uuid.UUID
	CompanyID     uuid.UUID
	VersionLabel  string
	EffectiveFrom time.Time
	UpdatedBy     uuid.UUID
}

// ============================================================================
// Attendance Rule & Employee Fine (updated with ComponentCode)
// ============================================================================

type AttendanceRule struct {
	RuleID           uuid.UUID  `json:"rule_id" db:"rule_id"`
	CompanyID        uuid.UUID  `json:"company_id" db:"company_id"`
	RuleType         string     `json:"rule_type" db:"rule_type"`                 // overtime | late | absent
	CalculationType  string     `json:"calculation_type" db:"calculation_type"`   // percentage | flat | multiplier
	Value            float64    `json:"value" db:"value"`                         // numeric(10,4)
	BasedOn          *string    `json:"based_on,omitempty" db:"based_on"`         // daily | hourly (nullable)
	ThresholdMinutes int        `json:"threshold_minutes" db:"threshold_minutes"` // default 0
	ComponentCode    string     `json:"component_code" db:"component_code"`       // NEW: link to payroll_component
	IsActive         bool       `json:"is_active" db:"is_active"`                 // default true
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`               // default now()
	CreatedBy        *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty" db:"updated_at"`
	UpdatedBy        *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

type EmployeeFine struct {
	FineID        uuid.UUID  `json:"fine_id" db:"fine_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	ComponentCode string     `json:"component_code" db:"component_code"` // NEW
	FineAmount    float64    `json:"fine_amount" db:"fine_amount"`       // numeric(12,2)
	Reason        string     `json:"reason" db:"reason"`
	FineDate      time.Time  `json:"fine_date" db:"fine_date"`       // date
	IsProcessed   bool       `json:"is_processed" db:"is_processed"` // default false
	PayrollRunID  *uuid.UUID `json:"payroll_run_id,omitempty" db:"payroll_run_id"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"` // default now()
	CreatedBy     uuid.UUID  `json:"created_by" db:"created_by"` // NOT NULL
}

type AttendanceRuleFilter struct {
	CompanyID    uuid.UUID
	RuleType     *string
	IsActive     *bool
	BasedOn      *string
	MinThreshold *int
	Page         int
	PageSize     int
}

type EmployeeFineFilter struct {
	CompanyID    uuid.UUID
	UserID       *uuid.UUID
	IsProcessed  *bool
	PayrollRunID *uuid.UUID
	FromDate     *time.Time
	ToDate       *time.Time
	Page         int
	PageSize     int
}

// ============================================================================
// Statutory Contribution Rule Inputs
// ============================================================================

type SetStatutoryContributionInput struct {
	CompanyID       uuid.UUID
	RuleSetID       uuid.UUID
	StatutoryCode   string
	EmployeeRate    *float64
	EmployerRate    *float64
	CalculationType string // percentage | fixed
	WageCeiling     *float64
	MinThreshold    *float64
	EffectiveFrom   time.Time
	ActorID         uuid.UUID
}

type CreateRuleSetInput struct {
	CompanyID     uuid.UUID
	CountryCode   string
	VersionLabel  string
	EffectiveFrom time.Time
	ActorID       uuid.UUID
}

type UpdateRuleSetInput struct {
	RuleSetID     uuid.UUID
	CompanyID     uuid.UUID
	VersionLabel  string
	EffectiveFrom time.Time
	EffectiveTo   *time.Time
	IsActive      bool
}

// ============================================================================
// statutory_component_definition (with soft‑delete)
// ============================================================================

type StatutoryComponentDefinition struct {
	CompanyID               uuid.UUID  `json:"company_id" db:"company_id"`
	StatutoryCode           string     `json:"statutory_code" db:"statutory_code"`
	Description             string     `json:"description" db:"description"`
	CountryCode             string     `json:"country_code" db:"country_code"`
	CalculationBasis        string     `json:"calculation_basis" db:"calculation_basis"`
	HasEmployeeContribution bool       `json:"has_employee_contribution" db:"has_employee_contribution"`
	HasEmployerContribution bool       `json:"has_employer_contribution" db:"has_employer_contribution"`
	IsActive                bool       `json:"is_active" db:"is_active"`
	DeactivatedAt           *time.Time `json:"deactivated_at,omitempty" db:"deactivated_at"`
	DeactivatedBy           *uuid.UUID `json:"deactivated_by,omitempty" db:"deactivated_by"`
	CreatedAt               time.Time  `json:"created_at" db:"created_at"`
}

// ============================================================================
// statutory_contribution_rule
// ============================================================================

type StatutoryContributionRule struct {
	RuleID           uuid.UUID  `json:"rule_id" db:"rule_id"`
	CompanyID        uuid.UUID  `json:"company_id" db:"company_id"`
	RuleSetID        uuid.UUID  `json:"rule_set_id" db:"rule_set_id"`
	StatutoryCode    string     `json:"statutory_code" db:"statutory_code"`
	ContributionSide string     `json:"contribution_side" db:"contribution_side"`
	CalculationType  string     `json:"calculation_type" db:"calculation_type"`
	RateValue        *float64   `json:"rate_value,omitempty" db:"rate_value"`
	WageCeiling      *float64   `json:"wage_ceiling,omitempty" db:"wage_ceiling"`
	MinThreshold     *float64   `json:"min_threshold,omitempty" db:"min_threshold"`
	EffectiveFrom    time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo      *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	IsActive         bool       `json:"is_active" db:"is_active"`
	Version          int        `json:"version" db:"version"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	DeactivatedAt    *time.Time `json:"deactivated_at,omitempty" db:"deactivated_at"`
	DeactivatedBy    *uuid.UUID `json:"deactivated_by,omitempty" db:"deactivated_by"`
}

// ============================================================================
// Inputs for statutory components
// ============================================================================

type CreateStatutoryContributionRuleInput struct {
	CompanyID        uuid.UUID
	RuleSetID        uuid.UUID
	StatutoryCode    string
	ContributionSide string
	CalculationType  string
	RateValue        *float64
	WageCeiling      *float64
	MinThreshold     *float64
	EffectiveFrom    time.Time
	ActorID          uuid.UUID
}

type CreateStatutoryComponentDefinitionInput struct {
	CompanyID        uuid.UUID
	StatutoryCode    string
	Description      string
	CountryCode      string
	CalculationBasis string
	HasEmployee      bool
	HasEmployer      bool
	ActorID          uuid.UUID
}

type StatutoryComponentDefinitionFilter struct {
	CompanyID   uuid.UUID
	CountryCode *string
}

// ============================================================================
// Tax Slab inputs
// ============================================================================

type CreateTaxSlabInput struct {
	CompanyID     uuid.UUID
	StatutoryCode string
	MinAmount     float64
	MaxAmount     *float64
	Rate          float64
	IsPercentage  bool
	SlabOrder     int
	EffectiveFrom time.Time
	RuleSetID     uuid.UUID
	CreatedBy     uuid.UUID
}

type UpdateTaxSlabInput struct {
	SlabID        uuid.UUID
	MinAmount     *float64
	MaxAmount     *float64
	Rate          *float64
	IsPercentage  *bool
	SlabOrder     *int
	EffectiveFrom *time.Time
	UpdatedBy     uuid.UUID
}

// ============================================================================
// Deduction Limit inputs
// ============================================================================

type CreateDeductionLimitInput struct {
	CompanyID  uuid.UUID
	RuleSetID  uuid.UUID
	LimitCode  string
	LimitValue float64
	Metadata   map[string]interface{}
}

type UpdateDeductionLimitInput struct {
	LimitID    uuid.UUID
	LimitValue *float64
	Metadata   map[string]interface{} // if nil, metadata is not updated; if non-nil, replaces existing
}

// ============================================================================
// Component Mapping inputs
// ============================================================================

type CreateComponentMappingInput struct {
	CompanyID     uuid.UUID
	StatutoryCode string
	ComponentCode string
	EffectiveFrom time.Time
	RuleSetID     uuid.UUID
	CreatedBy     uuid.UUID
}

type UpdateComponentMappingInput struct {
	MappingID     uuid.UUID
	ComponentCode *string
	EffectiveFrom *time.Time
	Version       int // current version for optimistic locking
	UpdatedBy     uuid.UUID
}

// ============================================================================
// New tables from SQL (already present above, but listed here for completeness)
// ============================================================================

// EmployeeBankDetails (payroll.employee_bank_details)
type EmployeeBankDetails struct {
	BankDetailID  uuid.UUID  `json:"bank_detail_id" db:"bank_detail_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	AccountHolder string     `json:"account_holder" db:"account_holder"`
	AccountNumber string     `json:"account_number" db:"account_number"` // encrypted
	IFSCCode      string     `json:"ifsc_code" db:"ifsc_code"`
	BankName      string     `json:"bank_name,omitempty" db:"bank_name"`
	Branch        string     `json:"branch,omitempty" db:"branch"`
	AccountType   string     `json:"account_type,omitempty" db:"account_type"` // savings, current
	IsActive      bool       `json:"is_active" db:"is_active"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// EmployeeLoan (payroll.employee_loan) – updated with ComponentCode
// EmployeeLoan (payroll.employee_loan)
type EmployeeLoan struct {
	LoanID    uuid.UUID `json:"loan_id" db:"loan_id"`
	CompanyID uuid.UUID `json:"company_id" db:"company_id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`

	ComponentCode string `json:"component_code" db:"component_code"`

	LoanType string `json:"loan_type" db:"loan_type"` // loan | advance

	PrincipalAmount float64 `json:"principal_amount" db:"principal_amount"`

	InterestRate *float64 `json:"interest_rate,omitempty" db:"interest_rate"`

	InterestType *string `json:"interest_type,omitempty" db:"interest_type"` // flat | compound

	TotalEmis int `json:"total_emis" db:"total_emis"`

	EmiAmount float64 `json:"emi_amount" db:"emi_amount"`

	OutstandingBalance float64 `json:"outstanding_balance" db:"outstanding_balance"`

	EmisPaid   int `json:"emis_paid" db:"emis_paid"`
	EmisMissed int `json:"emis_missed" db:"emis_missed"`

	DisbursedAt  time.Time `json:"disbursed_at" db:"disbursed_at"`
	FirstEmiDate time.Time `json:"first_emi_date" db:"first_emi_date"`

	ClosureDate *time.Time `json:"closure_date,omitempty" db:"closure_date"`

	Status string `json:"status" db:"status"` // active | closed | defaulted

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// EmiTransaction (payroll.emi_transaction)
type EmiTransaction struct {
	EmiID  uuid.UUID `json:"emi_id" db:"emi_id"`
	LoanID uuid.UUID `json:"loan_id" db:"loan_id"`

	DueDate time.Time `json:"due_date" db:"due_date"`

	PaidDate *time.Time `json:"paid_date,omitempty" db:"paid_date"`

	Amount float64 `json:"amount" db:"amount"`

	PaidAmount float64 `json:"paid_amount" db:"paid_amount"`

	PenaltyAmount float64 `json:"penalty_amount" db:"penalty_amount"`

	OutstandingAmount float64 `json:"outstanding_amount" db:"outstanding_amount"`

	PaymentStatus string `json:"payment_status" db:"payment_status"` // on_time | late

	Status string `json:"status" db:"status"` // pending | paid | missed | partial | waived

	PayrollRunID *uuid.UUID `json:"payroll_run_id,omitempty" db:"payroll_run_id"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// EmiTransaction (payroll.emi_transaction)

// Arrears (payroll.arrears) – updated with ComponentCode
type Arrears struct {
	ArrearsID     uuid.UUID  `json:"arrears_id" db:"arrears_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	ComponentCode string     `json:"component_code" db:"component_code"` // NEW
	PayrollRunID  *uuid.UUID `json:"payroll_run_id,omitempty" db:"payroll_run_id"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   time.Time  `json:"effective_to" db:"effective_to"`
	Amount        float64    `json:"amount" db:"amount"`
	Reason        *string    `json:"reason,omitempty" db:"reason"`
	Processed     bool       `json:"processed" db:"processed"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

// TaxDeclarationType (payroll.tax_declaration_type)
type TaxDeclarationType struct {
	CompanyID   uuid.UUID `json:"company_id" db:"company_id"`
	TypeCode    string    `json:"type_code" db:"type_code"`
	Description string    `json:"description" db:"description"`
	MaxLimit    *float64  `json:"max_limit,omitempty" db:"max_limit"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// TaxDeclaration (payroll.tax_declaration)
type TaxDeclaration struct {
	DeclarationID   uuid.UUID  `json:"declaration_id" db:"declaration_id"`
	CompanyID       uuid.UUID  `json:"company_id" db:"company_id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	FinancialYear   string     `json:"financial_year" db:"financial_year"` // e.g., "2024-25"
	DeclarationType string     `json:"declaration_type" db:"declaration_type"`
	Amount          float64    `json:"amount" db:"amount"`
	SupportingDocs  []string   `json:"supporting_docs,omitempty" db:"supporting_docs"` // array of object keys
	Status          string     `json:"status" db:"status"`                             // pending, verified, rejected
	SubmittedAt     time.Time  `json:"submitted_at" db:"submitted_at"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	VerifiedBy      *uuid.UUID `json:"verified_by,omitempty" db:"verified_by"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// ============================================================================
// NEW: CompanyPayrollSettings – company‑level default component codes
// ============================================================================

type CompanyPayrollSettings struct {
	CompanyID               uuid.UUID `json:"company_id" db:"company_id"`
	DefaultFineComponent    *string   `json:"default_fine_component" db:"default_fine_component"`
	DefaultArrearsComponent *string   `json:"default_arrears_component" db:"default_arrears_component"`
	DefaultLoanComponent    *string   `json:"default_loan_component" db:"default_loan_component"`
	DefaultBasicComponent   *string   `json:"default_basic_component" db:"default_basic_component"`
	CreatedAt               time.Time `json:"created_at" db:"created_at"`
	UpdatedAt               time.Time `json:"updated_at" db:"updated_at"`
}

// Payroll Job statuses
const (
	PayrollJobStatusQueued     = "queued"
	PayrollJobStatusProcessing = "processing"
	PayrollJobStatusCompleted  = "completed"
	PayrollJobStatusFailed     = "failed"
)

// ============================================================================
// payroll_job (background payroll execution)
// ============================================================================

type PayrollJob struct {
	JobID        uuid.UUID `json:"job_id" db:"job_id"`
	CompanyID    uuid.UUID `json:"company_id" db:"company_id"`
	PayrollRunID uuid.UUID `json:"payroll_run_id" db:"payroll_run_id"`

	Status       string  `json:"status" db:"status"` // queued | processing | completed | failed
	Attempts     int     `json:"attempts" db:"attempts"`
	MaxAttempts  int     `json:"max_attempts" db:"max_attempts"`
	Priority     int     `json:"priority" db:"priority"` // lower = higher priority
	RetryCount   int     `json:"retry_count" db:"retry_count"`
	MaxRetries   int     `json:"max_retries" db:"max_retries"`
	ErrorMessage *string `json:"error_message,omitempty" db:"error_message"`

	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty" db:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	NextRunAt   *time.Time `json:"next_run_at,omitempty" db:"next_run_at"`

	LockedBy *string    `json:"locked_by,omitempty" db:"locked_by"`
	LockedAt *time.Time `json:"locked_at,omitempty" db:"locked_at"`
}

type CreatePayrollJobInput struct {
	CompanyID    uuid.UUID
	PayrollRunID uuid.UUID

	MaxAttempts int
	MaxRetries  int
	Priority    int
}

// ============================================================================
// Payroll Component Inputs (for service methods)
// ============================================================================

type CreateComponentInput struct {
	CompanyID        uuid.UUID
	ComponentCode    string
	ComponentType    string
	Description      string
	IsTaxable        bool
	IsSystem         bool // will be rejected in service – system components cannot be created via API
	ContributionSide string
}

type UpdateComponentInput struct {
	CompanyID        uuid.UUID
	ComponentCode    string
	Description      string
	IsTaxable        bool
	IsActive         bool
	ContributionSide string
}

// Loan interest types
const (
	LoanInterestTypeFlat     = "flat"
	LoanInterestTypeCompound = "compound"
)

// EMI status
const (
	EmiStatusMissed  = "missed"
	EmiStatusPartial = "partial"
)

// Loan payment status
const (
	LoanPaymentOnTime = "on_time"
	LoanPaymentLate   = "late"
)

type LoanPayment struct {
	PaymentID uuid.UUID `json:"payment_id" db:"payment_id"`

	LoanID uuid.UUID `json:"loan_id" db:"loan_id"`

	EmiID *uuid.UUID `json:"emi_id,omitempty" db:"emi_id"`

	Amount float64 `json:"amount" db:"amount"`

	Penalty float64 `json:"penalty" db:"penalty"`

	PaidAt time.Time `json:"paid_at" db:"paid_at"`

	Source string `json:"source" db:"source"` // payroll | manual

	PayrollRunID *uuid.UUID `json:"payroll_run_id,omitempty" db:"payroll_run_id"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ============================================================================
// payroll_employee_job
// ============================================================================

const (
	EmployeeJobStatusPending    = "pending"
	EmployeeJobStatusProcessing = "processing"
	EmployeeJobStatusCompleted  = "completed"
	EmployeeJobStatusFailed     = "failed"
)

type PayrollEmployeeJob struct {
	JobID        uuid.UUID `json:"job_id" db:"job_id"`
	PayrollRunID uuid.UUID `json:"payroll_run_id" db:"payroll_run_id"`
	UserID       uuid.UUID `json:"user_id" db:"user_id"`

	Status   string `json:"status" db:"status"`
	Attempts int    `json:"attempts" db:"attempts"`

	LockedBy *string    `json:"locked_by,omitempty" db:"locked_by"`
	LockedAt *time.Time `json:"locked_at,omitempty" db:"locked_at"`

	Error *string `json:"error,omitempty" db:"error"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type PayslipComponent struct {
	Code        string  `json:"code"`
	Description string  `json:"description"`
	Amount      float64 `json:"amount"`
}

type PayslipData struct {
	// Company
	CompanyID   uuid.UUID
	CompanyName string

	// Employee
	UserID       uuid.UUID
	EmployeeName string
	EmployeeID   string
	Department   string
	Position     string

	// Payroll Run
	PayrollRunID uuid.UUID
	PeriodStart  time.Time
	PeriodEnd    time.Time

	// Financials
	GrossAmount float64
	NetAmount   float64
	Earnings    []PayslipComponent
	Deductions  []PayslipComponent

	// Bank Details (optional)
	BankDetails *struct {
		AccountHolder string
		AccountNumber string
		IFSCCode      string
		BankName      string
	}

	// Template
	FooterDeclaration   string
	AuthorizedSignatory string
	GeneratedAt         time.Time
}

type PayslipRecord struct {
	PayslipID    uuid.UUID  `db:"payslip_id"`
	PayrollRunID uuid.UUID  `db:"payroll_run_id"`
	UserID       uuid.UUID  `db:"user_id"`
	PDFObjectKey string     `db:"pdf_object_key"`
	GeneratedAt  time.Time  `db:"generated_at"`
	SentAt       *time.Time `db:"sent_at"`
}

type PayslipTemplate struct {
	TemplateID          uuid.UUID `db:"template_id"`
	CompanyID           uuid.UUID `db:"company_id"`
	TemplateName        string    `db:"template_name"`
	FooterDeclaration   *string   `db:"footer_declaration"`
	AuthorizedSignatory *string   `db:"authorized_signatory"`
	CreatedAt           time.Time `db:"created_at"`
}
