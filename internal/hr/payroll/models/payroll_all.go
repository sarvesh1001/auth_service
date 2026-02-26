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
	PayrollStatusDraft      = "draft"
	PayrollStatusCalculated = "calculated"
	PayrollStatusApproved   = "approved"
	PayrollStatusPaid       = "paid"

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
)

// ============================================================================
// payroll_component
// ============================================================================

type PayrollComponent struct {
	ComponentCode    string `json:"component_code" db:"component_code"`
	ComponentType    string `json:"component_type" db:"component_type"`
	Description      string `json:"description,omitempty" db:"description"`
	IsTaxable        bool   `json:"is_taxable" db:"is_taxable"`
	IsSystem         bool   `json:"is_system" db:"is_system"`
	IsActive         bool   `json:"is_active" db:"is_active"`
	ContributionSide string `json:"contribution_side" db:"contribution_side"` // new
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
	PayType    string                     `json:"pay_type"` // ⭐ ADD THIS
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

	PayType string `json:"pay_type" db:"pay_type"` // ⭐ NEW FIELD

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
	ContributionSide string  `json:"contribution_side"` // new
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

type PayslipComponent struct {
	Code        string  `json:"code"`
	Description string  `json:"description"`
	Amount      float64 `json:"amount"`
}

type PayslipTemplate struct {
	TemplateID          uuid.UUID `json:"template_id" db:"template_id"`
	CompanyID           uuid.UUID `json:"company_id" db:"company_id"`
	TemplateName        string    `json:"template_name" db:"template_name"`
	FooterDeclaration   *string   `json:"footer_declaration,omitempty" db:"footer_declaration"`
	AuthorizedSignatory *string   `json:"authorized_signatory,omitempty" db:"authorized_signatory"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
}

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
// statutory rate
// ============================================================================

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
// statutory threshold
// ============================================================================

// ============================================================================
// statutory deduction limit (NEW)
// ============================================================================

type StatutoryDeductionLimit struct {
	LimitID       uuid.UUID  `db:"limit_id" json:"limit_id"`
	CompanyID     uuid.UUID  `db:"company_id" json:"company_id"`
	RuleSetID     uuid.UUID  `db:"rule_set_id" json:"rule_set_id"`
	LimitCode     string     `db:"limit_code" json:"limit_code"`
	LimitValue    float64    `db:"limit_value" json:"limit_value"`
	Metadata      []byte     `db:"metadata" json:"metadata,omitempty"`
	IsActive      bool       `db:"is_active" json:"is_active"`
	DeactivatedAt *time.Time `db:"deactivated_at" json:"deactivated_at,omitempty"`
	DeactivatedBy *uuid.UUID `db:"deactivated_by" json:"deactivated_by,omitempty"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
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
// YTD statutory summary (NEW)
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
// statutory snapshot (NEW, audit‑safe)
// ============================================================================

type StatutoryBreakdownItem struct {
	StatutoryCode    string  `json:"statutory_code"`
	ContributionSide string  `json:"contribution_side"` // employee | employer
	Amount           float64 `json:"amount"`
}

type StatutorySnapshot struct {
	SnapshotID   uuid.UUID
	PayrollRunID uuid.UUID // 🔥 ADD THIS
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
type PayrollRunDashboard struct {
	RunID       uuid.UUID
	CompanyID   uuid.UUID
	PeriodStart time.Time
	PeriodEnd   time.Time
	Status      string

	TotalEmployees int
	ProcessedCount int
	FailedCount    int

	TotalGross      float64
	TotalNet        float64
	TotalDeductions float64
	TotalEmployer   float64

	CreatedAt time.Time
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
	UserID uuid.UUID

	TotalGross      float64
	TotalNet        float64
	TotalDeductions float64
	TotalTax        float64
	TotalEmployer   float64

	ComponentBreakdown []LedgerSummary
}
type EmployeeStatutorySummary struct {
	UserID uuid.UUID

	EmployeeContributions map[string]float64
	EmployerContributions map[string]float64

	TotalEmployee float64
	TotalEmployer float64
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

	TotalGross float64
	TotalNet   float64
}
type ComponentTrendPoint struct {
	PeriodStart   time.Time
	ComponentCode string
	TotalAmount   float64
}

const (
	ContributionSideEmployee = "employee"
	ContributionSideEmployer = "employer"
	ContributionSideNone     = "none"
)

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
	// ComponentCode and CalculationType are usually immutable once added
}

type AssignSalaryStructureInput struct {
	CompanyID     uuid.UUID
	UserID        uuid.UUID
	StructureID   uuid.UUID
	MonthlyCTC    float64
	PayType       string // ⭐ NEW
	EffectiveFrom time.Time
	ActorID       uuid.UUID
}

type BulkAssignSalaryStructureInput struct {
	CompanyID     uuid.UUID
	UserIDs       []uuid.UUID
	StructureID   uuid.UUID
	MonthlyCTC    float64
	PayType       string // ⭐ NEW
	EffectiveFrom time.Time
	ActorID       uuid.UUID
}

type ChangeSalaryStructureInput struct {
	CompanyID      uuid.UUID
	UserID         uuid.UUID
	NewStructureID uuid.UUID
	MonthlyCTC     float64
	PayType        string // ⭐ NEW
	EffectiveFrom  time.Time
	ActorID        uuid.UUID
}

type EmployeeSalaryStructure struct {
	EmployeeSalary
	// optionally include structure snapshot
	// Structure *SalaryStructureSnapshot `json:"structure,omitempty"`
}
type StructureStatus string

const (
	StructureDraft     StructureStatus = "draft"
	StructurePublished StructureStatus = "published"
	StructureArchived  StructureStatus = "archived"
)

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
// Pay Types (NEW)
// ============================================================================

const (
	PayTypeMonthly   = "monthly"
	PayTypeDailyWage = "daily_wage"
	PayTypeHourly    = "hourly"
)

// ============================================================================
// Attendance Rule Constants
// ============================================================================

const (
	RuleTypeOvertime = "overtime"
	RuleTypeLate     = "late"
	RuleTypeAbsent   = "absent"

	CalculationTypeMultiplier = "multiplier"

	BasedOnDaily  = "daily"
	BasedOnHourly = "hourly"
)

// ============================================================================
// payroll.attendance_rule
// ============================================================================

type AttendanceRule struct {
	RuleID           uuid.UUID  `json:"rule_id" db:"rule_id"`
	CompanyID        uuid.UUID  `json:"company_id" db:"company_id"`
	RuleType         string     `json:"rule_type" db:"rule_type"`                 // overtime | late | absent
	CalculationType  string     `json:"calculation_type" db:"calculation_type"`   // percentage | flat | multiplier
	Value            float64    `json:"value" db:"value"`                         // numeric(10,4)
	BasedOn          *string    `json:"based_on,omitempty" db:"based_on"`         // daily | hourly (nullable)
	ThresholdMinutes int        `json:"threshold_minutes" db:"threshold_minutes"` // default 0
	IsActive         bool       `json:"is_active" db:"is_active"`                 // default true
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`               // default now()
	CreatedBy        *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty" db:"updated_at"`
	UpdatedBy        *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

// ============================================================================
// payroll.employee_fine
// ============================================================================

type EmployeeFine struct {
	FineID       uuid.UUID  `json:"fine_id" db:"fine_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	FineAmount   float64    `json:"fine_amount" db:"fine_amount"` // numeric(12,2)
	Reason       string     `json:"reason" db:"reason"`
	FineDate     time.Time  `json:"fine_date" db:"fine_date"`       // date
	IsProcessed  bool       `json:"is_processed" db:"is_processed"` // default false
	PayrollRunID *uuid.UUID `json:"payroll_run_id,omitempty" db:"payroll_run_id"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"` // default now()
	CreatedBy    uuid.UUID  `json:"created_by" db:"created_by"` // NOT NULL
}

// Optional: filter structs if needed (not requested, but can be added)

// ============================================================================
// AttendanceRuleFilter
// ============================================================================

type AttendanceRuleFilter struct {
	CompanyID    uuid.UUID
	RuleType     *string
	IsActive     *bool
	BasedOn      *string
	MinThreshold *int
	Page         int // <-- ADD THIS
	PageSize     int // <-- ADD THIS
}

// ============================================================================
// EmployeeFineFilter
// ============================================================================

type EmployeeFineFilter struct {
	CompanyID    uuid.UUID
	UserID       *uuid.UUID
	IsProcessed  *bool
	PayrollRunID *uuid.UUID
	FromDate     *time.Time
	ToDate       *time.Time
	Page         int // <-- ADD THIS
	PageSize     int // <-- ADD THIS
}

type SetStatutoryContributionInput struct {
	CompanyID     uuid.UUID
	RuleSetID     uuid.UUID
	StatutoryCode string

	EmployeeRate *float64
	EmployerRate *float64

	CalculationType string // percentage | fixed

	WageCeiling  *float64
	MinThreshold *float64

	EffectiveFrom time.Time
	ActorID       uuid.UUID
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
// Statutory Constants (NEW - SAP Style)
// ============================================================================

const (
	CalculationTypeSlab = "slab"

	StatutoryCalculationBasisBasic = "basic"
	StatutoryCalculationBasisGross = "gross"
	StatutoryCalculationBasisCTC   = "ctc"
)

// ============================================================================
// statutory_component_definition (NEW)
// ============================================================================

type StatutoryComponentDefinition struct {
	CompanyID               uuid.UUID `json:"company_id" db:"company_id"`
	StatutoryCode           string    `json:"statutory_code" db:"statutory_code"`
	Description             string    `json:"description" db:"description"`
	CountryCode             string    `json:"country_code" db:"country_code"`
	CalculationBasis        string    `json:"calculation_basis" db:"calculation_basis"`
	HasEmployeeContribution bool      `json:"has_employee_contribution" db:"has_employee_contribution"`
	HasEmployerContribution bool      `json:"has_employer_contribution" db:"has_employer_contribution"`
	CreatedAt               time.Time `json:"created_at" db:"created_at"`
}

// ============================================================================
// statutory_contribution_rule (NEW - CORE)
// ============================================================================

type StatutoryContributionRule struct {
	RuleID        uuid.UUID `json:"rule_id" db:"rule_id"`
	CompanyID     uuid.UUID `json:"company_id" db:"company_id"`
	RuleSetID     uuid.UUID `json:"rule_set_id" db:"rule_set_id"`
	StatutoryCode string    `json:"statutory_code" db:"statutory_code"`

	ContributionSide string   `json:"contribution_side" db:"contribution_side"`
	CalculationType  string   `json:"calculation_type" db:"calculation_type"`
	RateValue        *float64 `json:"rate_value,omitempty" db:"rate_value"`

	WageCeiling  *float64 `json:"wage_ceiling,omitempty" db:"wage_ceiling"`
	MinThreshold *float64 `json:"min_threshold,omitempty" db:"min_threshold"`

	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`

	IsActive bool `json:"is_active" db:"is_active"`
	Version  int  `json:"version" db:"version"`

	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty" db:"deactivated_at"`
	DeactivatedBy *uuid.UUID `json:"deactivated_by,omitempty" db:"deactivated_by"`
}

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

// Tax Slab inputs
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

// Deduction Limit inputs
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

// Component Mapping inputs
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
