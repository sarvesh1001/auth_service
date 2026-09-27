package errors

import "errors"

var (
	ErrEmployeeProfileNotFound      = errors.New("employee profile: not found")
	ErrDepartmentHistoryNotFound    = errors.New("department history: not found")
	ErrNoActiveDepartmentAssignment = errors.New("employee: no active department assignment")
	ErrEmployeeDocumentNotFound     = errors.New("employee document: not found")
	ErrEmployeeExitNotFound         = errors.New("employee exit: not found")
	ErrPositionNotFound             = errors.New("position: not found")
	ErrRoleHistoryNotFound          = errors.New("role history: not found")
	ErrCompanyEmployeeNotFound      = errors.New("company employee: not found")
	ErrAttendanceIdentityNotFound   = errors.New("attendance identity: not found")
	// Org Unit errors
	ErrOrgUnitNotFound       = errors.New("org unit: not found")
	ErrOrgUnitAlreadyExists  = errors.New("org unit: already exists")
	ErrOrgUnitMemberNotFound = errors.New("org unit member: not found")
	ErrOrgUnitRoleNotFound   = errors.New("org unit role: not found")

	// Leave management
	ErrLeavePolicyNotFound          = errors.New("leave policy: not found")
	ErrLeaveTypeNotFound            = errors.New("leave type: not found")
	ErrLeaveEntitlementNotFound     = errors.New("leave entitlement: not found")
	ErrLeaveRequestNotFound         = errors.New("leave request: not found")
	ErrLeaveAccrualNotFound         = errors.New("leave accrual: not found")
	ErrLeaveBalanceSnapshotNotFound = errors.New("leave balance snapshot: not found")
	ErrLeavePolicyRuleNotFound      = errors.New("leave policy rule: not found")

	ErrArrearsNotFound         = errors.New("payroll arrears: not found")
	ErrAttendanceRuleNotFound  = errors.New("attendance rule: not found")
	ErrBankDetailsNotFound     = errors.New("bank details: not found")
	ErrPayrollSettingsNotFound = errors.New("payroll settings: not found")
	// Compensation / Payroll
	ErrEmployeeSalaryNotFound           = errors.New("employee salary: not found")
	ErrSalaryStructureNotFound          = errors.New("salary structure: not found")
	ErrSalaryStructureComponentNotFound = errors.New("salary structure component: not found")
	ErrPayrollComponentNotFound         = errors.New("payroll component: not found")
	ErrSalaryOverlap                    = errors.New("salary assignment overlaps with existing active assignment")
	ErrVersionMismatch                  = errors.New("version mismatch: record was modified by another process")
	ErrEmployeeFineNotFound             = errors.New("employee fine: not found")
	ErrPayrollRunNotFound               = errors.New("payroll run: not found")
	ErrPayrollItemNotFound              = errors.New("payroll item: not found")
	ErrPayrollAdjustmentNotFound        = errors.New("payroll adjustment: not found")
	ErrPayrollPeriodLockNotFound        = errors.New("payroll period lock: not found")
	ErrPayrollLedgerNotFound            = errors.New("payroll ledger entry: not found")
	ErrPayrollSnapshotNotFound          = errors.New("payroll snapshot: not found")

	// Loan / EMI errors
	ErrLoanNotFound        = errors.New("loan: not found")
	ErrEMINotFound         = errors.New("EMI: not found")
	ErrLoanPaymentNotFound = errors.New("loan payment: not found")
	ErrPayrollJobNotFound  = errors.New("payroll job: not found")
	// Add these two:
	ErrOrgUnitPrimaryAlreadyExists = errors.New("org unit: primary assignment already exists")
	ErrOrgUnitRoleAlreadyExists    = errors.New("org unit role: already exists")

	ErrPayslipNotFound                 = errors.New("payslip: not found")
	ErrPayslipTemplateNotFound         = errors.New("payslip template: not found")
	ErrSalaryStructureVersionMismatch  = errors.New("salary structure: version mismatch")
	ErrSalaryStructureInUse            = errors.New("salary structure: in use by employee")
	ErrStatutoryProfileNotFound        = errors.New("statutory profile: not found")
	ErrStatutoryProfileVersionMismatch = errors.New("statutory profile: version mismatch")
	ErrStatutoryProfileOverlap         = errors.New("statutory profile: overlapping active profile exists")

	ErrStatutoryRuleSetNotFound             = errors.New("statutory rule set: not found")
	ErrStatutoryComponentDefinitionNotFound = errors.New("statutory component definition: not found")
	ErrStatutoryContributionRuleNotFound    = errors.New("statutory contribution rule: not found")
	ErrStatutoryComponentMappingNotFound    = errors.New("statutory component mapping: not found")
	ErrTaxSlabNotFound                      = errors.New("tax slab: not found")
	ErrDeductionLimitNotFound               = errors.New("deduction limit: not found")
	ErrEmployeeStatutoryProfileNotFound     = errors.New("employee statutory profile: not found")
	ErrStatutorySnapshotNotFound            = errors.New("statutory snapshot: not found")
	ErrTaxDeclarationTypeNotFound           = errors.New("tax declaration type: not found")
	ErrTaxDeclarationNotFound               = errors.New("tax declaration: not found")
)
