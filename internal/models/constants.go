package models

// DataAccessScope constants
const (
	DataAccessGlobal   = "global"
	DataAccessRegionIN = "region_in"
	DataAccessRegionUS = "region_us"
	DataAccessRegionEU = "region_eu"
)

// Add all permission constants here
const (
	// Admin permissions
	PermissionAdminUserCreate        = "admin.user.create"
	PermissionAdminUserUpdate        = "admin.user.update"
	PermissionAdminUserView          = "admin.user.view"
	PermissionAdminUserDelete        = "admin.user.delete"
	PermissionAdminRoleCreate        = "admin.role.create"
	PermissionAdminRoleUpdate        = "admin.role.update"
	PermissionAdminRoleDelete        = "admin.role.delete"
	PermissionAdminRoleView          = "admin.role.view"
	PermissionAdminPermissionAssign  = "admin.permission.assign"
	PermissionAdminPermissionRevoke  = "admin.permission.revoke"
	PermissionAdminPermissionView    = "admin.permission.view"
	PermissionAdminDepartmentCreate  = "admin.department.create"
	PermissionAdminDepartmentUpdate  = "admin.department.update"
	PermissionAdminDepartmentDelete  = "admin.department.delete"
	PermissionAdminDepartmentView    = "admin.department.view"
	PermissionAdminCompanyUpdate     = "admin.company.update"
	PermissionAdminCompanyView       = "admin.company.view"
	PermissionAdminCompanySuspend    = "admin.company.suspend"
	PermissionAdminAuditLogsView     = "admin.audit.logs.view"
	PermissionAdminAuditLogsExport   = "admin.audit.logs.export"
)