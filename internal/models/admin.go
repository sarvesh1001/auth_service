package models

import (
	"time"

	"github.com/google/uuid"
)

// Constants for admin role masks
const (
	RoleMaskOwner         uint64 = 1 << 0 // 1
	RoleMaskSuperEmployee uint64 = 1 << 1 // 2
	RoleMaskEmployee      uint64 = 1 << 2 // 4
)

// Constants for system department bitmasks (16 departments)
const (
	DeptBitmaskHR         uint64 = 1 << 0  // 1
	DeptBitmaskFinance    uint64 = 1 << 1  // 2
	DeptBitmaskAccounting uint64 = 1 << 2  // 4
	DeptBitmaskProcurement uint64 = 1 << 3 // 8
	DeptBitmaskInventory  uint64 = 1 << 4  // 16
	DeptBitmaskLogistics  uint64 = 1 << 5  // 32
	DeptBitmaskSales      uint64 = 1 << 6  // 64
	DeptBitmaskMarketing  uint64 = 1 << 7  // 128
	DeptBitmaskSupport    uint64 = 1 << 8  // 256
	DeptBitmaskOperations uint64 = 1 << 9  // 512
	DeptBitmaskIT         uint64 = 1 << 10 // 1024
	DeptBitmaskProduction uint64 = 1 << 11 // 2048
	DeptBitmaskQC         uint64 = 1 << 12 // 4096
	DeptBitmaskQA         uint64 = 1 << 13 // 8192
	DeptBitmaskRND        uint64 = 1 << 14 // 16384
	DeptBitmaskAdmin      uint64 = 1 << 15 // 32768
	
	// Special bitmasks
	DeptBitmaskAll        uint64 = 0xFFFF  // All 16 departments
	DeptBitmaskNone       uint64 = 0       // No departments
)

// Admin permissions bit indices (229 permissions total)
var AdminPermissionBitIndices = map[string]int{
	// Admin permissions (209-228)
	"admin.user.create": 209,
	"admin.user.update": 210,
	"admin.user.view": 211,
	"admin.user.delete": 212,
	"admin.role.create": 213,
	"admin.role.update": 214,
	"admin.role.delete": 215,
	"admin.role.view": 216,
	"admin.permission.assign": 217,
	"admin.permission.revoke": 218,
	"admin.permission.view": 219,
	"admin.department.create": 220,
	"admin.department.update": 221,
	"admin.department.delete": 222,
	"admin.department.view": 223,
	"admin.company.update": 224,
	"admin.company.view": 225,
	"admin.company.suspend": 226,
	"admin.audit.logs.view": 227,
	"admin.audit.logs.export": 228,
}

type AdminUser struct {
	AdminID             uuid.UUID   `json:"admin_id" cql:"admin_id"`
	PhoneHash           string      `json:"phone_hash" cql:"phone_hash"`
	PhoneEncrypted      string      `json:"phone_encrypted,omitempty" cql:"phone_encrypted"`
	PhoneKeyID          uuid.UUID   `json:"phone_key_id" cql:"phone_key_id"`
	PhoneEncryptedDEK   string      `json:"phone_encrypted_dek,omitempty" cql:"phone_encrypted_dek"`
	AdminRoleMask       uint64      `json:"admin_role_mask" cql:"admin_role_mask"`
	AdminPermissionMask []uint64    `json:"admin_permission_mask" cql:"admin_permission_mask"`
	DepartmentBitmask   uint64      `json:"department_bitmask" cql:"department_bitmask"` // Bitmask for accessible departments
	AdminCreatedAt      time.Time   `json:"admin_created_at" cql:"admin_created_at"`
	AdminCreatedBy      uuid.UUID   `json:"admin_created_by" cql:"admin_created_by"`
	AdminUpdatedAt      time.Time   `json:"admin_updated_at" cql:"admin_updated_at"`
	IsActive            bool        `json:"is_active" cql:"is_active"`
	DataAccessScope     []string    `json:"data_access_scope" cql:"data_access_scope"`
	IPWhitelist         []string    `json:"ip_whitelist" cql:"ip_whitelist"`
	FailedLoginAttempts int         `json:"failed_login_attempts" cql:"failed_login_attempts"`
	LastLogin           time.Time   `json:"last_login,omitempty" cql:"last_login"`
}
// SystemDepartment represents a department in the system
type SystemDepartment struct {
    SystemDepartmentID uuid.UUID `json:"system_department_id" db:"system_department_id"`
    Name               string    `json:"name" db:"name"`
    ModuleCode         string    `json:"module_code" db:"module_code"`
    Description        string    `json:"description" db:"description"`
    Bitmask            uint64    `json:"bitmask" db:"bitmask"`
}


// Helper methods for AdminUser
func (a *AdminUser) IsOwner() bool {
	return a.AdminRoleMask&RoleMaskOwner != 0
}

func (a *AdminUser) IsSuperEmployee() bool {
	return a.AdminRoleMask&RoleMaskSuperEmployee != 0
}

func (a *AdminUser) IsEmployee() bool {
	return a.AdminRoleMask&RoleMaskEmployee != 0
}

func (a *AdminUser) HasDepartmentAccess(departmentBit uint64) bool {
	if a.IsOwner() {
		return true // Owner has access to all departments
	}
	return a.DepartmentBitmask&departmentBit != 0
}

func (a *AdminUser) HasAllDepartments() bool {
	if a.IsOwner() {
		return true
	}
	return a.DepartmentBitmask == DeptBitmaskAll
}

// Get accessible department names
func (a *AdminUser) GetAccessibleDepartments() []string {
	if a.IsOwner() {
		return []string{"HR", "Finance", "Accounting", "Procurement", "Inventory", 
			"Logistics", "Sales", "Marketing", "Customer Support", "Operations", 
			"IT", "Production", "Quality Control", "Quality Assurance", "R&D", "Administration"}
	}
	
	var departments []string
	if a.DepartmentBitmask&DeptBitmaskHR != 0 {
		departments = append(departments, "HR")
	}
	if a.DepartmentBitmask&DeptBitmaskFinance != 0 {
		departments = append(departments, "Finance")
	}
	if a.DepartmentBitmask&DeptBitmaskAccounting != 0 {
		departments = append(departments, "Accounting")
	}
	if a.DepartmentBitmask&DeptBitmaskProcurement != 0 {
		departments = append(departments, "Procurement")
	}
	if a.DepartmentBitmask&DeptBitmaskInventory != 0 {
		departments = append(departments, "Inventory")
	}
	if a.DepartmentBitmask&DeptBitmaskLogistics != 0 {
		departments = append(departments, "Logistics")
	}
	if a.DepartmentBitmask&DeptBitmaskSales != 0 {
		departments = append(departments, "Sales")
	}
	if a.DepartmentBitmask&DeptBitmaskMarketing != 0 {
		departments = append(departments, "Marketing")
	}
	if a.DepartmentBitmask&DeptBitmaskSupport != 0 {
		departments = append(departments, "Customer Support")
	}
	if a.DepartmentBitmask&DeptBitmaskOperations != 0 {
		departments = append(departments, "Operations")
	}
	if a.DepartmentBitmask&DeptBitmaskIT != 0 {
		departments = append(departments, "IT")
	}
	if a.DepartmentBitmask&DeptBitmaskProduction != 0 {
		departments = append(departments, "Production")
	}
	if a.DepartmentBitmask&DeptBitmaskQC != 0 {
		departments = append(departments, "Quality Control")
	}
	if a.DepartmentBitmask&DeptBitmaskQA != 0 {
		departments = append(departments, "Quality Assurance")
	}
	if a.DepartmentBitmask&DeptBitmaskRND != 0 {
		departments = append(departments, "R&D")
	}
	if a.DepartmentBitmask&DeptBitmaskAdmin != 0 {
		departments = append(departments, "Administration")
	}
	
	return departments
}

// Can manage employee of specific role
func (a *AdminUser) CanManageEmployee(employeeRoleMask uint64) bool {
	if a.IsOwner() {
		return true
	}
	
	if a.IsSuperEmployee() {
		// Super employee can manage employees (but not other super employees or owners)
		return employeeRoleMask == RoleMaskEmployee
	}
	
	// Employees cannot manage anyone
	return false
}

func (a *AdminUser) CanPromoteToRole(targetRoleMask uint64) bool {
	if a.IsOwner() {
		return true // Owner can promote to any role
	}
	
	if a.IsSuperEmployee() {
		// Super employee can only promote to employee role
		return targetRoleMask == RoleMaskEmployee
	}
	
	return false
}

// Check if admin has specific permission
func (a *AdminUser) HasPermission(permissionName string) bool {
	bitIndex, exists := AdminPermissionBitIndices[permissionName]
	if !exists {
		return false
	}
	
	// Owner has all permissions
	if a.IsOwner() {
		return true
	}
	
	return HasPermission(a.AdminPermissionMask, bitIndex)
}

// Get permission names from bitmask
func (a *AdminUser) GetPermissionNames() []string {
	var permissions []string
	for name := range AdminPermissionBitIndices {
		if a.HasPermission(name) {
			permissions = append(permissions, name)
		}
	}
	return permissions
}

// Copy permission mask
func (a *AdminUser) CopyPermissionMask() []uint64 {
	if a.AdminPermissionMask == nil {
		return make([]uint64, 4)
	}
	
	mask := make([]uint64, len(a.AdminPermissionMask))
	copy(mask, a.AdminPermissionMask)
	return mask
}

// Get role as string
func (a *AdminUser) GetRoleString() string {
	if a.IsOwner() {
		return "owner"
	}
	if a.IsSuperEmployee() {
		return "super_employee"
	}
	if a.IsEmployee() {
		return "employee"
	}
	return "unknown"
}

// Helper function to check permission in bitmask
func HasPermission(permissionMask []uint64, bitIndex int) bool {
	if bitIndex < 0 || bitIndex >= 229 {
		return false
	}
	
	segment := bitIndex / 64
	bit := bitIndex % 64
	
	if segment >= len(permissionMask) {
		return false
	}
	
	return (permissionMask[segment] & (1 << bit)) != 0
}

// Helper function to set permission in bitmask
func SetPermission(permissionMask []uint64, bitIndex int, value bool) []uint64 {
	if bitIndex < 0 || bitIndex >= 229 {
		return permissionMask
	}
	
	segment := bitIndex / 64
	bit := bitIndex % 64
	
	// Ensure mask has enough segments
	for len(permissionMask) <= segment {
		permissionMask = append(permissionMask, 0)
	}
	
	if value {
		permissionMask[segment] |= (1 << bit)
	} else {
		permissionMask[segment] &^= (1 << bit)
	}
	
	return permissionMask
}

// CreateFullPermissionMask creates a permission mask with all bits set (all permissions granted)
func CreateFullPermissionMask() []uint64 {
	// We have 229 permissions, which fits in 4 uint64s (4 * 64 = 256 bits)
	mask := make([]uint64, 4)
	
	// Set all bits to 1 in the first 3 segments (192 bits)
	for i := 0; i < 3; i++ {
		mask[i] = ^uint64(0) // All bits set to 1
	}
	
	// For the 4th segment, we only need 37 bits (229-192=37)
	// Set bits 0-36 to 1 (37 bits)
	for i := 0; i < 37; i++ {
		mask[3] |= (1 << uint(i))
	}
	
	return mask
}

// CreateEmptyPermissionMask creates an empty permission mask with no permissions
func CreateEmptyPermissionMask() []uint64 {
	return make([]uint64, 4)
}

// AddDepartmentBitmask adds a department bitmask to the user
func (a *AdminUser) AddDepartmentBitmask(departmentBit uint64) {
	a.DepartmentBitmask |= departmentBit
}

// RemoveDepartmentBitmask removes a department bitmask from the user
func (a *AdminUser) RemoveDepartmentBitmask(departmentBit uint64) {
	a.DepartmentBitmask &^= departmentBit
}

// GetBitmask returns the bitmask for SystemDepartment (to fix the missing field error)
func (d *SystemDepartment) GetBitmask() uint64 {
	return d.Bitmask
}

// SetBitmask sets the bitmask for SystemDepartment
func (d *SystemDepartment) SetBitmask(bitmask uint64) {
	d.Bitmask = bitmask
}