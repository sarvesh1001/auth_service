package scylla

import (
	"context"
	
	"auth-service/internal/models"
	
	"github.com/google/uuid"
)

type AdminRepository interface {
	CreateAdmin(ctx context.Context, admin *models.AdminUser) error
	GetAdminByID(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error)
	GetAdminByPhoneHash(ctx context.Context, phoneHash string) (*models.AdminUser, error)
	
	GetAllAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)
	GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)
	GetAdminsByRole(ctx context.Context, roleMask uint64) ([]*models.AdminUser, error)
	
	UpdateAdminPermissions(ctx context.Context, adminID uuid.UUID, permissions []uint64) error
	UpdateAdminRoleMask(ctx context.Context, adminID uuid.UUID, newRoleMask uint64, changedBy uuid.UUID) error
	UpdateAdminDepartmentBitmask(ctx context.Context, adminID uuid.UUID, departmentBitmask uint64) error
	UpdateAdminPhone(ctx context.Context, adminID uuid.UUID, phoneHash, phoneEncrypted string, phoneKeyID uuid.UUID, phoneEncryptedDEK string) error
	RemoveAdmin(ctx context.Context, adminID uuid.UUID, removedBy uuid.UUID) error
	
	GetAdminOwner(ctx context.Context) (*models.AdminUser, error)
	SetAdminOwner(ctx context.Context, adminID uuid.UUID, phoneHash string) error
	IsAdminOwnerExists(ctx context.Context) (bool, error)
	
	GetOwner(ctx context.Context) (*models.AdminUser, error)
	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
	HealthCheck(ctx context.Context) error
	
	DeactivateAdmin(ctx context.Context, adminID uuid.UUID) error
	ActivateAdmin(ctx context.Context, adminID uuid.UUID) error
	UpdateAdminLastLogin(ctx context.Context, adminID uuid.UUID) error
	
	IncrementAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) (int, error)
	ResetAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) error
	
	AdminHealthCheck(ctx context.Context) error
	GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error)
}

// // internal/repository/scylla/admin_repository.go
// package scylla

// import (
// 	"context"

// 	"auth-service/internal/models"

// 	"github.com/google/uuid"
// )

// // AdminRepository defines the contract for admin repository operations with bitmasks
// type AdminRepository interface {
// 	// ===== CORE OPERATIONS =====
// 	CreateAdmin(ctx context.Context, admin *models.AdminUser) error
// 	GetAdminByID(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error)
// 	GetAdminByPhoneHash(ctx context.Context, phoneHash string) (*models.AdminUser, error)

// 	// ===== QUERY OPERATIONS =====
// 	GetAllAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)
// 	GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)
// 	GetAdminsByRole(ctx context.Context, roleMask uint64) ([]*models.AdminUser, error)

// 	// ===== ADMIN MANAGEMENT =====
// 	UpdateAdminPermissions(ctx context.Context, adminID uuid.UUID, permissions []uint64) error
// 	UpdateAdminRoleMask(ctx context.Context, adminID uuid.UUID, newRoleMask uint64, changedBy uuid.UUID) error
// 	UpdateAdminPhone(ctx context.Context, adminID uuid.UUID, phoneHash, phoneEncrypted string, phoneKeyID uuid.UUID, phoneEncryptedDEK string) error
// 	RemoveAdmin(ctx context.Context, adminID uuid.UUID, removedBy uuid.UUID) error

// 	// ===== OWNER MANAGEMENT =====
// 	GetAdminOwner(ctx context.Context) (*models.AdminUser, error)
// 	SetAdminOwner(ctx context.Context, adminID uuid.UUID, phoneHash string) error
// 	IsAdminOwnerExists(ctx context.Context) (bool, error)

// 	// Aliases for external interface compatibility
// 	GetOwner(ctx context.Context) (*models.AdminUser, error)
// 	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
// 	HealthCheck(ctx context.Context) error

// 	// ===== STATUS OPERATIONS =====
// 	DeactivateAdmin(ctx context.Context, adminID uuid.UUID) error
// 	ActivateAdmin(ctx context.Context, adminID uuid.UUID) error
// 	UpdateAdminLastLogin(ctx context.Context, adminID uuid.UUID) error

// 	// ===== FAILED LOGIN TRACKING =====
// 	IncrementAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) (int, error)
// 	ResetAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) error

// 	// ===== HEALTH & STATS =====
// 	AdminHealthCheck(ctx context.Context) error
// 	GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error)
// }
