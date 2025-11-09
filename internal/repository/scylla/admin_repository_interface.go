// internal/repository/scylla/admin_repository.go

package scylla

import (
	"context"
	"auth-service/internal/models"
	"github.com/google/uuid"
)

// AdminRepository defines the contract for admin repository operations
type AdminRepository interface {
	// ===== CORE OPERATIONS =====
	CreateAdmin(ctx context.Context, admin *models.AdminUser) error
	GetAdminByID(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error)
	GetAdminByPhoneHash(ctx context.Context, phoneHash string) (*models.AdminUser, error)

	// ===== QUERY OPERATIONS =====
	GetAllAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)
	GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)
	GetAdminsByRole(ctx context.Context, roleLevel string) ([]*models.AdminUser, error)

	// ===== ADMIN MANAGEMENT =====
	UpdateAdminPermissions(ctx context.Context, adminID uuid.UUID, permissions []string) error
	UpdateAdminRoleLevel(ctx context.Context, adminID uuid.UUID, newRoleLevel string, changedBy uuid.UUID) error
	InviteUserAsAdmin(ctx context.Context, phoneHash string, roleLevel string, permissions []string, invitedBy uuid.UUID) (*models.AdminUser, error)
	RemoveAdmin(ctx context.Context, adminID uuid.UUID, removedBy uuid.UUID) error

	// ===== OWNER MANAGEMENT =====
	GetAdminOwner(ctx context.Context) (*models.AdminUser, error)
	SetAdminOwner(ctx context.Context, adminID uuid.UUID, phoneHash string) error
	IsAdminOwnerExists(ctx context.Context) (bool, error)
	UpdateAdminOwnerPhone(ctx context.Context, adminID uuid.UUID, phoneHash, phoneEncrypted string, phoneKeyID uuid.UUID, phoneEncryptedDEK string) error

	// Aliases for external interface compatibility
	GetOwner(ctx context.Context) (*models.AdminUser, error)
	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
	HealthCheck(ctx context.Context) error

	// ===== STATUS OPERATIONS =====
	DeactivateAdmin(ctx context.Context, adminID uuid.UUID) error
	ActivateAdmin(ctx context.Context, adminID uuid.UUID) error
	UpdateAdminLastLogin(ctx context.Context, adminID uuid.UUID) error

	// ===== FAILED LOGIN TRACKING =====
	IncrementAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) (int, error)
	ResetAdminFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) error

	// ===== HEALTH & STATS =====
	AdminHealthCheck(ctx context.Context) error
	GetAdminRepositoryStats(ctx context.Context) (map[string]interface{}, error)
}
