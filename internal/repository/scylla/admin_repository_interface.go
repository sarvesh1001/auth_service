// internal/repository/scylla/admin_repository.go
package scylla

import (
	"context"

	"auth-service/internal/models"
	"github.com/google/uuid"
)

// AdminRepository defines the interface for admin user repository operations
// Only 100s of admins in the system - separate from users table for efficiency
type AdminRepository interface {
	// ===== CORE OPERATIONS =====

	// CreateAdmin creates a new admin user
	// - Only by owner/super_employee based on permissions
	// - Only for invited phone numbers (must exist in users table)
	CreateAdmin(ctx context.Context, admin *models.AdminUser) error

	// GetAdminByID retrieves an admin by their ID
	GetAdminByID(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error)

	// GetAdminByPhoneHash retrieves an admin by their phone hash (linked to users table)
	GetAdminByPhoneHash(ctx context.Context, phoneHash string) (*models.AdminUser, error)

	// ===== ADMIN MANAGEMENT (Owner only) =====

	// UpdateAdminPermissions updates admin permissions
	// - Owner can update anyone
	// - SuperEmployee can only update Employees
	UpdateAdminPermissions(ctx context.Context, adminID uuid.UUID, permissions []string) error

	// UpdateAdminRoleLevel updates admin role level (promotion/demotion)
	// - Owner can change to any role
	// - SuperEmployee can only demote to Employee
	// - Employee cannot change anyone
	UpdateAdminRoleLevel(ctx context.Context, adminID uuid.UUID, newRoleLevel string, changedBy uuid.UUID) error

	// ===== INVITATION & ONBOARDING =====

	// InviteUserAsAdmin invites a user to become admin
	// - Checks if phone is already registered user
	// - Returns error if phone not registered: "number not registered yet"
	// - SuperEmployee can only invite as Employee
	// - Owner can invite at any role
	InviteUserAsAdmin(ctx context.Context, phoneHash string, roleLevel string, permissions []string, invitedBy uuid.UUID) (*models.AdminUser, error)

	// RemoveAdmin soft-deletes an admin (sets is_active = false)
	// - Removes admin privileges
	// - User becomes regular user again
	// - Owner can remove any admin
	// - SuperEmployee can only remove Employees
	RemoveAdmin(ctx context.Context, adminID uuid.UUID, removedBy uuid.UUID) error

	// ===== OWNER MANAGEMENT (System constraints) =====

	// GetOwner retrieves the current system owner (only one allowed)
	GetOwner(ctx context.Context) (*models.AdminUser, error)

	// SetOwner sets/changes the owner (can only change phone, not change person to new owner)
	// - Only current owner can change their own phone
	// - No one can become owner if owner already exists
	// - Returns error: "system already has an owner"
	SetOwner(ctx context.Context, adminID uuid.UUID, phoneHash string) error

	// IsOwnerExists checks if system has an owner
	IsOwnerExists(ctx context.Context) (bool, error)

	// ===== ADMIN STATUS OPERATIONS =====

	// UpdateAdminStatus updates is_active flag
	DeactivateAdmin(ctx context.Context, adminID uuid.UUID) error
	ActivateAdmin(ctx context.Context, adminID uuid.UUID) error

	// UpdateLastLogin updates admin last login timestamp
	UpdateLastLogin(ctx context.Context, adminID uuid.UUID) error

	// ===== FAILED ATTEMPTS TRACKING =====

	// IncrementFailedLoginAttempts increments failed attempts counter
	IncrementFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) (int, error)

	// ResetFailedLoginAttempts resets failed attempts to 0
	ResetFailedLoginAttempts(ctx context.Context, adminID uuid.UUID) error

	// ===== QUERY OPERATIONS =====

	// GetAdminsByRole retrieves all admins with specific role level
	GetAdminsByRole(ctx context.Context, roleLevel string) ([]*models.AdminUser, error)

	// GetActiveAdmins retrieves only active admins (is_active = true)
	GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)

	// GetAllAdmins retrieves all admins (active and inactive)
	GetAllAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error)

	// ===== HEALTH & STATISTICS =====

	// HealthCheck verifies repository connectivity
	HealthCheck(ctx context.Context) error

	// GetRepositoryStats returns repository statistics
	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
	UpdateOwnerPhone(ctx context.Context, adminID uuid.UUID, phoneHash, phoneEncrypted string, phoneKeyID uuid.UUID, phoneEncryptedDEK string) error
}
