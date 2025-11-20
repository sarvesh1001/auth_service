package rbac

import (
	"sync"
)

// PermissionRegistry stores global permission to bit position mapping
type PermissionRegistry struct {
	permissionToBit map[string]uint64
	bitToPermission map[uint64]string
	mu              sync.RWMutex
}

var (
	registry *PermissionRegistry
	once     sync.Once
)

// GetPermissionRegistry returns singleton instance
func GetPermissionRegistry() *PermissionRegistry {
	once.Do(func() {
		registry = &PermissionRegistry{
			permissionToBit: make(map[string]uint64),
			bitToPermission: make(map[uint64]string),
		}
	})
	return registry
}

// Initialize loads permissions from database
func (pr *PermissionRegistry) Initialize(permissions map[string]uint64) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	pr.permissionToBit = permissions
	// Create reverse mapping
	for perm, bit := range permissions {
		pr.bitToPermission[bit] = perm
	}
}

// GetBitPosition returns bit position for a permission
func (pr *PermissionRegistry) GetBitPosition(permission string) (uint64, bool) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	bit, exists := pr.permissionToBit[permission]
	return bit, exists
}

// GetPermissionName returns permission name for a bit position
func (pr *PermissionRegistry) GetPermissionName(bit uint64) (string, bool) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	permission, exists := pr.bitToPermission[bit]
	return permission, exists
}

// GetAllPermissions returns all registered permissions
func (pr *PermissionRegistry) GetAllPermissions() map[string]uint64 {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	// Return a copy
	result := make(map[string]uint64)
	for k, v := range pr.permissionToBit {
		result[k] = v
	}
	return result
}
