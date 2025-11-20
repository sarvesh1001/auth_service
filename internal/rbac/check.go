package rbac

// HasPermission checks if permission exists in bitmask
func HasPermission(mask []uint64, permission string) bool {
	if mask == nil || len(mask) == 0 {
		return false
	}

	registry := GetPermissionRegistry()
	bit, exists := registry.GetBitPosition(permission)
	if !exists {
		return false
	}

	return hasBit(mask, bit)
}

// HasAnyPermission checks if any of the permissions exist in bitmask
func HasAnyPermission(mask []uint64, permissions ...string) bool {
	for _, perm := range permissions {

		if HasPermission(mask, perm) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if all permissions exist in bitmask
func HasAllPermissions(mask []uint64, permissions ...string) bool {
	for _, perm := range permissions {
		if !HasPermission(mask, perm) {
			return false
		}
	}
	return true
}

// GetPermissionsFromMask returns all permission names from bitmask
func GetPermissionsFromMask(mask []uint64) []string {
	registry := GetPermissionRegistry()
	positions := GetBitPositionsFromMask(mask)

	var permissions []string
	for _, pos := range positions {
		if perm, exists := registry.GetPermissionName(pos); exists {
			permissions = append(permissions, perm)
		}
	}

	return permissions
}

// hasBit checks if specific bit is set in mask
func hasBit(mask []uint64, bit uint64) bool {
	index := bit / 64
	if index >= uint64(len(mask)) {
		return false
	}

	position := bit % 64
	return (mask[index] & (1 << position)) != 0
}
