package rbac

// BuildMaskFromBitPositions builds bitmask from bit positions
// Uses []uint64 where each uint64 holds 64 permissions
func BuildMaskFromBitPositions(bitPositions []uint64) []uint64 {
	if len(bitPositions) == 0 {
		return []uint64{0}
	}

	// Find maximum bit position to determine array size
	var maxBit uint64
	for _, bit := range bitPositions {
		if bit > maxBit {
			maxBit = bit
		}
	}

	// Calculate required uint64s (each holds 64 bits)
	arraySize := (maxBit / 64) + 1
	mask := make([]uint64, arraySize)

	// Set bits in the mask
	for _, bit := range bitPositions {
		index := bit / 64
		position := bit % 64
		mask[index] |= (1 << position)
	}

	return mask
}

// BuildMaskFromPermissionNames builds bitmask from permission names
func BuildMaskFromPermissionNames(permissionNames []string) []uint64 {
	registry := GetPermissionRegistry()
	var bitPositions []uint64

	for _, perm := range permissionNames {
		if bit, exists := registry.GetBitPosition(perm); exists {
			bitPositions = append(bitPositions, bit)
		}
	}

	return BuildMaskFromBitPositions(bitPositions)
}

// GetBitPositionsFromMask extracts bit positions from mask
func GetBitPositionsFromMask(mask []uint64) []uint64 {
	var positions []uint64

	for i, segment := range mask {
		if segment == 0 {
			continue
		}

		for j := 0; j < 64; j++ {
			if segment&(1<<j) != 0 {
				positions = append(positions, uint64(i*64+j))
			}
		}
	}

	return positions
}
