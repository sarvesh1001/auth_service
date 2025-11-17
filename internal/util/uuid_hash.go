// internal/util/uuid_hash.go
package util

import "github.com/google/uuid"

// HashUUID creates a simple hash from UUID for partition determination
func HashUUID(id uuid.UUID) int {
	// Use the first 8 bytes of the UUID to create a hash
	data := id[:8]
	var hash uint64
	for _, b := range data {
		hash = hash*31 + uint64(b)
	}
	return int(hash & 0x7FFFFFFF) // Ensure positive
}
