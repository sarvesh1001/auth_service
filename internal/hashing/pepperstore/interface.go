package pepperstore

import "context"

// PepperStore defines the interface for pepper storage
type PepperStore interface {
	GetPeppers(ctx context.Context) (map[int][]byte, error)
	SavePepper(ctx context.Context, version int, pepper []byte) error
	GetCurrentPepper(ctx context.Context) (int, []byte, error)
	CleanupOldPeppers(ctx context.Context, keepLast int) error
}
