package idempotency

import (
	"context"
	"database/sql"
)

type HybridStore struct {
	dbStore *PostgresStore
	cache   *RedisCache
}

func NewHybridStore(db *PostgresStore, cache *RedisCache) *HybridStore {
	return &HybridStore{
		dbStore: db,
		cache:   cache,
	}
}

// Get tries Redis first; if tx is nil and cache miss, return sql.ErrNoRows.
func (h *HybridStore) Get(ctx context.Context, tx *sql.Tx, key string, target interface{}) error {
	// 1. Always try Redis
	found, err := h.cache.Get(ctx, key, target)
	if err == nil && found {
		return nil
	}
	// 2. If no transaction, don't fallback to DB – just treat as miss
	if tx == nil {
		return sql.ErrNoRows
	}
	// 3. Fallback to DB with transaction
	if err := h.dbStore.Get(ctx, tx, key, target); err != nil {
		return err
	}
	// 4. Backfill Redis (non‑blocking)
	go h.cache.Set(context.Background(), key, target)
	return nil
}

func (h *HybridStore) Exists(ctx context.Context, tx *sql.Tx, key string) (bool, error) {
	// Could check cache first, but we keep DB-only for simplicity.
	return h.dbStore.Exists(ctx, tx, key)
}

// Store writes to Redis always; writes to DB only if tx != nil.
func (h *HybridStore) Store(ctx context.Context, tx *sql.Tx, key string, response interface{}) error {
	// Always store in Redis (synchronous or async – choose based on need)
	if err := h.cache.Set(ctx, key, response); err != nil {
		// Log error and continue? For idempotency, cache is critical, so return error.
		return err
	}
	if tx != nil {
		if err := h.dbStore.Store(ctx, tx, key, response); err != nil {
			return err
		}
	}
	return nil
}
