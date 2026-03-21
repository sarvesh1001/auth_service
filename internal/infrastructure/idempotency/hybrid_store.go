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

// ✅ Get now accepts tx and passes it to dbStore
func (h *HybridStore) Get(ctx context.Context, tx *sql.Tx, key string, target interface{}) error {
	// 1. Try Redis
	found, err := h.cache.Get(ctx, key, target)
	if err == nil && found {
		return nil
	}
	// 2. Fallback to DB with transaction
	if err := h.dbStore.Get(ctx, tx, key, target); err != nil {
		return err
	}
	// 3. Backfill Redis (non‑blocking)
	go h.cache.Set(context.Background(), key, target)
	return nil
}

func (h *HybridStore) Exists(ctx context.Context, tx *sql.Tx, key string) (bool, error) {
	return h.dbStore.Exists(ctx, tx, key)
}

func (h *HybridStore) Store(ctx context.Context, tx *sql.Tx, key string, response interface{}) error {
	if err := h.dbStore.Store(ctx, tx, key, response); err != nil {
		return err
	}
	go h.cache.Set(context.Background(), key, response)
	return nil
}
