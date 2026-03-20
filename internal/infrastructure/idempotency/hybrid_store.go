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

// --------------------------------------------------
// FAST PATH (Redis first)
// --------------------------------------------------

func (h *HybridStore) Get(ctx context.Context, key string, target interface{}) error {
	// 1. Try Redis
	found, err := h.cache.Get(ctx, key, target)
	if err != nil {
		return err
	}
	if found {
		return nil
	}

	// 2. Fallback to DB
	if err := h.dbStore.Get(ctx, key, target); err != nil {
		return err
	}

	// 3. Backfill Redis
	_ = h.cache.Set(ctx, key, target)

	return nil
}

// --------------------------------------------------
// TX-safe exists
// --------------------------------------------------

func (h *HybridStore) Exists(ctx context.Context, tx *sql.Tx, key string) (bool, error) {
	return h.dbStore.Exists(ctx, tx, key)
}

// --------------------------------------------------
// Store (TX + cache after)
// --------------------------------------------------

func (h *HybridStore) Store(ctx context.Context, tx *sql.Tx, key string, response interface{}) error {
	// 1. Store in DB (source of truth)
	if err := h.dbStore.Store(ctx, tx, key, response); err != nil {
		return err
	}

	// 2. Cache (non-blocking best effort)
	go h.cache.Set(context.Background(), key, response)

	return nil
}
