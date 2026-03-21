package idempotency

import (
	"context"
	"database/sql"
)

type Store interface {
	Exists(ctx context.Context, tx *sql.Tx, key string) (bool, error)
	Store(ctx context.Context, tx *sql.Tx, key string, response interface{}) error
	Get(ctx context.Context, tx *sql.Tx, key string, target interface{}) error // ✅ now accepts tx
}
