package idempotency

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// --------------------------------------------------
// Exists (TX aware)
// --------------------------------------------------

func (s *PostgresStore) Exists(ctx context.Context, tx *sql.Tx, key string) (bool, error) {
	query := `
		SELECT 1 FROM academics.idempotency_keys
		WHERE key = $1
	`

	var row *sql.Row
	if tx != nil {
		row = tx.QueryRowContext(ctx, query, key)
	} else {
		row = s.db.QueryRowContext(ctx, query, key)
	}

	var tmp int
	err := row.Scan(&tmp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// --------------------------------------------------
// Store (MUST be inside TX) with ON CONFLICT safety
// --------------------------------------------------

func (s *PostgresStore) Store(ctx context.Context, tx *sql.Tx, key string, response interface{}) error {
	if tx == nil {
		return errors.New("transaction required for idempotency store")
	}

	data, err := json.Marshal(response)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO academics.idempotency_keys (key, response)
		VALUES ($1, $2)
		ON CONFLICT (key) DO NOTHING
	`, key, data)

	return err
}

// --------------------------------------------------
// Get (non‑TX read) – unmarshals into target
// --------------------------------------------------

func (s *PostgresStore) Get(ctx context.Context, key string, target interface{}) error {
	var data []byte

	err := s.db.QueryRowContext(ctx, `
		SELECT response FROM academics.idempotency_keys
		WHERE key = $1
	`, key).Scan(&data)

	if err != nil {
		return err
	}

	return json.Unmarshal(data, target)
}
