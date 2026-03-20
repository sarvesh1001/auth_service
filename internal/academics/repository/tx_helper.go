// tx_helper.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
)

func beginTxIfNotTx(ctx context.Context, db DBTX) (*sql.Tx, bool, error) {
	switch t := db.(type) {

	case *sql.Tx:
		// already in transaction → not owner
		return t, false, nil

	case *sql.DB:
		tx, err := t.BeginTx(ctx, nil)
		if err != nil {
			return nil, false, fmt.Errorf("begin tx: %w", err)
		}
		return tx, true, nil

	default:
		return nil, false, fmt.Errorf("unsupported DBTX type")
	}
}
