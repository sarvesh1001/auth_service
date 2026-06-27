// repository/tx_helper.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DBTX is the interface that both *sql.DB and *sql.Tx implement.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// scanner is a minimal interface for rows and rows that can Scan.
type scanner interface {
	Scan(dest ...interface{}) error
}

// Pagination parameters
type Pagination struct {
	Limit  int
	Offset int
}

// Sort parameters
type Sort struct {
	Field     string
	Direction string // "ASC" or "DESC"
}

// validatePagination returns safe limit/offset with defaults.
func validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 20 // default
	}
	if limit > 1000 {
		limit = 1000 // max
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// validateSort checks if the sort field is allowed and returns a SQL ORDER BY clause.
func validateSort(s Sort, allowedFields map[string]bool) (string, error) {
	if s.Field == "" {
		return "", nil // no sorting
	}
	if !allowedFields[s.Field] {
		return "", fmt.Errorf("invalid sort field: %s", s.Field)
	}
	dir := s.Direction
	if dir == "" {
		dir = "ASC"
	}
	if dir != "ASC" && dir != "DESC" {
		return "", fmt.Errorf("invalid sort direction: %s", dir)
	}
	return fmt.Sprintf("ORDER BY %s %s", s.Field, dir), nil
}

// tx_helper.go – add these functions

func nullString(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

func nullUUID(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func nullTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}
