package repository

import (
	"context"
	"database/sql"
	"fmt"
)

// DBTX is the interface for database transactions/queries
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// scanner is an interface for rows/row that can scan
type scanner interface {
	Scan(dest ...interface{}) error
}

// Pagination holds limit and offset
type Pagination struct {
	Limit  int
	Offset int
}

// Sort holds field and direction
type Sort struct {
	Field     string
	Direction string
}

// validateSort checks if sort field is allowed and returns ORDER BY clause
func validateSort(s Sort, allowedFields map[string]bool) (string, error) {
	if s.Field == "" {
		return "", nil
	}
	if !allowedFields[s.Field] {
		return "", fmt.Errorf("invalid sort field: %s", s.Field)
	}
	dir := "ASC"
	if s.Direction == "DESC" || s.Direction == "desc" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", s.Field, dir), nil
}

// validatePagination returns limit and offset with defaults
func validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
