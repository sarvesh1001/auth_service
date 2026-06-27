// repository/lookup_helper.go
package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// LookupFilter is the generic filter for lookup tables.
type LookupFilter struct {
	IDs      []int16
	Code     *string
	Name     *string
	Category *string // optional, used only for statuses
}

// buildLookupFilter builds WHERE clause and arguments.
func buildLookupFilter(filter LookupFilter, idColumn, codeColumn, nameColumn, categoryColumn string) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if len(filter.IDs) > 0 {
		placeholders := make([]string, len(filter.IDs))
		for i, id := range filter.IDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("%s IN (%s)", idColumn, strings.Join(placeholders, ",")))
	}
	if filter.Code != nil {
		conds = append(conds, fmt.Sprintf("%s = $%d", codeColumn, idx))
		args = append(args, *filter.Code)
		idx++
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("%s = $%d", nameColumn, idx))
		args = append(args, *filter.Name)
		idx++
	}
	if filter.Category != nil && categoryColumn != "" {
		conds = append(conds, fmt.Sprintf("%s = $%d", categoryColumn, idx))
		args = append(args, *filter.Category)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// listLookup performs paginated listing on any lookup table.
func listLookup[T any](
	ctx context.Context,
	db DBTX,
	logger *zap.Logger,
	tableName string,
	filter LookupFilter,
	p Pagination,
	s Sort,
	idColumn, codeColumn, nameColumn, categoryColumn string,
	scanFn func(scanner) (*T, error),
) ([]*T, int64, error) {
	where, args := buildLookupFilter(filter, idColumn, codeColumn, nameColumn, categoryColumn)

	allowedSort := map[string]bool{
		idColumn:   true,
		codeColumn: true,
		nameColumn: true,
	}
	if categoryColumn != "" {
		allowedSort[categoryColumn] = true
	}
	orderBy, err := validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = fmt.Sprintf("ORDER BY %s", idColumn)
	}

	limit, offset := validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", tableName, where)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count lookup: %w", err)
	}
	if total == 0 {
		return []*T{}, 0, nil
	}

	// Data
	query := fmt.Sprintf("SELECT * FROM %s %s %s LIMIT $%d OFFSET $%d",
		tableName, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list lookup: %w", err)
	}
	defer rows.Close()

	var result []*T
	for rows.Next() {
		item, err := scanFn(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, item)
	}
	return result, total, rows.Err()
}

// searchLookup performs a search on code and name.
func searchLookup[T any](
	ctx context.Context,
	db DBTX,
	logger *zap.Logger,
	tableName string,
	companyID *uuid.UUID,
	query string,
	limit, offset int,
	codeColumn, nameColumn string,
	scanFn func(scanner) (*T, error),
) ([]*T, int64, error) {
	pattern := "%" + query + "%"
	var args []interface{}
	conds := []string{
		fmt.Sprintf("%s ILIKE $1", codeColumn),
		fmt.Sprintf("%s ILIKE $1", nameColumn),
	}
	args = append(args, pattern)
	idx := 2

	if companyID != nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, *companyID)
		idx++
	}
	where := "WHERE " + strings.Join(conds, " OR ")

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", tableName, where)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*T{}, 0, nil
	}

	// Data
	querySQL := fmt.Sprintf("SELECT * FROM %s %s ORDER BY %s LIMIT $%d OFFSET $%d",
		tableName, where, codeColumn, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()

	var result []*T
	for rows.Next() {
		item, err := scanFn(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, item)
	}
	return result, total, rows.Err()
}

// existsLookup checks existence by ID.
func existsLookup(ctx context.Context, db DBTX, tableName, idColumn string, id int16) (bool, error) {
	var exists bool
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE %s = $1)", tableName, idColumn)
	err := db.QueryRowContext(ctx, query, id).Scan(&exists)
	return exists, err
}

// existsLookupByCode checks existence by code (optionally with category).
func existsLookupByCode(ctx context.Context, db DBTX, tableName, codeColumn, code string, categoryColumn, category string) (bool, error) {
	var conds []string
	args := []interface{}{code}
	idx := 2
	conds = append(conds, fmt.Sprintf("%s = $1", codeColumn))
	if category != "" && categoryColumn != "" {
		conds = append(conds, fmt.Sprintf("%s = $%d", categoryColumn, idx))
		args = append(args, category)
	}
	where := "WHERE " + strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s %s)", tableName, where)
	var exists bool
	err := db.QueryRowContext(ctx, query, args...).Scan(&exists)
	return exists, err
}
