package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
)

type CreditCheckHistoryRepository interface {
	Create(ctx context.Context, db DBTX, history *models.CreditCheckHistory) error
	GetByID(ctx context.Context, db DBTX, companyID, creditHistoryID uuid.UUID) (*models.CreditCheckHistory, error)
	GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.CreditCheckHistory, int64, error)
	GetLatestByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*models.CreditCheckHistory, error)
	Exists(ctx context.Context, db DBTX, companyID, creditHistoryID uuid.UUID) (bool, error)
	List(ctx context.Context, db DBTX, filter CreditCheckHistoryFilter, p Pagination, s Sort) ([]*models.CreditCheckHistory, int64, error)
	GetCustomersOnHold(ctx context.Context, db DBTX, companyID uuid.UUID) ([]uuid.UUID, error)
	GetCreditLimitChangeHistory(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) ([]*models.CreditCheckHistory, error)
	GetApprovalHistory(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*models.CreditCheckHistory, error)
}

type CreditCheckHistoryFilter struct {
	CompanyID        uuid.UUID
	CustomerID       *uuid.UUID
	CreditHistoryIDs []uuid.UUID
	ActionType       *string
	ApprovedBy       *uuid.UUID
	CreatedBy        *uuid.UUID
	CreatedFrom      *time.Time
	CreatedTo        *time.Time
}

type creditCheckHistoryRepository struct {
	logger *zap.Logger
}

func NewCreditCheckHistoryRepository(logger *zap.Logger) CreditCheckHistoryRepository {
	return &creditCheckHistoryRepository{
		logger: logger.Named("sales_credit_check_history_repo"),
	}
}

func (r *creditCheckHistoryRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *creditCheckHistoryRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
	if s.Field == "" {
		return "", nil
	}
	if !allowed[s.Field] {
		return "", fmt.Errorf("invalid sort field: %s", s.Field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", s.Field, dir), nil
}

func (r *creditCheckHistoryRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (r *creditCheckHistoryRepository) buildFilter(filter CreditCheckHistoryFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.CustomerID != nil {
		conds = append(conds, fmt.Sprintf("customer_id = $%d", idx))
		args = append(args, *filter.CustomerID)
		idx++
	}
	if len(filter.CreditHistoryIDs) > 0 {
		placeholders := make([]string, len(filter.CreditHistoryIDs))
		for i, id := range filter.CreditHistoryIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("credit_history_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.ActionType != nil {
		conds = append(conds, fmt.Sprintf("action_type = $%d", idx))
		args = append(args, *filter.ActionType)
		idx++
	}
	if filter.ApprovedBy != nil {
		conds = append(conds, fmt.Sprintf("approved_by = $%d", idx))
		args = append(args, *filter.ApprovedBy)
		idx++
	}
	if filter.CreatedBy != nil {
		conds = append(conds, fmt.Sprintf("created_by = $%d", idx))
		args = append(args, *filter.CreatedBy)
		idx++
	}
	if filter.CreatedFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.CreatedFrom)
		idx++
	}
	if filter.CreatedTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.CreatedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *creditCheckHistoryRepository) scanHistory(s scanner) (*models.CreditCheckHistory, error) {
	var h models.CreditCheckHistory
	var previousLimit, newLimit, previousOutstanding, newOutstanding sql.NullString
	var reason, approvedBy, createdBy sql.NullString

	err := s.Scan(
		&h.CreditHistoryID,
		&h.CompanyID,
		&h.CustomerID,
		&h.ActionType,
		&previousLimit,
		&newLimit,
		&previousOutstanding,
		&newOutstanding,
		&reason,
		&approvedBy,
		&createdBy,
		&h.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan credit check history: %w", err)
	}

	if previousLimit.Valid {
		val, err := decimal.NewFromString(previousLimit.String)
		if err == nil {
			h.PreviousLimit = &val
		}
	}
	if newLimit.Valid {
		val, err := decimal.NewFromString(newLimit.String)
		if err == nil {
			h.NewLimit = &val
		}
	}
	if previousOutstanding.Valid {
		val, err := decimal.NewFromString(previousOutstanding.String)
		if err == nil {
			h.PreviousOutstanding = &val
		}
	}
	if newOutstanding.Valid {
		val, err := decimal.NewFromString(newOutstanding.String)
		if err == nil {
			h.NewOutstanding = &val
		}
	}
	if reason.Valid {
		h.Reason = &reason.String
	}
	if approvedBy.Valid {
		id, _ := uuid.Parse(approvedBy.String)
		h.ApprovedBy = &id
	}
	if createdBy.Valid {
		id, _ := uuid.Parse(createdBy.String)
		h.CreatedBy = &id
	}
	return &h, nil
}

// ---------- Append-only logging ----------
func (r *creditCheckHistoryRepository) Create(ctx context.Context, db DBTX, history *models.CreditCheckHistory) error {
	query := `
		INSERT INTO sales.credit_check_history (
			credit_history_id, company_id, customer_id, action_type,
			previous_limit, new_limit, previous_outstanding, new_outstanding,
			reason, approved_by, created_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		RETURNING created_at
	`
	var prevLimit, newLimit, prevOut, newOut interface{}
	if history.PreviousLimit != nil {
		prevLimit = history.PreviousLimit.String()
	} else {
		prevLimit = nil
	}
	if history.NewLimit != nil {
		newLimit = history.NewLimit.String()
	} else {
		newLimit = nil
	}
	if history.PreviousOutstanding != nil {
		prevOut = history.PreviousOutstanding.String()
	} else {
		prevOut = nil
	}
	if history.NewOutstanding != nil {
		newOut = history.NewOutstanding.String()
	} else {
		newOut = nil
	}
	err := db.QueryRowContext(ctx, query,
		history.CreditHistoryID,
		history.CompanyID,
		history.CustomerID,
		history.ActionType,
		prevLimit,
		newLimit,
		prevOut,
		newOut,
		history.Reason,
		r.nullUUIDParam(history.ApprovedBy),
		r.nullUUIDParam(history.CreatedBy),
	).Scan(&history.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create credit check history", zap.Error(err))
		return fmt.Errorf("create credit check history: %w", err)
	}
	return nil
}

// ---------- Lookups ----------
func (r *creditCheckHistoryRepository) GetByID(ctx context.Context, db DBTX, companyID, creditHistoryID uuid.UUID) (*models.CreditCheckHistory, error) {
	query := `
		SELECT credit_history_id, company_id, customer_id, action_type,
		       previous_limit, new_limit, previous_outstanding, new_outstanding,
		       reason, approved_by, created_by, created_at
		FROM sales.credit_check_history
		WHERE company_id = $1 AND credit_history_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, creditHistoryID)
	return r.scanHistory(row)
}

func (r *creditCheckHistoryRepository) GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.CreditCheckHistory, int64, error) {
	filter := CreditCheckHistoryFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
	}
	return r.List(ctx, db, filter, p, s)
}

func (r *creditCheckHistoryRepository) GetLatestByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*models.CreditCheckHistory, error) {
	query := `
		SELECT credit_history_id, company_id, customer_id, action_type,
		       previous_limit, new_limit, previous_outstanding, new_outstanding,
		       reason, approved_by, created_by, created_at
		FROM sales.credit_check_history
		WHERE company_id = $1 AND customer_id = $2
		ORDER BY created_at DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, customerID)
	return r.scanHistory(row)
}

func (r *creditCheckHistoryRepository) Exists(ctx context.Context, db DBTX, companyID, creditHistoryID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.credit_check_history WHERE company_id = $1 AND credit_history_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, creditHistoryID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

// ---------- Listing ----------
func (r *creditCheckHistoryRepository) List(ctx context.Context, db DBTX, filter CreditCheckHistoryFilter, p Pagination, s Sort) ([]*models.CreditCheckHistory, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"created_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.credit_check_history %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count credit history: %w", err)
	}
	if total == 0 {
		return []*models.CreditCheckHistory{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT credit_history_id, company_id, customer_id, action_type,
		       previous_limit, new_limit, previous_outstanding, new_outstanding,
		       reason, approved_by, created_by, created_at
		FROM sales.credit_check_history
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list credit history: %w", err)
	}
	defer rows.Close()

	var result []*models.CreditCheckHistory
	for rows.Next() {
		h, err := r.scanHistory(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, h)
	}
	return result, total, rows.Err()
}

// ---------- Reporting / Analytics ----------
func (r *creditCheckHistoryRepository) GetCustomersOnHold(ctx context.Context, db DBTX, companyID uuid.UUID) ([]uuid.UUID, error) {
	query := `
		SELECT DISTINCT customer_id
		FROM sales.credit_check_history
		WHERE company_id = $1
		AND action_type = 'hold'
		AND created_at = (
			SELECT MAX(created_at)
			FROM sales.credit_check_history sub
			WHERE sub.customer_id = credit_check_history.customer_id
			AND sub.company_id = $1
		)
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get customers on hold: %w", err)
	}
	defer rows.Close()
	var result []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (r *creditCheckHistoryRepository) GetCreditLimitChangeHistory(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) ([]*models.CreditCheckHistory, error) {
	filter := CreditCheckHistoryFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
		ActionType: stringPtr("limit_change"),
	}
	list, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "created_at", Direction: "ASC"})
	return list, err
}

func (r *creditCheckHistoryRepository) GetApprovalHistory(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*models.CreditCheckHistory, error) {
	filter := CreditCheckHistoryFilter{
		CompanyID:   companyID,
		ActionType:  stringPtr("approval"),
		CreatedFrom: from,
		CreatedTo:   to,
	}
	list, _, err := r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "created_at", Direction: "ASC"})
	return list, err
}

func stringPtr(s string) *string {
	return &s
}
