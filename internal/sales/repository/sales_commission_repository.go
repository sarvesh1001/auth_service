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
	"auth-service/internal/sales/models/enums"
)

// -------------------------------------------------------------------------
// Interface
// -------------------------------------------------------------------------

type SalesCommissionRepository interface {
	// Commission records
	Create(ctx context.Context, db DBTX, comm *models.SalesCommission) error
	GetByID(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (*models.SalesCommission, error)
	Update(ctx context.Context, db DBTX, comm *models.SalesCommission) error
	Exists(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (bool, error)
	GetByReference(ctx context.Context, db DBTX, companyID uuid.UUID, refType enums.CommissionReferenceType, refID uuid.UUID) ([]*models.SalesCommission, error)
	GetBySalesRepAndPeriod(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, from, to time.Time) ([]*models.SalesCommission, error)
	List(ctx context.Context, db DBTX, filter SalesCommissionFilter, p Pagination, s Sort) ([]*models.SalesCommission, int64, error)
	GetTotalCommission(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time, status *enums.CommissionStatus, salesRepID *uuid.UUID) (decimal.Decimal, error)
	CountByStatus(ctx context.Context, db DBTX, companyID uuid.UUID, status enums.CommissionStatus, salesRepID *uuid.UUID) (int64, error)
	GetTopByAmount(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.SalesCommission, error)
	GetTrend(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*CommissionTrendPoint, error)
	GetByStatus(ctx context.Context, db DBTX, companyID uuid.UUID, status enums.CommissionStatus) ([]*models.SalesCommission, error)
	GetUnpaid(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.SalesCommission, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (*models.SalesCommission, error)
	// HasOverlappingAssignment checks if the sales rep already has an active assignment on the given date.
	HasOverlappingAssignment(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, effectiveFrom time.Time) (bool, error)
	CountActiveAssignments(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (int64, error)

	// ExistsByReference checks whether a commission record already exists for the given reference (regardless of status).
	ExistsByReference(ctx context.Context, db DBTX, companyID uuid.UUID, referenceType enums.CommissionReferenceType, referenceID uuid.UUID) (bool, error)
	// Assignments
	CreateAssignment(ctx context.Context, db DBTX, assignment *models.SalesRepCommissionAssignment) error
	DeactivateCurrentAssignment(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, effectiveTo time.Time) error
	GetAssignmentAt(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, at time.Time) (*models.SalesRepCommissionAssignment, error)
}

type SalesCommissionFilter struct {
	CompanyID     uuid.UUID
	SalesRepID    *uuid.UUID
	ReferenceType *enums.CommissionReferenceType
	ReferenceID   *uuid.UUID
	Status        *enums.CommissionStatus
	EarnedFrom    *time.Time
	EarnedTo      *time.Time
}

type CommissionTrendPoint struct {
	Period   time.Time
	Earned   decimal.Decimal
	Approved decimal.Decimal
	Paid     decimal.Decimal
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type salesCommissionRepository struct {
	logger *zap.Logger
}

func NewSalesCommissionRepository(logger *zap.Logger) SalesCommissionRepository {
	return &salesCommissionRepository{
		logger: logger.Named("sales_commission_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *salesCommissionRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *salesCommissionRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *salesCommissionRepository) validatePagination(p Pagination) (int, int) {
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

func (r *salesCommissionRepository) buildCommissionFilter(filter SalesCommissionFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.SalesRepID != nil {
		conds = append(conds, fmt.Sprintf("sales_rep_id = $%d", idx))
		args = append(args, *filter.SalesRepID)
		idx++
	}
	if filter.ReferenceType != nil {
		conds = append(conds, fmt.Sprintf("reference_type = $%d", idx))
		args = append(args, string(*filter.ReferenceType))
		idx++
	}
	if filter.ReferenceID != nil {
		conds = append(conds, fmt.Sprintf("reference_id = $%d", idx))
		args = append(args, *filter.ReferenceID)
		idx++
	}
	if filter.Status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, string(*filter.Status))
		idx++
	}
	if filter.EarnedFrom != nil {
		conds = append(conds, fmt.Sprintf("earned_at >= $%d", idx))
		args = append(args, *filter.EarnedFrom)
		idx++
	}
	if filter.EarnedTo != nil {
		conds = append(conds, fmt.Sprintf("earned_at <= $%d", idx))
		args = append(args, *filter.EarnedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *salesCommissionRepository) scanCommission(s scanner) (*models.SalesCommission, error) {
	var c models.SalesCommission
	var statusStr string
	var rejectReason, notes sql.NullString
	var paidAt, approvedAt, rejectedAt sql.NullTime
	var ruleID uuid.NullUUID
	var createdBy, updatedBy uuid.NullUUID

	err := s.Scan(
		&c.CommissionID,
		&c.CompanyID,
		&c.SalesRepID,
		&c.ReferenceType,
		&c.ReferenceID,
		&c.CommissionBase,
		&c.CommissionRate,
		&c.CommissionAmount,
		&statusStr,
		&c.EarnedAt,
		&paidAt,
		&approvedAt,
		&rejectedAt,
		&rejectReason,
		&notes,
		&ruleID,
		&c.CreatedAt,
		&c.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan commission: %w", err)
	}

	c.Status = enums.CommissionStatus(statusStr)
	if paidAt.Valid {
		c.PaidAt = &paidAt.Time
	}
	if approvedAt.Valid {
		c.ApprovedAt = &approvedAt.Time
	}
	if rejectedAt.Valid {
		c.RejectedAt = &rejectedAt.Time
	}
	if rejectReason.Valid {
		c.RejectReason = &rejectReason.String
	}
	if notes.Valid {
		c.Notes = &notes.String
	}
	if ruleID.Valid {
		c.RuleID = &ruleID.UUID
	}
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		c.UpdatedBy = &updatedBy.UUID
	}
	return &c, nil
}

func (r *salesCommissionRepository) scanAssignment(s scanner) (*models.SalesRepCommissionAssignment, error) {
	var a models.SalesRepCommissionAssignment
	var effectiveTo sql.NullTime
	var assignedBy uuid.NullUUID

	err := s.Scan(
		&a.AssignmentID,
		&a.CompanyID,
		&a.SalesRepID,
		&a.PlanID,
		&a.EffectiveFrom,
		&effectiveTo,
		&assignedBy,
		&a.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan assignment: %w", err)
	}
	if effectiveTo.Valid {
		a.EffectiveTo = &effectiveTo.Time
	}
	if assignedBy.Valid {
		a.AssignedBy = &assignedBy.UUID
	}
	return &a, nil
}

// -------------------------------------------------------------------------
// Commission Record CRUD
// -------------------------------------------------------------------------

func (r *salesCommissionRepository) Create(ctx context.Context, db DBTX, comm *models.SalesCommission) error {
	query := `
		INSERT INTO sales.sales_commissions (
			commission_id, company_id, sales_rep_id, reference_type, reference_id,
			commission_base, commission_rate, commission_amount, status, earned_at,
			paid_at, approved_at, rejected_at, reject_reason, notes, rule_id,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW(), $17, $18)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		comm.CommissionID,
		comm.CompanyID,
		comm.SalesRepID,
		string(comm.ReferenceType),
		comm.ReferenceID,
		comm.CommissionBase,
		comm.CommissionRate,
		comm.CommissionAmount,
		string(comm.Status),
		comm.EarnedAt,
		comm.PaidAt,
		comm.ApprovedAt,
		comm.RejectedAt,
		comm.RejectReason,
		comm.Notes,
		r.nullUUIDParam(comm.RuleID),
		r.nullUUIDParam(comm.CreatedBy),
		r.nullUUIDParam(comm.UpdatedBy),
	).Scan(&comm.CreatedAt, &comm.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create sales commission", zap.Error(err))
		return fmt.Errorf("create sales commission: %w", err)
	}
	return nil
}

func (r *salesCommissionRepository) GetByID(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (*models.SalesCommission, error) {
	query := `
		SELECT commission_id, company_id, sales_rep_id, reference_type, reference_id,
			commission_base, commission_rate, commission_amount, status, earned_at,
			paid_at, approved_at, rejected_at, reject_reason, notes, rule_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.sales_commissions
		WHERE commission_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, commissionID, companyID)
	return r.scanCommission(row)
}

func (r *salesCommissionRepository) Update(ctx context.Context, db DBTX, comm *models.SalesCommission) error {
	query := `
		UPDATE sales.sales_commissions
		SET sales_rep_id = $3,
			reference_type = $4,
			reference_id = $5,
			commission_base = $6,
			commission_rate = $7,
			commission_amount = $8,
			status = $9,
			earned_at = $10,
			paid_at = $11,
			approved_at = $12,
			rejected_at = $13,
			reject_reason = $14,
			notes = $15,
			rule_id = $16,
			updated_at = NOW(),
			updated_by = $17
		WHERE commission_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		comm.CommissionID,
		comm.CompanyID,
		comm.SalesRepID,
		string(comm.ReferenceType),
		comm.ReferenceID,
		comm.CommissionBase,
		comm.CommissionRate,
		comm.CommissionAmount,
		string(comm.Status),
		comm.EarnedAt,
		comm.PaidAt,
		comm.ApprovedAt,
		comm.RejectedAt,
		comm.RejectReason,
		comm.Notes,
		r.nullUUIDParam(comm.RuleID),
		r.nullUUIDParam(comm.UpdatedBy),
	).Scan(&comm.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update sales commission", zap.Error(err))
		return fmt.Errorf("update sales commission: %w", err)
	}
	return nil
}

func (r *salesCommissionRepository) Exists(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.sales_commissions WHERE commission_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, commissionID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists commission: %w", err)
	}
	return exists, nil
}

func (r *salesCommissionRepository) GetByReference(ctx context.Context, db DBTX, companyID uuid.UUID, refType enums.CommissionReferenceType, refID uuid.UUID) ([]*models.SalesCommission, error) {
	query := `
		SELECT commission_id, company_id, sales_rep_id, reference_type, reference_id,
			commission_base, commission_rate, commission_amount, status, earned_at,
			paid_at, approved_at, rejected_at, reject_reason, notes, rule_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.sales_commissions
		WHERE company_id = $1 AND reference_type = $2 AND reference_id = $3
	`
	rows, err := db.QueryContext(ctx, query, companyID, string(refType), refID)
	if err != nil {
		return nil, fmt.Errorf("get by reference: %w", err)
	}
	defer rows.Close()
	var result []*models.SalesCommission
	for rows.Next() {
		c, err := r.scanCommission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *salesCommissionRepository) GetBySalesRepAndPeriod(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, from, to time.Time) ([]*models.SalesCommission, error) {
	query := `
		SELECT commission_id, company_id, sales_rep_id, reference_type, reference_id,
			commission_base, commission_rate, commission_amount, status, earned_at,
			paid_at, approved_at, rejected_at, reject_reason, notes, rule_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.sales_commissions
		WHERE company_id = $1 AND sales_rep_id = $2 AND earned_at BETWEEN $3 AND $4
	`
	rows, err := db.QueryContext(ctx, query, companyID, salesRepID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get by rep and period: %w", err)
	}
	defer rows.Close()
	var result []*models.SalesCommission
	for rows.Next() {
		c, err := r.scanCommission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *salesCommissionRepository) List(ctx context.Context, db DBTX, filter SalesCommissionFilter, p Pagination, s Sort) ([]*models.SalesCommission, int64, error) {
	where, args := r.buildCommissionFilter(filter)
	if where == "" && filter.CompanyID == uuid.Nil {
		return nil, 0, fmt.Errorf("list requires company_id filter")
	}
	if filter.CompanyID != uuid.Nil && where == "" {
		where = "WHERE company_id = $1"
		args = []interface{}{filter.CompanyID}
	}
	allowedSort := map[string]bool{
		"earned_at":         true,
		"commission_amount": true,
		"status":            true,
		"created_at":        true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY earned_at DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.sales_commissions %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count commissions: %w", err)
	}
	if total == 0 {
		return []*models.SalesCommission{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT commission_id, company_id, sales_rep_id, reference_type, reference_id,
			commission_base, commission_rate, commission_amount, status, earned_at,
			paid_at, approved_at, rejected_at, reject_reason, notes, rule_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.sales_commissions
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list commissions: %w", err)
	}
	defer rows.Close()

	var result []*models.SalesCommission
	for rows.Next() {
		c, err := r.scanCommission(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, c)
	}
	return result, total, rows.Err()
}

func (r *salesCommissionRepository) GetTotalCommission(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time, status *enums.CommissionStatus, salesRepID *uuid.UUID) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1

	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++

	if from != nil {
		conds = append(conds, fmt.Sprintf("earned_at >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("earned_at <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	if status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, string(*status))
		idx++
	}
	if salesRepID != nil {
		conds = append(conds, fmt.Sprintf("sales_rep_id = $%d", idx))
		args = append(args, *salesRepID)
		idx++
	}

	where := "WHERE " + strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT COALESCE(SUM(commission_amount), 0) FROM sales.sales_commissions %s", where)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total commission: %w", err)
	}
	return total, nil
}

func (r *salesCommissionRepository) CountByStatus(ctx context.Context, db DBTX, companyID uuid.UUID, status enums.CommissionStatus, salesRepID *uuid.UUID) (int64, error) {
	var conds []string
	var args []interface{}
	idx := 1

	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++

	conds = append(conds, fmt.Sprintf("status = $%d", idx))
	args = append(args, string(status))
	idx++

	if salesRepID != nil {
		conds = append(conds, fmt.Sprintf("sales_rep_id = $%d", idx))
		args = append(args, *salesRepID)
		idx++
	}

	where := "WHERE " + strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT COUNT(*) FROM sales.sales_commissions %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count by status: %w", err)
	}
	return count, nil
}

func (r *salesCommissionRepository) GetTopByAmount(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.SalesCommission, error) {
	var conds []string
	var args []interface{}
	idx := 1

	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++

	if from != nil {
		conds = append(conds, fmt.Sprintf("earned_at >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("earned_at <= $%d", idx))
		args = append(args, *to)
		idx++
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	query := fmt.Sprintf(`
		SELECT commission_id, company_id, sales_rep_id, reference_type, reference_id,
			commission_base, commission_rate, commission_amount, status, earned_at,
			paid_at, approved_at, rejected_at, reject_reason, notes, rule_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.sales_commissions
		%s
		ORDER BY commission_amount DESC
		LIMIT $%d
	`, where, idx)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top by amount: %w", err)
	}
	defer rows.Close()
	var result []*models.SalesCommission
	for rows.Next() {
		c, err := r.scanCommission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *salesCommissionRepository) GetTrend(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*CommissionTrendPoint, error) {
	// Group by day (or month) and sum commission amounts per status bucket.
	// For simplicity, we'll group by date (trunc to day) and compute earned (all), approved, paid.
	query := `
		SELECT DATE(earned_at) as period,
			COALESCE(SUM(commission_amount), 0) as earned,
			COALESCE(SUM(CASE WHEN status = 'approved' THEN commission_amount ELSE 0 END), 0) as approved,
			COALESCE(SUM(CASE WHEN status = 'paid' THEN commission_amount ELSE 0 END), 0) as paid
		FROM sales.sales_commissions
		WHERE company_id = $1
			AND ($2::timestamptz IS NULL OR earned_at >= $2)
			AND ($3::timestamptz IS NULL OR earned_at <= $3)
		GROUP BY DATE(earned_at)
		ORDER BY period ASC
	`
	var fromVal, toVal interface{} = nil, nil
	if from != nil {
		fromVal = *from
	}
	if to != nil {
		toVal = *to
	}
	rows, err := db.QueryContext(ctx, query, companyID, fromVal, toVal)
	if err != nil {
		return nil, fmt.Errorf("get trend: %w", err)
	}
	defer rows.Close()
	var result []*CommissionTrendPoint
	for rows.Next() {
		var pt CommissionTrendPoint
		err := rows.Scan(&pt.Period, &pt.Earned, &pt.Approved, &pt.Paid)
		if err != nil {
			return nil, fmt.Errorf("scan trend point: %w", err)
		}
		result = append(result, &pt)
	}
	return result, rows.Err()
}

func (r *salesCommissionRepository) GetByStatus(ctx context.Context, db DBTX, companyID uuid.UUID, status enums.CommissionStatus) ([]*models.SalesCommission, error) {
	query := `
		SELECT commission_id, company_id, sales_rep_id, reference_type, reference_id,
			commission_base, commission_rate, commission_amount, status, earned_at,
			paid_at, approved_at, rejected_at, reject_reason, notes, rule_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.sales_commissions
		WHERE company_id = $1 AND status = $2
	`
	rows, err := db.QueryContext(ctx, query, companyID, string(status))
	if err != nil {
		return nil, fmt.Errorf("get by status: %w", err)
	}
	defer rows.Close()
	var result []*models.SalesCommission
	for rows.Next() {
		c, err := r.scanCommission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *salesCommissionRepository) GetUnpaid(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.SalesCommission, error) {
	query := `
		SELECT commission_id, company_id, sales_rep_id, reference_type, reference_id,
			commission_base, commission_rate, commission_amount, status, earned_at,
			paid_at, approved_at, rejected_at, reject_reason, notes, rule_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.sales_commissions
		WHERE company_id = $1 AND status IN ('approved', 'pending')
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get unpaid: %w", err)
	}
	defer rows.Close()
	var result []*models.SalesCommission
	for rows.Next() {
		c, err := r.scanCommission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *salesCommissionRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, commissionID uuid.UUID) (*models.SalesCommission, error) {
	query := `
		SELECT commission_id, company_id, sales_rep_id, reference_type, reference_id,
			commission_base, commission_rate, commission_amount, status, earned_at,
			paid_at, approved_at, rejected_at, reject_reason, notes, rule_id,
			created_at, updated_at, created_by, updated_by
		FROM sales.sales_commissions
		WHERE commission_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, commissionID, companyID)
	return r.scanCommission(row)
}

// -------------------------------------------------------------------------
// Assignments
// -------------------------------------------------------------------------

func (r *salesCommissionRepository) CreateAssignment(ctx context.Context, db DBTX, assignment *models.SalesRepCommissionAssignment) error {
	query := `
		INSERT INTO sales.sales_rep_commission_assignments (
			assignment_id, company_id, sales_rep_id, plan_id, effective_from, effective_to, assigned_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		assignment.AssignmentID,
		assignment.CompanyID,
		assignment.SalesRepID,
		assignment.PlanID,
		assignment.EffectiveFrom,
		assignment.EffectiveTo,
		r.nullUUIDParam(assignment.AssignedBy),
	)
	if err != nil {
		r.logger.Error("failed to create assignment", zap.Error(err))
		return fmt.Errorf("create assignment: %w", err)
	}
	return nil
}

func (r *salesCommissionRepository) DeactivateCurrentAssignment(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, effectiveTo time.Time) error {
	query := `
		UPDATE sales.sales_rep_commission_assignments
		SET effective_to = $3
		WHERE company_id = $1 AND sales_rep_id = $2 AND effective_to IS NULL
	`
	result, err := db.ExecContext(ctx, query, companyID, salesRepID, effectiveTo)
	if err != nil {
		return fmt.Errorf("deactivate assignment: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		// No active assignment, that's fine.
		return nil
	}
	return nil
}

func (r *salesCommissionRepository) GetAssignmentAt(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, at time.Time) (*models.SalesRepCommissionAssignment, error) {
	query := `
		SELECT assignment_id, company_id, sales_rep_id, plan_id, effective_from, effective_to, assigned_by, created_at
		FROM sales.sales_rep_commission_assignments
		WHERE company_id = $1 AND sales_rep_id = $2
			AND effective_from <= $3
			AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, salesRepID, at)
	return r.scanAssignment(row)
}

// HasOverlappingAssignment implements SalesCommissionRepository.
func (r *salesCommissionRepository) HasOverlappingAssignment(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, effectiveFrom time.Time) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.sales_rep_commission_assignments
			WHERE company_id = $1 AND sales_rep_id = $2
			  AND effective_from <= $3
			  AND (effective_to IS NULL OR effective_to >= $3)
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, salesRepID, effectiveFrom).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check overlapping assignment: %w", err)
	}
	return exists, nil
}

// ExistsByReference implements SalesCommissionRepository.
func (r *salesCommissionRepository) ExistsByReference(ctx context.Context, db DBTX, companyID uuid.UUID, referenceType enums.CommissionReferenceType, referenceID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.sales_commissions
			WHERE company_id = $1 AND reference_type = $2 AND reference_id = $3
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, string(referenceType), referenceID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exists by reference: %w", err)
	}
	return exists, nil
}

// CountActiveAssignments implements SalesCommissionRepository.
func (r *salesCommissionRepository) CountActiveAssignments(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (int64, error) {
	query := `
        SELECT COUNT(*)
        FROM sales.sales_rep_commission_assignments
        WHERE company_id = $1 AND plan_id = $2 AND effective_to IS NULL
    `
	var count int64
	err := db.QueryRowContext(ctx, query, companyID, planID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active assignments: %w", err)
	}
	return count, nil
}
