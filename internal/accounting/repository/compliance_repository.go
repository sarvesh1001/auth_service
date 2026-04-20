package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models/compliance"
	"auth-service/internal/util"
)

// ComplianceReturnFilter defines filter criteria for listing compliance returns
type ComplianceReturnFilter struct {
	CompanyID   uuid.UUID
	ReturnType  string
	Status      string
	PeriodStart *time.Time
	PeriodEnd   *time.Time
	IsLocked    *bool
	Search      string // searches return_type, description? (no description field, maybe reference?)
}

// ComplianceRepository defines the interface for compliance data access
type ComplianceRepository interface {
	// =====================================================
	// RETURNS (CORE)
	// =====================================================
	CreateReturn(ctx context.Context, db DBTX, r *compliance.ComplianceReturn) error
	UpdateReturn(ctx context.Context, db DBTX, r *compliance.ComplianceReturn) error

	GetReturnByID(ctx context.Context, db DBTX, returnID uuid.UUID) (*compliance.ComplianceReturn, error)
	GetReturnByIDForUpdate(ctx context.Context, db DBTX, returnID uuid.UUID) (*compliance.ComplianceReturn, error)

	ListReturns(ctx context.Context, db DBTX, filter ComplianceReturnFilter, p Pagination, s Sort) ([]*compliance.ComplianceReturn, error)
	ListReturnsByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*compliance.ComplianceReturn, error)

	CountReturns(ctx context.Context, db DBTX, filter ComplianceReturnFilter) (int64, error)
	GetFilingByID(ctx context.Context, db DBTX, filingID uuid.UUID) (*compliance.ComplianceFiling, error)

	DeleteReturn(ctx context.Context, db DBTX, returnID uuid.UUID, deletedBy *uuid.UUID) error

	// =====================================================
	// RETURN STATUS / LIFECYCLE
	// =====================================================
	UpdateReturnStatus(ctx context.Context, db DBTX, returnID uuid.UUID, status string, updatedBy *uuid.UUID) error
	LockReturn(ctx context.Context, db DBTX, returnID uuid.UUID, updatedBy *uuid.UUID) error
	UnlockReturn(ctx context.Context, db DBTX, returnID uuid.UUID, updatedBy *uuid.UUID) error

	MarkAsFiled(ctx context.Context, db DBTX, returnID uuid.UUID, filedBy *uuid.UUID, filedAt time.Time) error

	// =====================================================
	// RETURN LINES
	// =====================================================
	AddReturnLine(ctx context.Context, db DBTX, line *compliance.ComplianceReturnLine) error
	BulkAddReturnLines(ctx context.Context, db DBTX, lines []*compliance.ComplianceReturnLine) error

	GetReturnLines(ctx context.Context, db DBTX, returnID uuid.UUID) ([]*compliance.ComplianceReturnLine, error)
	DeleteReturnLine(ctx context.Context, db DBTX, lineID uuid.UUID) error

	ClearReturnLines(ctx context.Context, db DBTX, returnID uuid.UUID) error

	// =====================================================
	// FILINGS
	// =====================================================
	CreateFiling(ctx context.Context, db DBTX, filing *compliance.ComplianceFiling) error

	GetFilingsByReturn(ctx context.Context, db DBTX, returnID uuid.UUID) ([]*compliance.ComplianceFiling, error)

	UpdateFilingStatus(ctx context.Context, db DBTX, filingID uuid.UUID, status string, errorMessage *string) error

	// =====================================================
	// AUDIT LOG (CRITICAL)
	// =====================================================
	CreateAuditLog(ctx context.Context, db DBTX, log *compliance.ComplianceAuditLog) error

	GetAuditLogs(ctx context.Context, db DBTX, companyID uuid.UUID, returnID *uuid.UUID) ([]*compliance.ComplianceAuditLog, error)

	// =====================================================
	// VALIDATION / SAFETY
	// =====================================================
	ExistsReturnForPeriod(ctx context.Context, db DBTX, companyID uuid.UUID, returnType string, start, end time.Time) (bool, error)

	IsReturnLocked(ctx context.Context, db DBTX, returnID uuid.UUID) (bool, error)

	// =====================================================
	// AGGREGATION / TOTALS (IMPORTANT)
	// =====================================================
	ComputeReturnTotals(ctx context.Context, db DBTX, returnID uuid.UUID) (totalLiability float64, totalPaid float64, err error)

	UpdateReturnTotals(ctx context.Context, db DBTX, returnID uuid.UUID, liability float64, paid float64) error
}

// complianceRepository implements ComplianceRepository
type complianceRepository struct {
	logger *zap.Logger
}

// NewComplianceRepository creates a new compliance repository instance
func NewComplianceRepository(logger *zap.Logger) ComplianceRepository {
	return &complianceRepository{
		logger: logger.Named("compliance_repo"),
	}
}

// allowed sort fields for compliance returns
var allowedComplianceReturnSortFields = map[string]bool{
	"period_start":    true,
	"period_end":      true,
	"due_date":        true,
	"status":          true,
	"created_at":      true,
	"updated_at":      true,
	"total_liability": true,
}

func (r *complianceRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "period_start"
	}
	if !allowedComplianceReturnSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *complianceRepository) validatePagination(p Pagination) (int, int) {
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

func (r *complianceRepository) buildReturnFilter(filter ComplianceReturnFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.ReturnType != "" {
		conditions = append(conditions, fmt.Sprintf("return_type = $%d", idx))
		args = append(args, filter.ReturnType)
		idx++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", idx))
		args = append(args, filter.Status)
		idx++
	}
	if filter.PeriodStart != nil {
		conditions = append(conditions, fmt.Sprintf("period_start >= $%d", idx))
		args = append(args, *filter.PeriodStart)
		idx++
	}
	if filter.PeriodEnd != nil {
		conditions = append(conditions, fmt.Sprintf("period_end <= $%d", idx))
		args = append(args, *filter.PeriodEnd)
		idx++
	}
	if filter.IsLocked != nil {
		conditions = append(conditions, fmt.Sprintf("is_locked = $%d", idx))
		args = append(args, *filter.IsLocked)
		idx++
	}
	if filter.Search != "" {
		searchPattern := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(return_type ILIKE $%d)", idx))
		args = append(args, searchPattern)
		idx++
	}

	// Soft delete condition
	conditions = append(conditions, "deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// scanReturn scans a row into a ComplianceReturn model
func (r *complianceRepository) scanReturn(scanner interface {
	Scan(dest ...interface{}) error
}) (*compliance.ComplianceReturn, error) {
	var ret compliance.ComplianceReturn
	var filingDate, filedAt sql.NullTime
	var createdBy, updatedBy, filedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := scanner.Scan(
		&ret.ReturnID, &ret.CompanyID, &ret.ReturnType,
		&ret.PeriodStart, &ret.PeriodEnd, &ret.DueDate, &filingDate,
		&ret.Status, &ret.TotalLiability, &ret.TotalPaid, &ret.IsLocked,
		&ret.CreatedAt, &ret.UpdatedAt, &createdBy, &updatedBy, &filedBy, &filedAt, &deletedAt,
	)
	if err != nil {
		return nil, err
	}
	if filingDate.Valid {
		ret.FilingDate = &filingDate.Time
	}
	if createdBy.Valid {
		ret.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ret.UpdatedBy = &updatedBy.UUID
	}
	if filedBy.Valid {
		ret.FiledBy = &filedBy.UUID
	}
	if filedAt.Valid {
		ret.FiledAt = &filedAt.Time
	}
	if deletedAt.Valid {
		ret.DeletedAt = &deletedAt.Time
	}
	return &ret, nil
}

// scanReturnLine scans a row into a ComplianceReturnLine
func (r *complianceRepository) scanReturnLine(scanner interface {
	Scan(dest ...interface{}) error
}) (*compliance.ComplianceReturnLine, error) {
	var line compliance.ComplianceReturnLine
	var taxRateID uuid.NullUUID
	var description sql.NullString

	err := scanner.Scan(
		&line.LineID, &line.ReturnID, &line.LineType,
		&taxRateID, &line.TaxableAmount, &line.TaxAmount,
		&description, &line.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if taxRateID.Valid {
		line.TaxRateID = &taxRateID.UUID
	}
	if description.Valid {
		line.Description = &description.String
	}
	return &line, nil
}

// =====================================================
// RETURNS (CORE)
// =====================================================

func (r *complianceRepository) CreateReturn(ctx context.Context, db DBTX, ret *compliance.ComplianceReturn) error {
	query := `
		INSERT INTO accounting.compliance_returns (
			return_id, company_id, return_type, period_start, period_end,
			due_date, filing_date, status, total_liability, total_paid,
			is_locked, created_at, updated_at, created_by, updated_by,
			filed_by, filed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), $12, $13, $14, $15)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		ret.ReturnID, ret.CompanyID, ret.ReturnType, ret.PeriodStart, ret.PeriodEnd,
		ret.DueDate, ret.FilingDate, ret.Status, ret.TotalLiability, ret.TotalPaid,
		ret.IsLocked, ret.CreatedBy, ret.UpdatedBy, ret.FiledBy, ret.FiledAt,
	).Scan(&ret.CreatedAt, &ret.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create compliance return",
			util.String("company_id", ret.CompanyID.String()),
			util.String("return_type", ret.ReturnType),
			util.ErrorField(err))
		return fmt.Errorf("create compliance return: %w", err)
	}
	return nil
}

func (r *complianceRepository) UpdateReturn(ctx context.Context, db DBTX, ret *compliance.ComplianceReturn) error {
	query := `
		UPDATE accounting.compliance_returns
		SET return_type = $2,
		    period_start = $3,
		    period_end = $4,
		    due_date = $5,
		    filing_date = $6,
		    status = $7,
		    total_liability = $8,
		    total_paid = $9,
		    is_locked = $10,
		    updated_by = $11,
		    updated_at = NOW(),
		    filed_by = $12,
		    filed_at = $13
		WHERE return_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		ret.ReturnID, ret.ReturnType, ret.PeriodStart, ret.PeriodEnd,
		ret.DueDate, ret.FilingDate, ret.Status, ret.TotalLiability, ret.TotalPaid,
		ret.IsLocked, ret.UpdatedBy, ret.FiledBy, ret.FiledAt,
	).Scan(&ret.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("compliance return %s not found or deleted", ret.ReturnID)
		}
		r.logger.Error("failed to update compliance return",
			util.String("id", ret.ReturnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update compliance return: %w", err)
	}
	return nil
}

func (r *complianceRepository) GetReturnByID(ctx context.Context, db DBTX, returnID uuid.UUID) (*compliance.ComplianceReturn, error) {
	query := `
		SELECT return_id, company_id, return_type, period_start, period_end,
		       due_date, filing_date, status, total_liability, total_paid,
		       is_locked, created_at, updated_at, created_by, updated_by,
		       filed_by, filed_at, deleted_at
		FROM accounting.compliance_returns
		WHERE return_id = $1 AND deleted_at IS NULL
	`
	ret, err := r.scanReturn(db.QueryRowContext(ctx, query, returnID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get compliance return by ID",
			util.String("id", returnID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get compliance return by ID: %w", err)
	}
	return ret, nil
}

func (r *complianceRepository) GetReturnByIDForUpdate(ctx context.Context, db DBTX, returnID uuid.UUID) (*compliance.ComplianceReturn, error) {
	query := `
		SELECT return_id, company_id, return_type, period_start, period_end,
		       due_date, filing_date, status, total_liability, total_paid,
		       is_locked, created_at, updated_at, created_by, updated_by,
		       filed_by, filed_at, deleted_at
		FROM accounting.compliance_returns
		WHERE return_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	ret, err := r.scanReturn(db.QueryRowContext(ctx, query, returnID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get compliance return for update",
			util.String("id", returnID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get compliance return for update: %w", err)
	}
	return ret, nil
}

func (r *complianceRepository) ListReturns(ctx context.Context, db DBTX, filter ComplianceReturnFilter, p Pagination, s Sort) ([]*compliance.ComplianceReturn, error) {
	where, args := r.buildReturnFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT return_id, company_id, return_type, period_start, period_end,
		       due_date, filing_date, status, total_liability, total_paid,
		       is_locked, created_at, updated_at, created_by, updated_by,
		       filed_by, filed_at, deleted_at
		FROM accounting.compliance_returns
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list compliance returns",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list compliance returns: %w", err)
	}
	defer rows.Close()

	var result []*compliance.ComplianceReturn
	for rows.Next() {
		ret, err := r.scanReturn(rows)
		if err != nil {
			return nil, fmt.Errorf("scan return: %w", err)
		}
		result = append(result, ret)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *complianceRepository) ListReturnsByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*compliance.ComplianceReturn, error) {
	return r.ListReturns(ctx, db, ComplianceReturnFilter{CompanyID: companyID}, Pagination{Limit: 1000}, Sort{Field: "period_start", Direction: "DESC"})
}

func (r *complianceRepository) CountReturns(ctx context.Context, db DBTX, filter ComplianceReturnFilter) (int64, error) {
	where, args := r.buildReturnFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM accounting.compliance_returns %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count compliance returns",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count compliance returns: %w", err)
	}
	return count, nil
}

func (r *complianceRepository) DeleteReturn(ctx context.Context, db DBTX, returnID uuid.UUID, deletedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.compliance_returns
		SET deleted_at = NOW(), updated_by = $2, updated_at = NOW()
		WHERE return_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, returnID, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete compliance return",
			util.String("id", returnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete compliance return: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("compliance return %s not found or already deleted", returnID)
	}
	return nil
}

// =====================================================
// RETURN STATUS / LIFECYCLE
// =====================================================

func (r *complianceRepository) UpdateReturnStatus(ctx context.Context, db DBTX, returnID uuid.UUID, status string, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.compliance_returns
		SET status = $2, updated_by = $3, updated_at = NOW()
		WHERE return_id = $1 AND deleted_at IS NULL AND is_locked = false
	`
	result, err := db.ExecContext(ctx, query, returnID, status, updatedBy)
	if err != nil {
		r.logger.Error("failed to update return status",
			util.String("id", returnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update return status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("return %s not found, deleted, or locked", returnID)
	}
	return nil
}

func (r *complianceRepository) LockReturn(ctx context.Context, db DBTX, returnID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.compliance_returns
		SET is_locked = true, updated_by = $2, updated_at = NOW()
		WHERE return_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, returnID, updatedBy)
	if err != nil {
		r.logger.Error("failed to lock return",
			util.String("id", returnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("lock return: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("return %s not found or deleted", returnID)
	}
	return nil
}

func (r *complianceRepository) UnlockReturn(ctx context.Context, db DBTX, returnID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.compliance_returns
		SET is_locked = false, updated_by = $2, updated_at = NOW()
		WHERE return_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, returnID, updatedBy)
	if err != nil {
		r.logger.Error("failed to unlock return",
			util.String("id", returnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("unlock return: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("return %s not found or deleted", returnID)
	}
	return nil
}

func (r *complianceRepository) MarkAsFiled(ctx context.Context, db DBTX, returnID uuid.UUID, filedBy *uuid.UUID, filedAt time.Time) error {
	query := `
		UPDATE accounting.compliance_returns
		SET status = 'filed',
		    filing_date = $2,
		    filed_by = $3,
		    filed_at = $4,
		    is_locked = true,
		    updated_at = NOW()
		WHERE return_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, returnID, filedAt, filedBy, filedAt)
	if err != nil {
		r.logger.Error("failed to mark return as filed",
			util.String("id", returnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("mark as filed: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("return %s not found or deleted", returnID)
	}
	return nil
}

// =====================================================
// RETURN LINES
// =====================================================

func (r *complianceRepository) AddReturnLine(ctx context.Context, db DBTX, line *compliance.ComplianceReturnLine) error {
	query := `
		INSERT INTO accounting.compliance_return_lines (
			line_id, return_id, line_type, tax_rate_id,
			taxable_amount, tax_amount, description, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		line.LineID, line.ReturnID, line.LineType, line.TaxRateID,
		line.TaxableAmount, line.TaxAmount, line.Description,
	).Scan(&line.CreatedAt)
	if err != nil {
		r.logger.Error("failed to add return line",
			util.String("return_id", line.ReturnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add return line: %w", err)
	}
	return nil
}

func (r *complianceRepository) BulkAddReturnLines(ctx context.Context, db DBTX, lines []*compliance.ComplianceReturnLine) error {
	if len(lines) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO accounting.compliance_return_lines (
			line_id, return_id, line_type, tax_rate_id,
			taxable_amount, tax_amount, description, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		RETURNING created_at
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk insert: %w", err)
	}
	defer stmt.Close()

	for _, line := range lines {
		err = stmt.QueryRowContext(ctx,
			line.LineID, line.ReturnID, line.LineType, line.TaxRateID,
			line.TaxableAmount, line.TaxAmount, line.Description,
		).Scan(&line.CreatedAt)
		if err != nil {
			r.logger.Error("bulk add return line failed",
				util.String("return_id", line.ReturnID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk add return line: %w", err)
		}
	}
	return nil
}

func (r *complianceRepository) GetReturnLines(ctx context.Context, db DBTX, returnID uuid.UUID) ([]*compliance.ComplianceReturnLine, error) {
	query := `
		SELECT line_id, return_id, line_type, tax_rate_id,
		       taxable_amount, tax_amount, description, created_at
		FROM accounting.compliance_return_lines
		WHERE return_id = $1
		ORDER BY line_type, created_at
	`
	rows, err := db.QueryContext(ctx, query, returnID)
	if err != nil {
		r.logger.Error("failed to get return lines",
			util.String("return_id", returnID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get return lines: %w", err)
	}
	defer rows.Close()

	var result []*compliance.ComplianceReturnLine
	for rows.Next() {
		line, err := r.scanReturnLine(rows)
		if err != nil {
			return nil, fmt.Errorf("scan return line: %w", err)
		}
		result = append(result, line)
	}
	return result, nil
}

func (r *complianceRepository) DeleteReturnLine(ctx context.Context, db DBTX, lineID uuid.UUID) error {
	query := `DELETE FROM accounting.compliance_return_lines WHERE line_id = $1`
	result, err := db.ExecContext(ctx, query, lineID)
	if err != nil {
		r.logger.Error("failed to delete return line",
			util.String("line_id", lineID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete return line: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("return line %s not found", lineID)
	}
	return nil
}

func (r *complianceRepository) ClearReturnLines(ctx context.Context, db DBTX, returnID uuid.UUID) error {
	query := `DELETE FROM accounting.compliance_return_lines WHERE return_id = $1`
	_, err := db.ExecContext(ctx, query, returnID)
	if err != nil {
		r.logger.Error("failed to clear return lines",
			util.String("return_id", returnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("clear return lines: %w", err)
	}
	return nil
}

// =====================================================
// FILINGS
// =====================================================

func (r *complianceRepository) CreateFiling(ctx context.Context, db DBTX, filing *compliance.ComplianceFiling) error {
	query := `
		INSERT INTO accounting.compliance_filings (
			filing_id, return_id, submission_date, acknowledgement_no,
			filing_status, error_message, metadata, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING submission_date
	`
	err := db.QueryRowContext(ctx, query,
		filing.FilingID, filing.ReturnID, filing.SubmissionDate,
		filing.AcknowledgementNo, filing.FilingStatus, filing.ErrorMessage,
		filing.Metadata, filing.CreatedBy,
	).Scan(&filing.SubmissionDate)
	if err != nil {
		r.logger.Error("failed to create filing",
			util.String("return_id", filing.ReturnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create filing: %w", err)
	}
	return nil
}

func (r *complianceRepository) GetFilingsByReturn(ctx context.Context, db DBTX, returnID uuid.UUID) ([]*compliance.ComplianceFiling, error) {
	query := `
		SELECT filing_id, return_id, submission_date, acknowledgement_no,
		       filing_status, error_message, metadata, created_by
		FROM accounting.compliance_filings
		WHERE return_id = $1
		ORDER BY submission_date DESC
	`
	rows, err := db.QueryContext(ctx, query, returnID)
	if err != nil {
		r.logger.Error("failed to get filings by return",
			util.String("return_id", returnID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get filings by return: %w", err)
	}
	defer rows.Close()

	var result []*compliance.ComplianceFiling
	for rows.Next() {
		var f compliance.ComplianceFiling
		var ackNo, errMsg sql.NullString
		var metadata []byte
		var createdBy uuid.NullUUID

		err = rows.Scan(
			&f.FilingID, &f.ReturnID, &f.SubmissionDate, &ackNo,
			&f.FilingStatus, &errMsg, &metadata, &createdBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan filing: %w", err)
		}
		if ackNo.Valid {
			f.AcknowledgementNo = &ackNo.String
		}
		if errMsg.Valid {
			f.ErrorMessage = &errMsg.String
		}
		if len(metadata) > 0 {
			f.Metadata = metadata
		}
		if createdBy.Valid {
			f.CreatedBy = &createdBy.UUID
		}
		result = append(result, &f)
	}
	return result, nil
}

func (r *complianceRepository) UpdateFilingStatus(ctx context.Context, db DBTX, filingID uuid.UUID, status string, errorMessage *string) error {
	query := `
		UPDATE accounting.compliance_filings
		SET filing_status = $2, error_message = $3
		WHERE filing_id = $1
	`
	_, err := db.ExecContext(ctx, query, filingID, status, errorMessage)
	if err != nil {
		r.logger.Error("failed to update filing status",
			util.String("filing_id", filingID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update filing status: %w", err)
	}
	return nil
}

// =====================================================
// AUDIT LOG (CRITICAL)
// =====================================================

func (r *complianceRepository) CreateAuditLog(ctx context.Context, db DBTX, log *compliance.ComplianceAuditLog) error {
	query := `
		INSERT INTO accounting.compliance_audit_logs (
			audit_id, company_id, return_id, action,
			old_state, new_state, acted_by, acted_at, ip_address
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := db.ExecContext(ctx, query,
		log.AuditID, log.CompanyID, log.ReturnID, log.Action,
		log.OldState, log.NewState, log.ActedBy, log.ActedAt, log.IPAddress,
	)
	if err != nil {
		r.logger.Error("failed to create audit log",
			util.String("company_id", log.CompanyID.String()),
			util.String("action", log.Action),
			util.ErrorField(err))
		return fmt.Errorf("create audit log: %w", err)
	}
	return nil
}

func (r *complianceRepository) GetAuditLogs(ctx context.Context, db DBTX, companyID uuid.UUID, returnID *uuid.UUID) ([]*compliance.ComplianceAuditLog, error) {
	query := `
		SELECT audit_id, company_id, return_id, action,
		       old_state, new_state, acted_by, acted_at, ip_address
		FROM accounting.compliance_audit_logs
		WHERE company_id = $1
	`
	args := []interface{}{companyID}
	idx := 2
	if returnID != nil {
		query += fmt.Sprintf(" AND return_id = $%d", idx)
		args = append(args, *returnID)
		idx++
	}
	query += " ORDER BY acted_at DESC"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to get audit logs",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get audit logs: %w", err)
	}
	defer rows.Close()

	var result []*compliance.ComplianceAuditLog
	for rows.Next() {
		var log compliance.ComplianceAuditLog
		var returnIDNull uuid.NullUUID
		var oldState, newState []byte
		var actedBy uuid.NullUUID
		var ipAddress sql.NullString

		err = rows.Scan(
			&log.AuditID, &log.CompanyID, &returnIDNull, &log.Action,
			&oldState, &newState, &actedBy, &log.ActedAt, &ipAddress,
		)
		if err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		if returnIDNull.Valid {
			log.ReturnID = &returnIDNull.UUID
		}
		if len(oldState) > 0 {
			log.OldState = oldState
		}
		if len(newState) > 0 {
			log.NewState = newState
		}
		if actedBy.Valid {
			log.ActedBy = &actedBy.UUID
		}
		if ipAddress.Valid {
			log.IPAddress = &ipAddress.String
		}
		result = append(result, &log)
	}
	return result, nil
}

// =====================================================
// VALIDATION / SAFETY
// =====================================================

func (r *complianceRepository) ExistsReturnForPeriod(ctx context.Context, db DBTX, companyID uuid.UUID, returnType string, start, end time.Time) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM accounting.compliance_returns
			WHERE company_id = $1
			  AND return_type = $2
			  AND period_start <= $4
			  AND period_end >= $3
			  AND deleted_at IS NULL
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, returnType, start, end).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existing return for period",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("exists return for period: %w", err)
	}
	return exists, nil
}

func (r *complianceRepository) IsReturnLocked(ctx context.Context, db DBTX, returnID uuid.UUID) (bool, error) {
	query := `SELECT is_locked FROM accounting.compliance_returns WHERE return_id = $1 AND deleted_at IS NULL`
	var locked bool
	err := db.QueryRowContext(ctx, query, returnID).Scan(&locked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("return %s not found", returnID)
		}
		r.logger.Error("failed to check if return is locked",
			util.String("id", returnID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("is return locked: %w", err)
	}
	return locked, nil
}

// =====================================================
// AGGREGATION / TOTALS (IMPORTANT)
// =====================================================

func (r *complianceRepository) ComputeReturnTotals(ctx context.Context, db DBTX, returnID uuid.UUID) (totalLiability float64, totalPaid float64, err error) {
	// Sum tax_amount as total liability. Paid amount would come from a payment table; for now we set to 0.
	query := `
		SELECT COALESCE(SUM(tax_amount), 0) as total_liability
		FROM accounting.compliance_return_lines
		WHERE return_id = $1
	`
	err = db.QueryRowContext(ctx, query, returnID).Scan(&totalLiability)
	if err != nil {
		r.logger.Error("failed to compute return totals",
			util.String("return_id", returnID.String()),
			util.ErrorField(err))
		return 0, 0, fmt.Errorf("compute return totals: %w", err)
	}
	// totalPaid remains 0 for now, but you can implement payment aggregation later.
	return totalLiability, 0, nil
}

func (r *complianceRepository) UpdateReturnTotals(ctx context.Context, db DBTX, returnID uuid.UUID, liability float64, paid float64) error {
	query := `
		UPDATE accounting.compliance_returns
		SET total_liability = $2, total_paid = $3, updated_at = NOW()
		WHERE return_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, returnID, liability, paid)
	if err != nil {
		r.logger.Error("failed to update return totals",
			util.String("return_id", returnID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update return totals: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("return %s not found or deleted", returnID)
	}
	return nil
}
func (r *complianceRepository) GetFilingByID(ctx context.Context, db DBTX, filingID uuid.UUID) (*compliance.ComplianceFiling, error) {
	query := `
        SELECT filing_id, return_id, submission_date, acknowledgement_no,
               filing_status, error_message, metadata, created_by
        FROM accounting.compliance_filings
        WHERE filing_id = $1
    `
	var f compliance.ComplianceFiling
	var ackNo, errMsg sql.NullString
	var metadata []byte
	var createdBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, filingID).Scan(
		&f.FilingID, &f.ReturnID, &f.SubmissionDate, &ackNo,
		&f.FilingStatus, &errMsg, &metadata, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get filing by ID",
			util.String("filing_id", filingID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get filing by ID: %w", err)
	}
	if ackNo.Valid {
		f.AcknowledgementNo = &ackNo.String
	}
	if errMsg.Valid {
		f.ErrorMessage = &errMsg.String
	}
	if len(metadata) > 0 {
		f.Metadata = metadata
	}
	if createdBy.Valid {
		f.CreatedBy = &createdBy.UUID
	}
	return &f, nil
}
