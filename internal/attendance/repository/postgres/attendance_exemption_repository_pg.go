package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type exemptionRepo struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewAttendanceExemptionRepository(pg *client.PostgresClient, logger *zap.Logger) repository.AttendanceExemptionRepository {
	return &exemptionRepo{client: pg, logger: logger.Named("exemption_repo")}
}

func (r *exemptionRepo) Create(ctx context.Context, tx *sql.Tx, exemption *models.AttendanceExemption) error {
	if exemption.ExemptionID == uuid.Nil {
		exemption.ExemptionID = uuid.New()
	}
	now := time.Now().UTC()
	exemption.CreatedAt = now
	exemption.UpdatedAt = now

	query := `
		INSERT INTO attendance.attendance_exemptions (
			exemption_id, company_id, subject_type, subject_id, from_date, to_date,
			reason, approved_by, created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}
	_, err := exec(query,
		exemption.ExemptionID,
		exemption.CompanyID,
		exemption.SubjectType,
		exemption.SubjectID,
		exemption.FromDate,
		exemption.ToDate,
		exemption.Reason,
		exemption.ApprovedBy,
		exemption.CreatedAt,
		exemption.UpdatedAt,
		exemption.CreatedBy,
	)
	return err
}

func (r *exemptionRepo) Update(ctx context.Context, tx *sql.Tx, exemption *models.AttendanceExemption) error {
	exemption.UpdatedAt = time.Now().UTC()
	query := `
		UPDATE attendance.attendance_exemptions
		SET from_date = $1, to_date = $2, reason = $3, approved_by = $4, updated_at = $5
		WHERE exemption_id = $6
	`
	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}
	_, err := exec(query,
		exemption.FromDate,
		exemption.ToDate,
		exemption.Reason,
		exemption.ApprovedBy,
		exemption.UpdatedAt,
		exemption.ExemptionID,
	)
	return err
}

func (r *exemptionRepo) Delete(ctx context.Context, tx *sql.Tx, exemptionID uuid.UUID) error {
	query := `DELETE FROM attendance.attendance_exemptions WHERE exemption_id = $1`
	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}
	_, err := exec(query, exemptionID)
	return err
}

func (r *exemptionRepo) GetByID(ctx context.Context, tx *sql.Tx, exemptionID uuid.UUID) (*models.AttendanceExemption, error) {
	query := `
		SELECT exemption_id, company_id, subject_type, subject_id, from_date, to_date,
		       reason, approved_by, created_at, updated_at, created_by
		FROM attendance.attendance_exemptions
		WHERE exemption_id = $1
	`
	row := r.getRow(ctx, tx, query, exemptionID)
	return r.scanExemption(row)
}

func (r *exemptionRepo) GetActiveForSubject(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, date time.Time) ([]*models.AttendanceExemption, error) {
	query := `
		SELECT exemption_id, company_id, subject_type, subject_id, from_date, to_date,
		       reason, approved_by, created_at, updated_at, created_by
		FROM attendance.attendance_exemptions
		WHERE company_id = $1
		  AND subject_type = $2
		  AND subject_id = $3
		  AND from_date <= $4
		  AND to_date >= $4
	`
	rows, err := r.getRows(ctx, tx, query, companyID, subjectType, subjectID, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var exemptions []*models.AttendanceExemption
	for rows.Next() {
		e, err := r.scanExemptionFromRows(rows)
		if err != nil {
			return nil, err
		}
		exemptions = append(exemptions, e)
	}
	return exemptions, nil
}

func (r *exemptionRepo) GetForDateRange(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceExemption, error) {
	query := `
		SELECT exemption_id, company_id, subject_type, subject_id, from_date, to_date,
		       reason, approved_by, created_at, updated_at, created_by
		FROM attendance.attendance_exemptions
		WHERE company_id = $1
		  AND subject_type = $2
		  AND subject_id = $3
		  AND from_date >= $4
		  AND to_date <= $5
		ORDER BY from_date
	`
	rows, err := r.getRows(ctx, tx, query, companyID, subjectType, subjectID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var exemptions []*models.AttendanceExemption
	for rows.Next() {
		e, err := r.scanExemptionFromRows(rows)
		if err != nil {
			return nil, err
		}
		exemptions = append(exemptions, e)
	}
	return exemptions, nil
}

func (r *exemptionRepo) List(ctx context.Context, tx *sql.Tx, filter repository.ExemptionFilter, pag repository.Pagination) ([]*models.AttendanceExemption, error) {
	query := `
		SELECT exemption_id, company_id, subject_type, subject_id, from_date, to_date,
		       reason, approved_by, created_at, updated_at, created_by
		FROM attendance.attendance_exemptions
		WHERE 1=1
	`
	args := []interface{}{}
	argPos := 1

	if filter.CompanyID != nil {
		query += fmt.Sprintf(" AND company_id = $%d", argPos)
		args = append(args, *filter.CompanyID)
		argPos++
	}
	if filter.SubjectType != nil {
		query += fmt.Sprintf(" AND subject_type = $%d", argPos)
		args = append(args, *filter.SubjectType)
		argPos++
	}
	if filter.SubjectID != nil {
		query += fmt.Sprintf(" AND subject_id = $%d", argPos)
		args = append(args, *filter.SubjectID)
		argPos++
	}
	if filter.FromDate != nil {
		query += fmt.Sprintf(" AND from_date >= $%d", argPos)
		args = append(args, *filter.FromDate)
		argPos++
	}
	if filter.ToDate != nil {
		query += fmt.Sprintf(" AND to_date <= $%d", argPos)
		args = append(args, *filter.ToDate)
		argPos++
	}

	query += " ORDER BY from_date DESC"
	if pag.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argPos, argPos+1)
		args = append(args, pag.Limit, pag.Offset)
	}

	rows, err := r.getRows(ctx, tx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var exemptions []*models.AttendanceExemption
	for rows.Next() {
		e, err := r.scanExemptionFromRows(rows)
		if err != nil {
			return nil, err
		}
		exemptions = append(exemptions, e)
	}
	return exemptions, nil
}

func (r *exemptionRepo) Count(ctx context.Context, tx *sql.Tx, filter repository.ExemptionFilter) (int64, error) {
	query := `SELECT COUNT(*) FROM attendance.attendance_exemptions WHERE 1=1`
	args := []interface{}{}
	argPos := 1

	if filter.CompanyID != nil {
		query += fmt.Sprintf(" AND company_id = $%d", argPos)
		args = append(args, *filter.CompanyID)
		argPos++
	}
	if filter.SubjectType != nil {
		query += fmt.Sprintf(" AND subject_type = $%d", argPos)
		args = append(args, *filter.SubjectType)
		argPos++
	}
	if filter.SubjectID != nil {
		query += fmt.Sprintf(" AND subject_id = $%d", argPos)
		args = append(args, *filter.SubjectID)
		argPos++
	}
	if filter.FromDate != nil {
		query += fmt.Sprintf(" AND from_date >= $%d", argPos)
		args = append(args, *filter.FromDate)
		argPos++
	}
	if filter.ToDate != nil {
		query += fmt.Sprintf(" AND to_date <= $%d", argPos)
		args = append(args, *filter.ToDate)
		argPos++
	}

	var count int64
	err := r.getRow(ctx, tx, query, args...).Scan(&count)
	return count, err
}

// Helper: get a *sql.Row using either tx or client.
func (r *exemptionRepo) getRow(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) *sql.Row {
	if tx != nil {
		return tx.QueryRowContext(ctx, query, args...)
	}
	return r.client.QueryRow(ctx, query, args...)
}

// Helper: get *sql.Rows using either tx or client.
func (r *exemptionRepo) getRows(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (*sql.Rows, error) {
	if tx != nil {
		return tx.QueryContext(ctx, query, args...)
	}
	return r.client.Query(ctx, query, args...)
}

func (r *exemptionRepo) scanExemption(row *sql.Row) (*models.AttendanceExemption, error) {
	var e models.AttendanceExemption
	var reason, _, _ sql.NullString
	var approvedByUUID, createdByUUID uuid.NullUUID
	err := row.Scan(
		&e.ExemptionID,
		&e.CompanyID,
		&e.SubjectType,
		&e.SubjectID,
		&e.FromDate,
		&e.ToDate,
		&reason,
		&approvedByUUID,
		&e.CreatedAt,
		&e.UpdatedAt,
		&createdByUUID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if reason.Valid {
		e.Reason = &reason.String
	}
	if approvedByUUID.Valid {
		e.ApprovedBy = &approvedByUUID.UUID
	}
	if createdByUUID.Valid {
		e.CreatedBy = &createdByUUID.UUID
	}
	return &e, nil
}

func (r *exemptionRepo) scanExemptionFromRows(rows *sql.Rows) (*models.AttendanceExemption, error) {
	var e models.AttendanceExemption
	var reason, _, _ sql.NullString
	var approvedByUUID, createdByUUID uuid.NullUUID
	err := rows.Scan(
		&e.ExemptionID,
		&e.CompanyID,
		&e.SubjectType,
		&e.SubjectID,
		&e.FromDate,
		&e.ToDate,
		&reason,
		&approvedByUUID,
		&e.CreatedAt,
		&e.UpdatedAt,
		&createdByUUID,
	)
	if err != nil {
		return nil, err
	}
	if reason.Valid {
		e.Reason = &reason.String
	}
	if approvedByUUID.Valid {
		e.ApprovedBy = &approvedByUUID.UUID
	}
	if createdByUUID.Valid {
		e.CreatedBy = &createdByUUID.UUID
	}
	return &e, nil
}
