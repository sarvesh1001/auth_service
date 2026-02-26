package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DBTX defines the database methods used by the repository.
// Both *client.PostgresClient and *sql.Tx (via txQuerier) implement this interface.

// EmployeeStatutoryProfile represents the database model.
type EmployeeStatutoryProfile struct {
	ProfileID       uuid.UUID
	CompanyID       uuid.UUID
	UserID          uuid.UUID
	StatutoryCode   string
	OptIn           bool
	Regime          *string
	SpecialCategory *string
	EffectiveFrom   time.Time
	EffectiveTo     *time.Time
	IsActive        bool
	Version         int
	CreatedAt       time.Time
	CreatedBy       *uuid.UUID
	DeactivatedAt   *time.Time
	DeactivatedBy   *uuid.UUID
	RuleSetID       *uuid.UUID
}

// StatutoryProfileRepository defines data access methods.
type StatutoryProfileRepository interface {
	GetProfileByID(ctx context.Context, profileID uuid.UUID) (*EmployeeStatutoryProfile, error)
	GetActiveProfile(ctx context.Context, companyID, userID uuid.UUID, statutoryCode string, asOf time.Time) (*EmployeeStatutoryProfile, error)
	GetActiveProfilesForEmployee(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) ([]EmployeeStatutoryProfile, error)
	GetProfileHistory(ctx context.Context, companyID, userID uuid.UUID, statutoryCode string) ([]EmployeeStatutoryProfile, error)
	ListProfiles(ctx context.Context, filter *models.StatutoryProfileFilter) ([]EmployeeStatutoryProfile, int, error)
	InsertProfile(ctx context.Context, profile *EmployeeStatutoryProfile) error
	UpdateProfile(ctx context.Context, profile *EmployeeStatutoryProfile) error
	DeactivateProfile(ctx context.Context, profileID uuid.UUID, deactivatedBy uuid.UUID) error
	CloseActiveProfile(ctx context.Context, companyID, userID uuid.UUID, statutoryCode string, closeDate time.Time, closedBy uuid.UUID) error
	HasOverlappingActiveProfile(ctx context.Context, companyID, userID uuid.UUID, statutoryCode string, effectiveFrom time.Time, excludeProfileID *uuid.UUID) (bool, error)
	WithTx(ctx context.Context, fn func(StatutoryProfileRepository) error) error
}

// statutoryProfileRepository implements StatutoryProfileRepository.
type statutoryProfileRepository struct {
	db     DBTX
	logger *zap.Logger
}

// NewStatutoryProfileRepository creates a new repository.
func NewStatutoryProfileRepository(postgresClient *client.PostgresClient, logger *zap.Logger) StatutoryProfileRepository {
	return &statutoryProfileRepository{
		db:     postgresClient,
		logger: logger.Named("statutory_profile_repo"),
	}
}

// WithTx implements transactional execution.
func (r *statutoryProfileRepository) WithTx(ctx context.Context, fn func(StatutoryProfileRepository) error) error {
	pgClient, ok := r.db.(*client.PostgresClient)
	if !ok {
		return fmt.Errorf("WithTx can only be used with a PostgresClient-based repository")
	}

	tx, err := pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	txRepo := &statutoryProfileRepository{
		db:     &txQuerier{tx: tx},
		logger: r.logger,
	}

	if err := fn(txRepo); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			r.logger.Error("transaction rollback failed", zap.Error(rbErr))
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// scanner interface matches sql.Row and sql.Rows.
type scanner interface {
	Scan(dest ...interface{}) error
}

// scanProfile scans a row into an EmployeeStatutoryProfile.
func scanProfile(s scanner) (*EmployeeStatutoryProfile, error) {
	var p EmployeeStatutoryProfile
	var regime, specialCategory sql.NullString
	var effectiveTo, deactivatedAt sql.NullTime
	var createdBy, deactivatedBy, ruleSetID uuid.NullUUID
	var version int

	err := s.Scan(
		&p.ProfileID,
		&p.CompanyID,
		&p.UserID,
		&p.StatutoryCode,
		&p.OptIn,
		&regime,
		&specialCategory,
		&p.EffectiveFrom,
		&effectiveTo,
		&p.IsActive,
		&version,
		&p.CreatedAt,
		&createdBy,
		&deactivatedAt,
		&deactivatedBy,
		&ruleSetID,
	)
	if err != nil {
		return nil, err
	}

	if regime.Valid {
		p.Regime = &regime.String
	}
	if specialCategory.Valid {
		p.SpecialCategory = &specialCategory.String
	}
	if effectiveTo.Valid {
		p.EffectiveTo = &effectiveTo.Time
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	if deactivatedAt.Valid {
		p.DeactivatedAt = &deactivatedAt.Time
	}
	if deactivatedBy.Valid {
		p.DeactivatedBy = &deactivatedBy.UUID
	}
	if ruleSetID.Valid {
		p.RuleSetID = &ruleSetID.UUID
	}
	p.Version = version

	return &p, nil
}

// GetProfileByID implementation.
func (r *statutoryProfileRepository) GetProfileByID(ctx context.Context, profileID uuid.UUID) (*EmployeeStatutoryProfile, error) {
	const query = `
		SELECT profile_id, company_id, user_id, statutory_code, opt_in,
		       regime, special_category,
		       effective_from, effective_to, is_active, version,
		       created_at, created_by,
		       deactivated_at, deactivated_by, rule_set_id
		FROM payroll.employee_statutory_profile
		WHERE profile_id = $1
	`
	row := r.db.QueryRow(ctx, query, profileID)
	p, err := scanProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		r.logger.Error("failed to get profile by ID",
			util.String("profile_id", profileID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("get profile by ID: %w", err)
	}
	return p, nil
}

// GetActiveProfile implementation.
func (r *statutoryProfileRepository) GetActiveProfile(ctx context.Context, companyID, userID uuid.UUID, statutoryCode string, asOf time.Time) (*EmployeeStatutoryProfile, error) {
	const query = `
		SELECT profile_id, company_id, user_id, statutory_code, opt_in,
		       regime, special_category,
		       effective_from, effective_to, is_active, version,
		       created_at, created_by,
		       deactivated_at, deactivated_by, rule_set_id
		FROM payroll.employee_statutory_profile
		WHERE company_id = $1
		  AND user_id = $2
		  AND statutory_code = $3
		  AND is_active = true
		  AND effective_from <= $4
		  AND (effective_to IS NULL OR effective_to >= $4)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.db.QueryRow(ctx, query, companyID, userID, statutoryCode, asOf)
	p, err := scanProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		r.logger.Error("failed to get active profile",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("statutory_code", statutoryCode),
			util.Time("as_of", asOf),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("get active profile: %w", err)
	}
	return p, nil
}

// GetActiveProfilesForEmployee implementation.
func (r *statutoryProfileRepository) GetActiveProfilesForEmployee(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) ([]EmployeeStatutoryProfile, error) {
	const query = `
		SELECT profile_id, company_id, user_id, statutory_code, opt_in,
		       regime, special_category,
		       effective_from, effective_to, is_active, version,
		       created_at, created_by,
		       deactivated_at, deactivated_by, rule_set_id
		FROM payroll.employee_statutory_profile
		WHERE company_id = $1
		  AND user_id = $2
		  AND is_active = true
		  AND effective_from <= $3
		  AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY statutory_code, effective_from DESC
	`
	rows, err := r.db.Query(ctx, query, companyID, userID, asOf)
	if err != nil {
		r.logger.Error("failed to get active profiles for employee",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.Time("as_of", asOf),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("get active profiles: %w", err)
	}
	defer rows.Close()

	var profiles []EmployeeStatutoryProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan profile: %w", err)
		}
		profiles = append(profiles, *p)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return profiles, nil
}

// GetProfileHistory implementation.
func (r *statutoryProfileRepository) GetProfileHistory(ctx context.Context, companyID, userID uuid.UUID, statutoryCode string) ([]EmployeeStatutoryProfile, error) {
	const query = `
		SELECT profile_id, company_id, user_id, statutory_code, opt_in,
		       regime, special_category,
		       effective_from, effective_to, is_active, version,
		       created_at, created_by,
		       deactivated_at, deactivated_by, rule_set_id
		FROM payroll.employee_statutory_profile
		WHERE company_id = $1
		  AND user_id = $2
		  AND statutory_code = $3
		ORDER BY effective_from DESC
	`
	rows, err := r.db.Query(ctx, query, companyID, userID, statutoryCode)
	if err != nil {
		r.logger.Error("failed to get profile history",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("statutory_code", statutoryCode),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("get profile history: %w", err)
	}
	defer rows.Close()

	var profiles []EmployeeStatutoryProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan profile: %w", err)
		}
		profiles = append(profiles, *p)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return profiles, nil
}

// ListProfiles implementation.
func (r *statutoryProfileRepository) ListProfiles(ctx context.Context, filter *models.StatutoryProfileFilter) ([]EmployeeStatutoryProfile, int, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("company_id = $%d", argIdx))
	args = append(args, filter.CompanyID)
	argIdx++

	if filter.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, *filter.UserID)
		argIdx++
	}
	if filter.StatutoryCode != nil {
		conditions = append(conditions, fmt.Sprintf("statutory_code = $%d", argIdx))
		args = append(args, *filter.StatutoryCode)
		argIdx++
	}
	if filter.ActiveOn != nil {
		conditions = append(conditions, fmt.Sprintf("effective_from <= $%d", argIdx))
		args = append(args, *filter.ActiveOn)
		argIdx++
		conditions = append(conditions, fmt.Sprintf("(effective_to IS NULL OR effective_to >= $%d)", argIdx))
		args = append(args, *filter.ActiveOn)
		argIdx++
		conditions = append(conditions, "is_active = true")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM payroll.employee_statutory_profile %s", whereClause)
	var total int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		r.logger.Error("failed to count profiles", util.ErrorField(err))
		return nil, 0, fmt.Errorf("count profiles: %w", err)
	}

	// Pagination
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 || filter.PageSize > 100 {
		filter.PageSize = 20
	}
	offset := (filter.Page - 1) * filter.PageSize

	dataQuery := fmt.Sprintf(`
		SELECT profile_id, company_id, user_id, statutory_code, opt_in,
		       regime, special_category,
		       effective_from, effective_to, is_active, version,
		       created_at, created_by,
		       deactivated_at, deactivated_by, rule_set_id
		FROM payroll.employee_statutory_profile
		%s
		ORDER BY effective_from DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, filter.PageSize, offset)

	rows, err := r.db.Query(ctx, dataQuery, args...)
	if err != nil {
		r.logger.Error("failed to list profiles", util.ErrorField(err))
		return nil, 0, fmt.Errorf("list profiles: %w", err)
	}
	defer rows.Close()

	var profiles []EmployeeStatutoryProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan profile: %w", err)
		}
		profiles = append(profiles, *p)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}
	return profiles, total, nil
}

// InsertProfile implementation.
func (r *statutoryProfileRepository) InsertProfile(ctx context.Context, p *EmployeeStatutoryProfile) error {
	const query = `
		INSERT INTO payroll.employee_statutory_profile (
			profile_id, company_id, user_id, statutory_code, opt_in,
			regime, special_category,
			effective_from, effective_to, is_active, version,
			created_at, created_by,
			deactivated_at, deactivated_by, rule_set_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
		          $12, $13, $14, $15, $16)
	`
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	p.Version = 1

	_, err := r.db.Exec(ctx, query,
		p.ProfileID,
		p.CompanyID,
		p.UserID,
		p.StatutoryCode,
		p.OptIn,
		nullString(p.Regime),
		nullString(p.SpecialCategory),
		p.EffectiveFrom,
		nullTime(p.EffectiveTo),
		p.IsActive,
		p.Version,
		p.CreatedAt,
		nullUUID(p.CreatedBy),
		nullTime(p.DeactivatedAt),
		nullUUID(p.DeactivatedBy),
		nullUUID(p.RuleSetID),
	)
	if err != nil {
		r.logger.Error("failed to insert profile",
			util.String("profile_id", p.ProfileID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("insert profile: %w", err)
	}
	return nil
}

// UpdateProfile updates non-temporal fields and increments version.
func (r *statutoryProfileRepository) UpdateProfile(ctx context.Context, p *EmployeeStatutoryProfile) error {
	const query = `
		UPDATE payroll.employee_statutory_profile
		SET opt_in = $1,
		    regime = $2,
		    special_category = $3,
		    version = version + 1
		WHERE profile_id = $4
		  AND version = $5
	`
	result, err := r.db.Exec(ctx, query,
		p.OptIn,
		nullString(p.Regime),
		nullString(p.SpecialCategory),
		p.ProfileID,
		p.Version,
	)
	if err != nil {
		r.logger.Error("failed to update profile",
			util.String("profile_id", p.ProfileID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("update profile: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("profile %s not found or version mismatch", p.ProfileID)
	}
	p.Version++
	return nil
}

// DeactivateProfile sets effective_to and deactivation timestamps.
func (r *statutoryProfileRepository) DeactivateProfile(ctx context.Context, profileID uuid.UUID, deactivatedBy uuid.UUID) error {
	const query = `
		UPDATE payroll.employee_statutory_profile
		SET effective_to = $2,
		    is_active = false,
		    version = version + 1,
		    deactivated_at = $3,
		    deactivated_by = $4
		WHERE profile_id = $1
		  AND is_active = true
	`
	now := time.Now().UTC()
	// Set effective_to to one day before now (or could be a parameter)
	effectiveTo := now.AddDate(0, 0, -1)
	result, err := r.db.Exec(ctx, query, profileID, effectiveTo, now, deactivatedBy)
	if err != nil {
		r.logger.Error("failed to deactivate profile",
			util.String("profile_id", profileID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("deactivate profile: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("profile %s not found or already inactive", profileID)
	}
	return nil
}

// CloseActiveProfile ends the currently active profile by setting its effective_to to closeDate-1.
func (r *statutoryProfileRepository) CloseActiveProfile(ctx context.Context, companyID, userID uuid.UUID, statutoryCode string, closeDate time.Time, closedBy uuid.UUID) error {
	const query = `
		UPDATE payroll.employee_statutory_profile
		SET effective_to = $4,
		    version = version + 1
		WHERE company_id = $1
		  AND user_id = $2
		  AND statutory_code = $3
		  AND is_active = true
		  AND effective_from < $4
		  AND (effective_to IS NULL OR effective_to >= $4)
	`
	closeDateMinusOne := closeDate.AddDate(0, 0, -1)
	result, err := r.db.Exec(ctx, query, companyID, userID, statutoryCode, closeDateMinusOne)
	if err != nil {
		r.logger.Error("failed to close active profile",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("statutory_code", statutoryCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("close active profile: %w", err)
	}
	// It's okay if no row was updated (no active profile)
	_ = result
	return nil
}

// HasOverlappingActiveProfile checks for overlap.
func (r *statutoryProfileRepository) HasOverlappingActiveProfile(ctx context.Context, companyID, userID uuid.UUID, statutoryCode string, effectiveFrom time.Time, excludeProfileID *uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM payroll.employee_statutory_profile
			WHERE company_id = $1
			  AND user_id = $2
			  AND statutory_code = $3
			  AND is_active = true
			  AND effective_from <= $4
			  AND (effective_to IS NULL OR effective_to >= $4)
	`
	args := []interface{}{companyID, userID, statutoryCode, effectiveFrom}
	if excludeProfileID != nil {
		query += " AND profile_id != $" + fmt.Sprint(len(args)+1)
		args = append(args, *excludeProfileID)
	}
	query += ")"

	var exists bool
	err := r.db.QueryRow(ctx, query, args...).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check overlapping profile",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("statutory_code", statutoryCode),
			util.Time("effective_from", effectiveFrom),
			util.ErrorField(err),
		)
		return false, fmt.Errorf("check overlap: %w", err)
	}
	return exists, nil
}

// --------------------------------------------------------------------------
// Null helpers
// --------------------------------------------------------------------------

func nullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: *s, Valid: true}
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func nullUUID(u *uuid.UUID) uuid.NullUUID {
	if u == nil {
		return uuid.NullUUID{Valid: false}
	}
	return uuid.NullUUID{UUID: *u, Valid: true}
}
