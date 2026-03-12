package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
)

// TaxDeclarationRepository defines operations for tax declaration types and employee declarations.
type TaxDeclarationRepository interface {
	// Declaration type management
	CreateDeclarationType(ctx context.Context, dt *models.TaxDeclarationType) error
	UpdateDeclarationType(ctx context.Context, dt *models.TaxDeclarationType) error
	GetDeclarationType(ctx context.Context, companyID uuid.UUID, typeCode string) (*models.TaxDeclarationType, error)
	ListDeclarationTypes(ctx context.Context, companyID uuid.UUID) ([]models.TaxDeclarationType, error)

	// Employee declaration management
	CreateDeclaration(ctx context.Context, decl *models.TaxDeclaration) error
	UpdateDeclaration(ctx context.Context, decl *models.TaxDeclaration) error
	GetDeclarationByID(ctx context.Context, declarationID uuid.UUID) (*models.TaxDeclaration, error)
	ListDeclarationsByUser(ctx context.Context, companyID, userID uuid.UUID, financialYear string) ([]models.TaxDeclaration, error)
	ListDeclarationsByFinancialYear(ctx context.Context, companyID uuid.UUID, financialYear string, status *string) ([]models.TaxDeclaration, error)
	VerifyDeclaration(ctx context.Context, declarationID uuid.UUID, verifiedBy uuid.UUID, status string) error
}

type taxDeclarationRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewTaxDeclarationRepository creates a new tax declaration repository.
func NewTaxDeclarationRepository(postgresClient *client.PostgresClient, logger *zap.Logger) TaxDeclarationRepository {
	return &taxDeclarationRepository{
		client: postgresClient,
		logger: logger.Named("tax_declaration_repo"),
	}
}

// ------------------- Declaration Types -------------------

func (r *taxDeclarationRepository) CreateDeclarationType(ctx context.Context, dt *models.TaxDeclarationType) error {
	if dt.CreatedAt.IsZero() {
		dt.CreatedAt = time.Now().UTC()
	}
	if dt.UpdatedAt.IsZero() {
		dt.UpdatedAt = dt.CreatedAt
	}

	query := `
		INSERT INTO payroll.tax_declaration_type (
			company_id, type_code, description, max_limit, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.client.Exec(ctx, query,
		dt.CompanyID,
		dt.TypeCode,
		dt.Description,
		nullFloat64(dt.MaxLimit),
		dt.IsActive,
		dt.CreatedAt,
		dt.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create tax declaration type",
			util.String("company_id", dt.CompanyID.String()),
			util.String("type_code", dt.TypeCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create tax declaration type: %w", err)
	}
	return nil
}

func (r *taxDeclarationRepository) UpdateDeclarationType(ctx context.Context, dt *models.TaxDeclarationType) error {
	dt.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE payroll.tax_declaration_type
		SET description = $1, max_limit = $2, is_active = $3, updated_at = $4
		WHERE company_id = $5 AND type_code = $6
	`
	result, err := r.client.Exec(ctx, query,
		dt.Description,
		nullFloat64(dt.MaxLimit),
		dt.IsActive,
		dt.UpdatedAt,
		dt.CompanyID,
		dt.TypeCode,
	)
	if err != nil {
		r.logger.Error("Failed to update tax declaration type",
			util.String("company_id", dt.CompanyID.String()),
			util.String("type_code", dt.TypeCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update tax declaration type: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("tax declaration type not found")
	}
	return nil
}

func (r *taxDeclarationRepository) GetDeclarationType(ctx context.Context, companyID uuid.UUID, typeCode string) (*models.TaxDeclarationType, error) {
	query := `
		SELECT company_id, type_code, description, max_limit, is_active, created_at, updated_at
		FROM payroll.tax_declaration_type
		WHERE company_id = $1 AND type_code = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, typeCode)
	var dt models.TaxDeclarationType
	var maxLimit sql.NullFloat64

	err := row.Scan(
		&dt.CompanyID,
		&dt.TypeCode,
		&dt.Description,
		&maxLimit,
		&dt.IsActive,
		&dt.CreatedAt,
		&dt.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get tax declaration type",
			util.String("company_id", companyID.String()),
			util.String("type_code", typeCode),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get tax declaration type: %w", err)
	}
	if maxLimit.Valid {
		dt.MaxLimit = &maxLimit.Float64
	}
	return &dt, nil
}

func (r *taxDeclarationRepository) ListDeclarationTypes(ctx context.Context, companyID uuid.UUID) ([]models.TaxDeclarationType, error) {
	query := `
		SELECT company_id, type_code, description, max_limit, is_active, created_at, updated_at
		FROM payroll.tax_declaration_type
		WHERE company_id = $1
		ORDER BY type_code
	`
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to list tax declaration types",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list tax declaration types: %w", err)
	}
	defer rows.Close()

	var types []models.TaxDeclarationType
	for rows.Next() {
		var dt models.TaxDeclarationType
		var maxLimit sql.NullFloat64

		if err := rows.Scan(
			&dt.CompanyID,
			&dt.TypeCode,
			&dt.Description,
			&maxLimit,
			&dt.IsActive,
			&dt.CreatedAt,
			&dt.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan tax declaration type: %w", err)
		}
		if maxLimit.Valid {
			dt.MaxLimit = &maxLimit.Float64
		}
		types = append(types, dt)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return types, nil
}

// ------------------- Employee Declarations -------------------

func (r *taxDeclarationRepository) CreateDeclaration(ctx context.Context, decl *models.TaxDeclaration) error {
	if decl.DeclarationID == uuid.Nil {
		decl.DeclarationID = uuid.New()
	}
	if decl.CreatedAt.IsZero() {
		decl.CreatedAt = time.Now().UTC()
	}
	if decl.UpdatedAt.IsZero() {
		decl.UpdatedAt = decl.CreatedAt
	}
	if decl.SubmittedAt.IsZero() {
		decl.SubmittedAt = decl.CreatedAt
	}

	query := `
		INSERT INTO payroll.tax_declaration (
			declaration_id, company_id, user_id, financial_year, declaration_type,
			amount, supporting_docs, status, submitted_at, verified_at, verified_by,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := r.client.Exec(ctx, query,
		decl.DeclarationID,
		decl.CompanyID,
		decl.UserID,
		decl.FinancialYear,
		decl.DeclarationType,
		decl.Amount,
		pq.Array(decl.SupportingDocs),
		decl.Status,
		decl.SubmittedAt,
		nullTime(decl.VerifiedAt),
		nullUUID(decl.VerifiedBy),
		decl.CreatedAt,
		decl.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create tax declaration",
			util.String("declaration_id", decl.DeclarationID.String()),
			util.String("company_id", decl.CompanyID.String()),
			util.String("user_id", decl.UserID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create tax declaration: %w", err)
	}
	return nil
}

func (r *taxDeclarationRepository) UpdateDeclaration(ctx context.Context, decl *models.TaxDeclaration) error {
	decl.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE payroll.tax_declaration
		SET amount = $1, supporting_docs = $2, status = $3, updated_at = $4
		WHERE declaration_id = $5
	`
	result, err := r.client.Exec(ctx, query,
		decl.Amount,
		pq.Array(decl.SupportingDocs),
		decl.Status,
		decl.UpdatedAt,
		decl.DeclarationID,
	)
	if err != nil {
		r.logger.Error("Failed to update tax declaration",
			util.String("declaration_id", decl.DeclarationID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update tax declaration: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("tax declaration not found")
	}
	return nil
}

func (r *taxDeclarationRepository) GetDeclarationByID(ctx context.Context, declarationID uuid.UUID) (*models.TaxDeclaration, error) {
	query := `
		SELECT
			declaration_id, company_id, user_id, financial_year, declaration_type,
			amount, supporting_docs, status, submitted_at, verified_at, verified_by,
			created_at, updated_at
		FROM payroll.tax_declaration
		WHERE declaration_id = $1
	`
	row := r.client.QueryRow(ctx, query, declarationID)
	var decl models.TaxDeclaration
	var verifiedAt sql.NullTime
	var verifiedBy uuid.NullUUID
	var docs []string

	err := row.Scan(
		&decl.DeclarationID,
		&decl.CompanyID,
		&decl.UserID,
		&decl.FinancialYear,
		&decl.DeclarationType,
		&decl.Amount,
		pq.Array(&docs),
		&decl.Status,
		&decl.SubmittedAt,
		&verifiedAt,
		&verifiedBy,
		&decl.CreatedAt,
		&decl.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get tax declaration by ID",
			util.String("declaration_id", declarationID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get tax declaration: %w", err)
	}
	decl.SupportingDocs = docs
	if verifiedAt.Valid {
		decl.VerifiedAt = &verifiedAt.Time
	}
	if verifiedBy.Valid {
		decl.VerifiedBy = &verifiedBy.UUID
	}
	return &decl, nil
}

func (r *taxDeclarationRepository) ListDeclarationsByUser(ctx context.Context, companyID, userID uuid.UUID, financialYear string) ([]models.TaxDeclaration, error) {
	query := `
		SELECT
			declaration_id, company_id, user_id, financial_year, declaration_type,
			amount, supporting_docs, status, submitted_at, verified_at, verified_by,
			created_at, updated_at
		FROM payroll.tax_declaration
		WHERE company_id = $1 AND user_id = $2 AND financial_year = $3
		ORDER BY declaration_type
	`
	rows, err := r.client.Query(ctx, query, companyID, userID, financialYear)
	if err != nil {
		r.logger.Error("Failed to list declarations by user",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("financial_year", financialYear),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list declarations: %w", err)
	}
	defer rows.Close()

	var declarations []models.TaxDeclaration
	for rows.Next() {
		var decl models.TaxDeclaration
		var verifiedAt sql.NullTime
		var verifiedBy uuid.NullUUID
		var docs []string

		if err := rows.Scan(
			&decl.DeclarationID,
			&decl.CompanyID,
			&decl.UserID,
			&decl.FinancialYear,
			&decl.DeclarationType,
			&decl.Amount,
			pq.Array(&docs),
			&decl.Status,
			&decl.SubmittedAt,
			&verifiedAt,
			&verifiedBy,
			&decl.CreatedAt,
			&decl.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan tax declaration: %w", err)
		}
		decl.SupportingDocs = docs
		if verifiedAt.Valid {
			decl.VerifiedAt = &verifiedAt.Time
		}
		if verifiedBy.Valid {
			decl.VerifiedBy = &verifiedBy.UUID
		}
		declarations = append(declarations, decl)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return declarations, nil
}

func (r *taxDeclarationRepository) ListDeclarationsByFinancialYear(ctx context.Context, companyID uuid.UUID, financialYear string, status *string) ([]models.TaxDeclaration, error) {
	query := `
		SELECT
			declaration_id, company_id, user_id, financial_year, declaration_type,
			amount, supporting_docs, status, submitted_at, verified_at, verified_by,
			created_at, updated_at
		FROM payroll.tax_declaration
		WHERE company_id = $1 AND financial_year = $2
	`
	args := []interface{}{companyID, financialYear}
	if status != nil {
		query += " AND status = $3"
		args = append(args, *status)
	}
	query += " ORDER BY user_id, declaration_type"

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to list declarations by financial year",
			util.String("company_id", companyID.String()),
			util.String("financial_year", financialYear),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list declarations: %w", err)
	}
	defer rows.Close()

	var declarations []models.TaxDeclaration
	for rows.Next() {
		var decl models.TaxDeclaration
		var verifiedAt sql.NullTime
		var verifiedBy uuid.NullUUID
		var docs []string

		if err := rows.Scan(
			&decl.DeclarationID,
			&decl.CompanyID,
			&decl.UserID,
			&decl.FinancialYear,
			&decl.DeclarationType,
			&decl.Amount,
			pq.Array(&docs),
			&decl.Status,
			&decl.SubmittedAt,
			&verifiedAt,
			&verifiedBy,
			&decl.CreatedAt,
			&decl.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan tax declaration: %w", err)
		}
		decl.SupportingDocs = docs
		if verifiedAt.Valid {
			decl.VerifiedAt = &verifiedAt.Time
		}
		if verifiedBy.Valid {
			decl.VerifiedBy = &verifiedBy.UUID
		}
		declarations = append(declarations, decl)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return declarations, nil
}

func (r *taxDeclarationRepository) VerifyDeclaration(ctx context.Context, declarationID uuid.UUID, verifiedBy uuid.UUID, status string) error {
	now := time.Now().UTC()
	query := `
		UPDATE payroll.tax_declaration
		SET status = $1, verified_at = $2, verified_by = $3, updated_at = $2
		WHERE declaration_id = $4
	`
	result, err := r.client.Exec(ctx, query, status, now, verifiedBy, declarationID)
	if err != nil {
		r.logger.Error("Failed to verify tax declaration",
			util.String("declaration_id", declarationID.String()),
			util.String("status", status),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to verify declaration: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("declaration not found")
	}
	return nil
}
