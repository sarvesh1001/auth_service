package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
)

// BankDetailsRepository defines operations for employee bank details.
type BankDetailsRepository interface {
	Create(ctx context.Context, bank *models.EmployeeBankDetails) error
	Update(ctx context.Context, bank *models.EmployeeBankDetails) error
	Deactivate(ctx context.Context, bankDetailID uuid.UUID, deactivatedBy uuid.UUID) error
	GetByID(ctx context.Context, bankDetailID uuid.UUID) (*models.EmployeeBankDetails, error)
	GetActiveByUser(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) (*models.EmployeeBankDetails, error)
	ListByUser(ctx context.Context, companyID, userID uuid.UUID) ([]models.EmployeeBankDetails, error)
	// For payroll run: get bank details for many employees at once
	GetBankDetailsForPayrollRun(ctx context.Context, companyID uuid.UUID, userIDs []uuid.UUID) (map[uuid.UUID]models.EmployeeBankDetails, error)
}

type bankDetailsRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewBankDetailsRepository creates a new PostgreSQL implementation of BankDetailsRepository.
func NewBankDetailsRepository(postgresClient *client.PostgresClient, logger *zap.Logger) BankDetailsRepository {
	return &bankDetailsRepository{
		client: postgresClient,
		logger: logger.Named("bank_details_repo"),
	}
}

// Create inserts a new bank detail record.
func (r *bankDetailsRepository) Create(ctx context.Context, bank *models.EmployeeBankDetails) error {
	if bank.BankDetailID == uuid.Nil {
		bank.BankDetailID = uuid.New()
	}
	if bank.CreatedAt.IsZero() {
		bank.CreatedAt = time.Now().UTC()
	}
	if bank.UpdatedAt.IsZero() {
		bank.UpdatedAt = bank.CreatedAt
	}

	query := `
		INSERT INTO payroll.employee_bank_details (
			bank_detail_id, company_id, user_id,
			account_holder, account_number, ifsc_code,
			bank_name, branch, account_type,
			is_active, effective_from, effective_to,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err := r.client.Exec(ctx, query,
		bank.BankDetailID,
		bank.CompanyID,
		bank.UserID,
		bank.AccountHolder,
		bank.AccountNumber,
		bank.IFSCCode,
		bank.BankName,
		bank.Branch,
		bank.AccountType,
		bank.IsActive,
		bank.EffectiveFrom,
		nullTime(bank.EffectiveTo),
		bank.CreatedAt,
		bank.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create bank details",
			util.String("bank_detail_id", bank.BankDetailID.String()),
			util.String("company_id", bank.CompanyID.String()),
			util.String("user_id", bank.UserID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create bank details: %w", err)
	}
	return nil
}

// Update modifies an existing bank detail record.
func (r *bankDetailsRepository) Update(ctx context.Context, bank *models.EmployeeBankDetails) error {
	bank.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE payroll.employee_bank_details
		SET
			account_holder = $1,
			account_number = $2,
			ifsc_code = $3,
			bank_name = $4,
			branch = $5,
			account_type = $6,
			is_active = $7,
			effective_from = $8,
			effective_to = $9,
			updated_at = $10
		WHERE bank_detail_id = $11
	`

	result, err := r.client.Exec(ctx, query,
		bank.AccountHolder,
		bank.AccountNumber,
		bank.IFSCCode,
		bank.BankName,
		bank.Branch,
		bank.AccountType,
		bank.IsActive,
		bank.EffectiveFrom,
		nullTime(bank.EffectiveTo),
		bank.UpdatedAt,
		bank.BankDetailID,
	)
	if err != nil {
		r.logger.Error("Failed to update bank details",
			util.String("bank_detail_id", bank.BankDetailID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update bank details: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("bank details not found")
	}
	return nil
}

// Deactivate soft‑deactivates a bank detail record by setting is_active = false and effective_to.
func (r *bankDetailsRepository) Deactivate(ctx context.Context, bankDetailID uuid.UUID, deactivatedBy uuid.UUID) error {
	now := time.Now().UTC()
	effectiveTo := now.AddDate(0, 0, -1) // make it end yesterday

	query := `
		UPDATE payroll.employee_bank_details
		SET
			is_active = false,
			effective_to = $1,
			updated_at = $2
		WHERE bank_detail_id = $3
	`

	result, err := r.client.Exec(ctx, query, effectiveTo, now, bankDetailID)
	if err != nil {
		r.logger.Error("Failed to deactivate bank details",
			util.String("bank_detail_id", bankDetailID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to deactivate bank details: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("bank details not found")
	}
	return nil
}

// GetByID retrieves a bank detail record by its ID.
func (r *bankDetailsRepository) GetByID(ctx context.Context, bankDetailID uuid.UUID) (*models.EmployeeBankDetails, error) {
	query := `
		SELECT
			bank_detail_id, company_id, user_id,
			account_holder, account_number, ifsc_code,
			bank_name, branch, account_type,
			is_active, effective_from, effective_to,
			created_at, updated_at
		FROM payroll.employee_bank_details
		WHERE bank_detail_id = $1
	`

	row := r.client.QueryRow(ctx, query, bankDetailID)
	bank, err := r.scanBankDetails(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get bank details by ID",
			util.String("bank_detail_id", bankDetailID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get bank details: %w", err)
	}
	return bank, nil
}

// GetActiveByUser returns the active bank details for a user at a given date.
func (r *bankDetailsRepository) GetActiveByUser(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) (*models.EmployeeBankDetails, error) {
	query := `
		SELECT
			bank_detail_id, company_id, user_id,
			account_holder, account_number, ifsc_code,
			bank_name, branch, account_type,
			is_active, effective_from, effective_to,
			created_at, updated_at
		FROM payroll.employee_bank_details
		WHERE company_id = $1
		  AND user_id = $2
		  AND is_active = true
		  AND effective_from <= $3
		  AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY effective_from DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, userID, asOf)
	bank, err := r.scanBankDetails(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get active bank details by user",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.Time("as_of", asOf),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get active bank details: %w", err)
	}
	return bank, nil
}

// ListByUser returns all bank detail records (active and inactive) for a user.
func (r *bankDetailsRepository) ListByUser(ctx context.Context, companyID, userID uuid.UUID) ([]models.EmployeeBankDetails, error) {
	query := `
		SELECT
			bank_detail_id, company_id, user_id,
			account_holder, account_number, ifsc_code,
			bank_name, branch, account_type,
			is_active, effective_from, effective_to,
			created_at, updated_at
		FROM payroll.employee_bank_details
		WHERE company_id = $1 AND user_id = $2
		ORDER BY effective_from DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		r.logger.Error("Failed to list bank details by user",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list bank details: %w", err)
	}
	defer rows.Close()

	var banks []models.EmployeeBankDetails
	for rows.Next() {
		bank, err := r.scanBankDetails(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan bank details: %w", err)
		}
		banks = append(banks, *bank)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return banks, nil
}

// GetBankDetailsForPayrollRun returns a map of userID → active bank details for the given list of userIDs.
func (r *bankDetailsRepository) GetBankDetailsForPayrollRun(ctx context.Context, companyID uuid.UUID, userIDs []uuid.UUID) (map[uuid.UUID]models.EmployeeBankDetails, error) {
	if len(userIDs) == 0 {
		return make(map[uuid.UUID]models.EmployeeBankDetails), nil
	}

	// Use array ANY to fetch all at once
	query := `
		SELECT
			bank_detail_id, company_id, user_id,
			account_holder, account_number, ifsc_code,
			bank_name, branch, account_type,
			is_active, effective_from, effective_to,
			created_at, updated_at
		FROM payroll.employee_bank_details
		WHERE company_id = $1
		  AND user_id = ANY($2)
		  AND is_active = true
		  AND effective_from <= NOW()
		  AND (effective_to IS NULL OR effective_to >= NOW())
		ORDER BY user_id, effective_from DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, userIDs)
	if err != nil {
		r.logger.Error("Failed to get bank details for payroll run",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get bank details for payroll run: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID]models.EmployeeBankDetails)
	for rows.Next() {
		bank, err := r.scanBankDetails(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan bank details: %w", err)
		}
		// If multiple rows per user (due to different effective_from), we take the first (most recent)
		if _, exists := result[bank.UserID]; !exists {
			result[bank.UserID] = *bank
		}
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return result, nil
}

// scanBankDetails is a helper to scan a row into an EmployeeBankDetails struct.
func (r *bankDetailsRepository) scanBankDetails(row scanner) (*models.EmployeeBankDetails, error) {
	var b models.EmployeeBankDetails
	var effectiveTo sql.NullTime
	var createdAt, updatedAt time.Time

	err := row.Scan(
		&b.BankDetailID,
		&b.CompanyID,
		&b.UserID,
		&b.AccountHolder,
		&b.AccountNumber,
		&b.IFSCCode,
		&b.BankName,
		&b.Branch,
		&b.AccountType,
		&b.IsActive,
		&b.EffectiveFrom,
		&effectiveTo,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, err
	}

	if effectiveTo.Valid {
		b.EffectiveTo = &effectiveTo.Time
	}
	b.CreatedAt = createdAt
	b.UpdatedAt = updatedAt
	return &b, nil
}
