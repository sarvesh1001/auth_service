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
	"auth-service/internal/encryption"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
)

type BankDetailsRepository interface {
	Create(ctx context.Context, bank *models.EmployeeBankDetails) error
	Update(ctx context.Context, bank *models.EmployeeBankDetails) error
	Deactivate(ctx context.Context, bankDetailID uuid.UUID, deactivatedBy uuid.UUID) error
	GetByID(ctx context.Context, bankDetailID uuid.UUID) (*models.EmployeeBankDetails, error)
	GetActiveByUser(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) (*models.EmployeeBankDetails, error)
	ListByUser(ctx context.Context, companyID, userID uuid.UUID) ([]models.EmployeeBankDetails, error)
	GetBankDetailsForPayrollRun(ctx context.Context, companyID uuid.UUID, userIDs []uuid.UUID) (map[uuid.UUID]models.EmployeeBankDetails, error)
	Activate(ctx context.Context, bankDetailID uuid.UUID, actorID uuid.UUID) error
}

type bankDetailsRepository struct {
	client     *client.PostgresClient
	logger     *zap.Logger
	encryption *encryption.EncryptionManager
}

func NewBankDetailsRepository(
	postgresClient *client.PostgresClient,
	encryptionManager *encryption.EncryptionManager,
	logger *zap.Logger,
) BankDetailsRepository {
	return &bankDetailsRepository{
		client:     postgresClient,
		encryption: encryptionManager,
		logger:     logger.Named("bank_details_repo"),
	}
}

func (r *bankDetailsRepository) Create(ctx context.Context, bank *models.EmployeeBankDetails) error {

	if bank.BankDetailID == uuid.Nil {
		bank.BankDetailID = uuid.New()
	}

	now := time.Now().UTC()
	bank.CreatedAt = now
	bank.UpdatedAt = now

	encAccount, err := r.encryption.EncryptField(ctx, bank.AccountNumber, "bank_account")
	if err != nil {
		return err
	}

	encIFSC, err := r.encryption.EncryptField(ctx, bank.IFSCCode, "bank_ifsc")
	if err != nil {
		return err
	}

	query := `
	INSERT INTO payroll.employee_bank_details (
		bank_detail_id, company_id, user_id,
		account_holder,

		account_number,
		account_number_dek,
		account_number_key_id,

		ifsc_code,
		ifsc_code_dek,
		ifsc_code_key_id,

		bank_name, branch, account_type,
		is_active, effective_from, effective_to,
		created_at, updated_at
	)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
	`

	_, err = r.client.Exec(ctx, query,
		bank.BankDetailID,
		bank.CompanyID,
		bank.UserID,
		bank.AccountHolder,

		encAccount.EncryptedValue,
		encAccount.EncryptedDEK,
		encAccount.KeyID,

		encIFSC.EncryptedValue,
		encIFSC.EncryptedDEK,
		encIFSC.KeyID,

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
		r.logger.Error("failed to create bank details", util.ErrorField(err))
		return err
	}

	return nil
}

func (r *bankDetailsRepository) Update(ctx context.Context, bank *models.EmployeeBankDetails) error {

	bank.UpdatedAt = time.Now().UTC()

	encAccount, err := r.encryption.EncryptField(ctx, bank.AccountNumber, "bank_account")
	if err != nil {
		return err
	}

	encIFSC, err := r.encryption.EncryptField(ctx, bank.IFSCCode, "bank_ifsc")
	if err != nil {
		return err
	}

	query := `
	UPDATE payroll.employee_bank_details
	SET
	account_holder=$1,

	account_number=$2,
	account_number_dek=$3,
	account_number_key_id=$4,

	ifsc_code=$5,
	ifsc_code_dek=$6,
	ifsc_code_key_id=$7,

	bank_name=$8,
	branch=$9,
	account_type=$10,
	is_active=$11,
	effective_from=$12,
	effective_to=$13,
	updated_at=$14
	WHERE bank_detail_id=$15
	`

	result, err := r.client.Exec(ctx, query,
		bank.AccountHolder,

		encAccount.EncryptedValue,
		encAccount.EncryptedDEK,
		encAccount.KeyID,

		encIFSC.EncryptedValue,
		encIFSC.EncryptedDEK,
		encIFSC.KeyID,

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
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("bank details not found")
	}

	return nil
}

func (r *bankDetailsRepository) Deactivate(ctx context.Context, bankDetailID uuid.UUID, deactivatedBy uuid.UUID) error {

	now := time.Now().UTC()

	query := `
	UPDATE payroll.employee_bank_details
	SET is_active=false,
	effective_to=$1,
	updated_at=$2
	WHERE bank_detail_id=$3
	`

	result, err := r.client.Exec(ctx, query, now, now, bankDetailID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("bank details not found")
	}

	return nil
}

func (r *bankDetailsRepository) GetByID(ctx context.Context, bankDetailID uuid.UUID) (*models.EmployeeBankDetails, error) {

	query := `
	SELECT
	bank_detail_id, company_id, user_id,
	account_holder,

	account_number,
	account_number_dek,
	account_number_key_id,

	ifsc_code,
	ifsc_code_dek,
	ifsc_code_key_id,

	bank_name, branch, account_type,
	is_active, effective_from, effective_to,
	created_at, updated_at
	FROM payroll.employee_bank_details
	WHERE bank_detail_id=$1
	`

	row := r.client.QueryRow(ctx, query, bankDetailID)

	return r.scanBankDetails(ctx, row)
}

func (r *bankDetailsRepository) GetActiveByUser(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) (*models.EmployeeBankDetails, error) {

	query := `
	SELECT
	bank_detail_id, company_id, user_id,
	account_holder,

	account_number,
	account_number_dek,
	account_number_key_id,

	ifsc_code,
	ifsc_code_dek,
	ifsc_code_key_id,

	bank_name, branch, account_type,
	is_active, effective_from, effective_to,
	created_at, updated_at
	FROM payroll.employee_bank_details
	WHERE company_id=$1
	AND user_id=$2
	AND is_active=true
	AND effective_from <= $3
	AND (effective_to IS NULL OR effective_to >= $3)
	ORDER BY effective_from DESC
	LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, userID, asOf)

	return r.scanBankDetails(ctx, row)
}

func (r *bankDetailsRepository) ListByUser(ctx context.Context, companyID, userID uuid.UUID) ([]models.EmployeeBankDetails, error) {

	query := `
	SELECT
	bank_detail_id, company_id, user_id,
	account_holder,

	account_number,
	account_number_dek,
	account_number_key_id,

	ifsc_code,
	ifsc_code_dek,
	ifsc_code_key_id,

	bank_name, branch, account_type,
	is_active, effective_from, effective_to,
	created_at, updated_at
	FROM payroll.employee_bank_details
	WHERE company_id=$1 AND user_id=$2
	ORDER BY effective_from DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var banks []models.EmployeeBankDetails

	for rows.Next() {
		bank, err := r.scanBankDetails(ctx, rows)
		if err != nil {
			return nil, err
		}
		banks = append(banks, *bank)
	}

	return banks, nil
}

func (r *bankDetailsRepository) GetBankDetailsForPayrollRun(ctx context.Context, companyID uuid.UUID, userIDs []uuid.UUID) (map[uuid.UUID]models.EmployeeBankDetails, error) {

	if len(userIDs) == 0 {
		return map[uuid.UUID]models.EmployeeBankDetails{}, nil
	}

	query := `
	SELECT
	bank_detail_id, company_id, user_id,
	account_holder,

	account_number,
	account_number_dek,
	account_number_key_id,

	ifsc_code,
	ifsc_code_dek,
	ifsc_code_key_id,

	bank_name, branch, account_type,
	is_active, effective_from, effective_to,
	created_at, updated_at
	FROM payroll.employee_bank_details
	WHERE company_id=$1
	AND user_id = ANY($2)
	AND is_active=true
	AND effective_from <= NOW()
	AND (effective_to IS NULL OR effective_to >= NOW())
	ORDER BY user_id,effective_from DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, pq.Array(userIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[uuid.UUID]models.EmployeeBankDetails)

	for rows.Next() {
		bank, err := r.scanBankDetails(ctx, rows)
		if err != nil {
			return nil, err
		}

		if _, exists := result[bank.UserID]; !exists {
			result[bank.UserID] = *bank
		}
	}

	return result, nil
}

func (r *bankDetailsRepository) scanBankDetails(ctx context.Context, row scanner) (*models.EmployeeBankDetails, error) {

	var b models.EmployeeBankDetails

	var effectiveTo sql.NullTime
	var createdAt, updatedAt time.Time

	var accValue, accDEK, accKeyID string
	var ifscValue, ifscDEK, ifscKeyID string

	err := row.Scan(
		&b.BankDetailID,
		&b.CompanyID,
		&b.UserID,
		&b.AccountHolder,

		&accValue,
		&accDEK,
		&accKeyID,

		&ifscValue,
		&ifscDEK,
		&ifscKeyID,

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
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if effectiveTo.Valid {
		b.EffectiveTo = &effectiveTo.Time
	}

	b.CreatedAt = createdAt
	b.UpdatedAt = updatedAt

	account, err := r.encryption.DecryptField(ctx, &encryption.EncryptedData{
		EncryptedValue: accValue,
		EncryptedDEK:   accDEK,
		KeyID:          accKeyID,
	})

	if err == nil {
		b.AccountNumber = account
	}

	ifsc, err := r.encryption.DecryptField(ctx, &encryption.EncryptedData{
		EncryptedValue: ifscValue,
		EncryptedDEK:   ifscDEK,
		KeyID:          ifscKeyID,
	})

	if err == nil {
		b.IFSCCode = ifsc
	}

	return &b, nil
}

func (r *bankDetailsRepository) Activate(
	ctx context.Context,
	bankDetailID uuid.UUID,
	actorID uuid.UUID,
) error {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	var companyID uuid.UUID
	var userID uuid.UUID

	err = tx.QueryRowContext(ctx, `
		SELECT company_id, user_id
		FROM payroll.employee_bank_details
		WHERE bank_detail_id = $1
	`, bankDetailID).Scan(&companyID, &userID)

	if err != nil {
		return err
	}

	now := time.Now().UTC()

	// deactivate existing active bank
	_, err = tx.ExecContext(ctx, `
		UPDATE payroll.employee_bank_details
		SET is_active = false,
		    updated_at = $1
		WHERE company_id = $2
		AND user_id = $3
		AND is_active = true
	`, now, companyID, userID)

	if err != nil {
		return err
	}

	// activate selected bank
	res, err := tx.ExecContext(ctx, `
		UPDATE payroll.employee_bank_details
		SET is_active = true,
		    effective_to = NULL,
		    updated_at = $1
		WHERE bank_detail_id = $2
	`, now, bankDetailID)

	if err != nil {
		return err
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("bank details not found")
	}

	return tx.Commit()
}
