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

	"auth-service/internal/accounting/models/tax"
	"auth-service/internal/util"
)

type TaxTransactionFilter struct {
	CompanyID       uuid.UUID
	TransactionType string
	TaxRateID       *uuid.UUID
	TaxRuleID       *uuid.UUID
	FromDate        *time.Time
	ToDate          *time.Time
	Search          string
}

type TaxRateSummary struct {
	TaxRateID     uuid.UUID
	TaxName       string
	TaxableAmount float64
	TaxAmount     float64
}

type TaxRuleSummary struct {
	TaxRuleID     uuid.UUID
	RuleName      string
	TaxableAmount float64
	TaxAmount     float64
}

type TaxTransactionDetail struct {
	tax.TaxTransaction
	RatePercentage *float64 `json:"rate_percentage,omitempty"`
	RuleName       *string  `json:"rule_name,omitempty"`
}

type TaxTransactionRepository interface {
	// Write operations
	Create(ctx context.Context, db DBTX, t *tax.TaxTransaction) error
	BulkCreate(ctx context.Context, db DBTX, txs []*tax.TaxTransaction) error
	Upsert(ctx context.Context, db DBTX, t *tax.TaxTransaction) error
	BulkUpsert(ctx context.Context, db DBTX, txs []*tax.TaxTransaction) error // new
	DeleteByTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) error
	DeleteByTransactionAndRate(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID, taxRateID uuid.UUID) error // new

	// Read operations
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxTransaction, error)
	GetByTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) ([]*tax.TaxTransaction, error)
	GetDetailedByTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) ([]*TaxTransactionDetail, error) // new
	ExistsForTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) (bool, error)
	ExistsForTransactionAndRate(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID, taxRateID uuid.UUID) (bool, error) // new
	List(ctx context.Context, db DBTX, filter TaxTransactionFilter, p Pagination, s Sort) ([]*tax.TaxTransaction, error)
	Count(ctx context.Context, db DBTX, filter TaxTransactionFilter) (int64, error)

	// Aggregation (compliance & reporting)
	SumByPeriod(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) (taxable float64, taxAmount float64, err error)
	SumByRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TaxRateSummary, error)
	SumByRule(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TaxRuleSummary, error)

	// Compliance support
	GetForReturn(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*tax.TaxTransaction, error)
}

type taxTransactionRepository struct {
	logger *zap.Logger
}

func NewTaxTransactionRepository(logger *zap.Logger) TaxTransactionRepository {
	return &taxTransactionRepository{logger: logger.Named("tax_transaction_repo")}
}

var allowedTaxTransactionSortFields = map[string]bool{
	"transaction_date": true, "taxable_amount": true, "tax_amount": true, "created_at": true,
}

func (r *taxTransactionRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "transaction_date"
	}
	if !allowedTaxTransactionSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *taxTransactionRepository) validatePagination(p Pagination) (int, int) {
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

func (r *taxTransactionRepository) buildTaxTransactionFilter(filter TaxTransactionFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.TransactionType != "" {
		conditions = append(conditions, fmt.Sprintf("transaction_type = $%d", idx))
		args = append(args, filter.TransactionType)
		idx++
	}
	if filter.TaxRateID != nil {
		conditions = append(conditions, fmt.Sprintf("tax_rate_id = $%d", idx))
		args = append(args, *filter.TaxRateID)
		idx++
	}
	if filter.TaxRuleID != nil {
		conditions = append(conditions, fmt.Sprintf("tax_rule_id = $%d", idx))
		args = append(args, *filter.TaxRuleID)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("transaction_date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("transaction_date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("transaction_id::text ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	// No deleted_at column in tax_transactions – no soft delete (by design)
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *taxTransactionRepository) scanTaxTransaction(scanner interface {
	Scan(dest ...interface{}) error
}) (*tax.TaxTransaction, error) {
	var tt tax.TaxTransaction
	var taxRuleID, taxRateID uuid.NullUUID
	err := scanner.Scan(
		&tt.TaxTransactionID, &tt.CompanyID, &tt.TransactionType, &tt.TransactionID,
		&taxRuleID, &taxRateID, &tt.TaxableAmount, &tt.TaxAmount,
		&tt.Currency, &tt.ExchangeRate, &tt.BaseCurrencyAmount,
		&tt.TransactionDate, &tt.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if taxRuleID.Valid {
		tt.TaxRuleID = &taxRuleID.UUID
	}
	if taxRateID.Valid {
		tt.TaxRateID = &taxRateID.UUID
	}
	return &tt, nil
}

// Create inserts a single tax transaction.
func (r *taxTransactionRepository) Create(ctx context.Context, db DBTX, t *tax.TaxTransaction) error {
	query := `
        INSERT INTO accounting.tax_transactions (
            tax_transaction_id, company_id, transaction_type, transaction_id,
            tax_rule_id, tax_rate_id, taxable_amount, tax_amount,
            currency, exchange_rate, transaction_date, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
        RETURNING base_currency_amount
    `
	err := db.QueryRowContext(ctx, query,
		t.TaxTransactionID, t.CompanyID, t.TransactionType, t.TransactionID,
		t.TaxRuleID, t.TaxRateID, t.TaxableAmount, t.TaxAmount,
		t.Currency, t.ExchangeRate, t.TransactionDate,
	).Scan(&t.BaseCurrencyAmount)
	if err != nil {
		r.logger.Error("failed to create tax transaction",
			util.String("company_id", t.CompanyID.String()),
			util.String("transaction_type", t.TransactionType),
			util.String("transaction_id", t.TransactionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create tax transaction: %w", err)
	}
	return nil
}

// BulkCreate inserts many tax transactions.
func (r *taxTransactionRepository) BulkCreate(ctx context.Context, db DBTX, txs []*tax.TaxTransaction) error {
	if len(txs) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO accounting.tax_transactions (
			tax_transaction_id, company_id, transaction_type, transaction_id,
			tax_rule_id, tax_rate_id, taxable_amount, tax_amount,
			currency, exchange_rate, transaction_date, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk insert: %w", err)
	}
	defer stmt.Close()
	for _, tt := range txs {
		if _, err := stmt.ExecContext(ctx,
			tt.TaxTransactionID, tt.CompanyID, tt.TransactionType, tt.TransactionID,
			tt.TaxRuleID, tt.TaxRateID, tt.TaxableAmount, tt.TaxAmount,
			tt.Currency, tt.ExchangeRate, tt.TransactionDate,
		); err != nil {
			r.logger.Error("bulk create failed",
				util.String("company_id", tt.CompanyID.String()),
				util.String("transaction_type", tt.TransactionType),
				util.String("transaction_id", tt.TransactionID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk create tax transaction: %w", err)
		}
	}
	return nil
}

// Upsert (single) based on unique constraint (company_id, transaction_type, transaction_id, tax_rate_id).
func (r *taxTransactionRepository) Upsert(ctx context.Context, db DBTX, t *tax.TaxTransaction) error {
	query := `
		INSERT INTO accounting.tax_transactions (
			tax_transaction_id, company_id, transaction_type, transaction_id,
			tax_rule_id, tax_rate_id, taxable_amount, tax_amount,
			currency, exchange_rate, transaction_date, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		ON CONFLICT (company_id, transaction_type, transaction_id, tax_rate_id)
		DO UPDATE SET
			tax_rule_id = EXCLUDED.tax_rule_id,
			taxable_amount = EXCLUDED.taxable_amount,
			tax_amount = EXCLUDED.tax_amount,
			currency = EXCLUDED.currency,
			exchange_rate = EXCLUDED.exchange_rate,
			transaction_date = EXCLUDED.transaction_date
	`
	_, err := db.ExecContext(ctx, query,
		t.TaxTransactionID, t.CompanyID, t.TransactionType, t.TransactionID,
		t.TaxRuleID, t.TaxRateID, t.TaxableAmount, t.TaxAmount,
		t.Currency, t.ExchangeRate, t.TransactionDate,
	)
	if err != nil {
		r.logger.Error("failed to upsert tax transaction",
			util.String("company_id", t.CompanyID.String()),
			util.String("transaction_type", t.TransactionType),
			util.String("transaction_id", t.TransactionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("upsert tax transaction: %w", err)
	}
	return nil
}

// BulkUpsert – idempotent bulk upsert for many transactions.
func (r *taxTransactionRepository) BulkUpsert(ctx context.Context, db DBTX, txs []*tax.TaxTransaction) error {
	if len(txs) == 0 {
		return nil
	}
	tx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("BulkUpsert requires a transaction")
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO accounting.tax_transactions (
			tax_transaction_id, company_id, transaction_type, transaction_id,
			tax_rule_id, tax_rate_id, taxable_amount, tax_amount,
			currency, exchange_rate, transaction_date, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		ON CONFLICT (company_id, transaction_type, transaction_id, tax_rate_id)
		DO UPDATE SET
			tax_rule_id = EXCLUDED.tax_rule_id,
			taxable_amount = EXCLUDED.taxable_amount,
			tax_amount = EXCLUDED.tax_amount,
			currency = EXCLUDED.currency,
			exchange_rate = EXCLUDED.exchange_rate,
			transaction_date = EXCLUDED.transaction_date
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk upsert: %w", err)
	}
	defer stmt.Close()
	for _, tt := range txs {
		if _, err := stmt.ExecContext(ctx,
			tt.TaxTransactionID, tt.CompanyID, tt.TransactionType, tt.TransactionID,
			tt.TaxRuleID, tt.TaxRateID, tt.TaxableAmount, tt.TaxAmount,
			tt.Currency, tt.ExchangeRate, tt.TransactionDate,
		); err != nil {
			return fmt.Errorf("bulk upsert row: %w", err)
		}
	}
	return nil
}

// DeleteByTransaction removes all tax transactions for a source.
func (r *taxTransactionRepository) DeleteByTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) error {
	query := `DELETE FROM accounting.tax_transactions WHERE transaction_type = $1 AND transaction_id = $2`
	result, err := db.ExecContext(ctx, query, transactionType, transactionID)
	if err != nil {
		r.logger.Error("failed to delete tax transactions by source",
			util.String("type", transactionType),
			util.String("id", transactionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete by transaction: %w", err)
	}
	rows, _ := result.RowsAffected()
	r.logger.Info("deleted tax transactions",
		util.String("type", transactionType),
		util.String("id", transactionID.String()),
		util.Int64("count", rows))
	return nil
}

// DeleteByTransactionAndRate deletes a specific tax line.
func (r *taxTransactionRepository) DeleteByTransactionAndRate(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID, taxRateID uuid.UUID) error {
	query := `DELETE FROM accounting.tax_transactions WHERE transaction_type = $1 AND transaction_id = $2 AND tax_rate_id = $3`
	_, err := db.ExecContext(ctx, query, transactionType, transactionID, taxRateID)
	if err != nil {
		r.logger.Error("failed to delete tax transaction by rate",
			util.String("type", transactionType),
			util.String("id", transactionID.String()),
			util.String("rate_id", taxRateID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete by transaction and rate: %w", err)
	}
	return nil
}

// GetByID retrieves a tax transaction by its ID.
func (r *taxTransactionRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxTransaction, error) {
	query := `
		SELECT tax_transaction_id, company_id, transaction_type, transaction_id,
		       tax_rule_id, tax_rate_id, taxable_amount, tax_amount,
		       currency, exchange_rate, base_currency_amount,
		       transaction_date, created_at
		FROM accounting.tax_transactions
		WHERE tax_transaction_id = $1
	`
	tt, err := r.scanTaxTransaction(db.QueryRowContext(ctx, query, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get tax transaction by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax transaction by ID: %w", err)
	}
	return tt, nil
}

// GetByTransaction returns all tax transactions for a source.
func (r *taxTransactionRepository) GetByTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) ([]*tax.TaxTransaction, error) {
	query := `
		SELECT tax_transaction_id, company_id, transaction_type, transaction_id,
		       tax_rule_id, tax_rate_id, taxable_amount, tax_amount,
		       currency, exchange_rate, base_currency_amount,
		       transaction_date, created_at
		FROM accounting.tax_transactions
		WHERE transaction_type = $1 AND transaction_id = $2
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, transactionType, transactionID)
	if err != nil {
		r.logger.Error("failed to get tax transactions by source",
			util.String("type", transactionType),
			util.String("id", transactionID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get by transaction: %w", err)
	}
	defer rows.Close()
	var result []*tax.TaxTransaction
	for rows.Next() {
		tt, err := r.scanTaxTransaction(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tax transaction: %w", err)
		}
		result = append(result, tt)
	}
	return result, nil
}

// GetDetailedByTransaction returns tax transactions joined with rate percentage and rule name.
// GetDetailedByTransaction returns tax transactions joined with rate percentage and rule name.
func (r *taxTransactionRepository) GetDetailedByTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) ([]*TaxTransactionDetail, error) {
	query := `
		SELECT
			tt.tax_transaction_id, tt.company_id, tt.transaction_type, tt.transaction_id,
			tt.tax_rule_id, tt.tax_rate_id, tt.taxable_amount, tt.tax_amount,
			tt.currency, tt.exchange_rate, tt.base_currency_amount,
			tt.transaction_date, tt.created_at,
			tr.rate_percentage,
			tax_r.rule_name
		FROM accounting.tax_transactions tt
		LEFT JOIN accounting.tax_rates tr ON tt.tax_rate_id = tr.tax_rate_id
		LEFT JOIN accounting.tax_rules tax_r ON tt.tax_rule_id = tax_r.tax_rule_id
		WHERE tt.transaction_type = $1 AND tt.transaction_id = $2
		ORDER BY tt.created_at
	`
	rows, err := db.QueryContext(ctx, query, transactionType, transactionID)
	if err != nil {
		r.logger.Error("failed to get detailed tax transactions",
			util.String("type", transactionType),
			util.String("id", transactionID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get detailed by transaction: %w", err)
	}
	defer rows.Close()

	var details []*TaxTransactionDetail
	for rows.Next() {
		var d TaxTransactionDetail
		var ratePerc sql.NullFloat64
		var ruleName sql.NullString
		// FIXED: use uuid.NullUUID instead of sql.NullUUID
		var taxRuleID, taxRateID uuid.NullUUID

		err := rows.Scan(
			&d.TaxTransactionID, &d.CompanyID, &d.TransactionType, &d.TransactionID,
			&taxRuleID, &taxRateID, &d.TaxableAmount, &d.TaxAmount,
			&d.Currency, &d.ExchangeRate, &d.BaseCurrencyAmount,
			&d.TransactionDate, &d.CreatedAt,
			&ratePerc, &ruleName,
		)
		if err != nil {
			return nil, fmt.Errorf("scan detailed transaction: %w", err)
		}
		if taxRuleID.Valid {
			d.TaxRuleID = &taxRuleID.UUID
		}
		if taxRateID.Valid {
			d.TaxRateID = &taxRateID.UUID
		}
		if ratePerc.Valid {
			d.RatePercentage = &ratePerc.Float64
		}
		if ruleName.Valid {
			d.RuleName = &ruleName.String
		}
		details = append(details, &d)
	}
	return details, rows.Err()
}

// ExistsForTransaction checks if any tax transaction exists for the source.
func (r *taxTransactionRepository) ExistsForTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM accounting.tax_transactions WHERE transaction_type = $1 AND transaction_id = $2)`, transactionType, transactionID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence for transaction",
			util.String("type", transactionType),
			util.String("id", transactionID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("exists for transaction: %w", err)
	}
	return exists, nil
}

// ExistsForTransactionAndRate checks if a specific tax rate line exists.
func (r *taxTransactionRepository) ExistsForTransactionAndRate(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID, taxRateID uuid.UUID) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM accounting.tax_transactions WHERE transaction_type = $1 AND transaction_id = $2 AND tax_rate_id = $3)`, transactionType, transactionID, taxRateID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence for transaction and rate",
			util.String("type", transactionType),
			util.String("id", transactionID.String()),
			util.String("rate_id", taxRateID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("exists for transaction and rate: %w", err)
	}
	return exists, nil
}

// List returns a paginated list.
func (r *taxTransactionRepository) List(ctx context.Context, db DBTX, filter TaxTransactionFilter, p Pagination, s Sort) ([]*tax.TaxTransaction, error) {
	where, args := r.buildTaxTransactionFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)
	query := fmt.Sprintf(`
		SELECT tax_transaction_id, company_id, transaction_type, transaction_id,
		       tax_rule_id, tax_rate_id, taxable_amount, tax_amount,
		       currency, exchange_rate, base_currency_amount,
		       transaction_date, created_at
		FROM accounting.tax_transactions
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list tax transactions",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list tax transactions: %w", err)
	}
	defer rows.Close()
	var result []*tax.TaxTransaction
	for rows.Next() {
		tt, err := r.scanTaxTransaction(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tax transaction: %w", err)
		}
		result = append(result, tt)
	}
	return result, rows.Err()
}

// Count returns the number of tax transactions.
func (r *taxTransactionRepository) Count(ctx context.Context, db DBTX, filter TaxTransactionFilter) (int64, error) {
	where, args := r.buildTaxTransactionFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM accounting.tax_transactions %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count tax transactions",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count tax transactions: %w", err)
	}
	return count, nil
}

// Aggregations

func (r *taxTransactionRepository) SumByPeriod(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) (taxable float64, taxAmount float64, err error) {
	query := `
		SELECT COALESCE(SUM(taxable_amount), 0), COALESCE(SUM(tax_amount), 0)
		FROM accounting.tax_transactions
		WHERE company_id = $1 AND transaction_date BETWEEN $2 AND $3
	`
	err = db.QueryRowContext(ctx, query, companyID, from, to).Scan(&taxable, &taxAmount)
	if err != nil {
		r.logger.Error("failed to sum tax by period",
			util.String("company_id", companyID.String()),
			util.Time("from", from), util.Time("to", to),
			util.ErrorField(err))
		return 0, 0, fmt.Errorf("sum by period: %w", err)
	}
	return taxable, taxAmount, nil
}

func (r *taxTransactionRepository) SumByRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TaxRateSummary, error) {
	query := `
		SELECT
			tr.tax_rate_id,
			tr.tax_name,
			COALESCE(SUM(tt.taxable_amount), 0) AS total_taxable,
			COALESCE(SUM(tt.tax_amount), 0) AS total_tax
		FROM accounting.tax_transactions tt
		INNER JOIN accounting.tax_rates tr ON tt.tax_rate_id = tr.tax_rate_id
		WHERE tt.company_id = $1
		  AND tt.transaction_date BETWEEN $2 AND $3
		  AND tt.tax_rate_id IS NOT NULL
		GROUP BY tr.tax_rate_id, tr.tax_name
		ORDER BY tr.tax_name
	`
	rows, err := db.QueryContext(ctx, query, companyID, from, to)
	if err != nil {
		r.logger.Error("failed to sum tax by rate",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("sum by rate: %w", err)
	}
	defer rows.Close()
	var results []*TaxRateSummary
	for rows.Next() {
		var s TaxRateSummary
		if err := rows.Scan(&s.TaxRateID, &s.TaxName, &s.TaxableAmount, &s.TaxAmount); err != nil {
			return nil, fmt.Errorf("scan tax rate summary: %w", err)
		}
		results = append(results, &s)
	}
	return results, rows.Err()
}

func (r *taxTransactionRepository) SumByRule(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TaxRuleSummary, error) {
	query := `
		SELECT
			tr.tax_rule_id,
			tr.rule_name,
			COALESCE(SUM(tt.taxable_amount), 0) AS total_taxable,
			COALESCE(SUM(tt.tax_amount), 0) AS total_tax
		FROM accounting.tax_transactions tt
		INNER JOIN accounting.tax_rules tr ON tt.tax_rule_id = tr.tax_rule_id
		WHERE tt.company_id = $1
		  AND tt.transaction_date BETWEEN $2 AND $3
		  AND tt.tax_rule_id IS NOT NULL
		GROUP BY tr.tax_rule_id, tr.rule_name
		ORDER BY tr.rule_name
	`
	rows, err := db.QueryContext(ctx, query, companyID, from, to)
	if err != nil {
		r.logger.Error("failed to sum tax by rule",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("sum by rule: %w", err)
	}
	defer rows.Close()
	var results []*TaxRuleSummary
	for rows.Next() {
		var s TaxRuleSummary
		if err := rows.Scan(&s.TaxRuleID, &s.RuleName, &s.TaxableAmount, &s.TaxAmount); err != nil {
			return nil, fmt.Errorf("scan tax rule summary: %w", err)
		}
		results = append(results, &s)
	}
	return results, rows.Err()
}

// GetForReturn returns all tax transactions for a compliance return period.
func (r *taxTransactionRepository) GetForReturn(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*tax.TaxTransaction, error) {
	filter := TaxTransactionFilter{
		CompanyID: companyID,
		FromDate:  &from,
		ToDate:    &to,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "transaction_date", Direction: "ASC"})
}
