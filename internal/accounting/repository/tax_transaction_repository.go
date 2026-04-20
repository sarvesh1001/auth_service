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

// TaxTransactionFilter defines filter criteria for listing tax transactions
type TaxTransactionFilter struct {
	CompanyID       uuid.UUID
	TransactionType string
	TaxRateID       *uuid.UUID
	TaxRuleID       *uuid.UUID
	FromDate        *time.Time
	ToDate          *time.Time
	Search          string // searches in transaction_id (string) or other fields if needed
}

// TaxRateSummary aggregates tax amounts by tax rate
type TaxRateSummary struct {
	TaxRateID     uuid.UUID
	TaxName       string
	TaxableAmount float64
	TaxAmount     float64
}

// TaxRuleSummary aggregates tax amounts by tax rule
type TaxRuleSummary struct {
	TaxRuleID     uuid.UUID
	RuleName      string
	TaxableAmount float64
	TaxAmount     float64
}

// TaxTransactionRepository defines the interface for tax transaction data access
type TaxTransactionRepository interface {
	// Write operations
	Create(ctx context.Context, db DBTX, t *tax.TaxTransaction) error
	BulkCreate(ctx context.Context, db DBTX, txs []*tax.TaxTransaction) error
	Upsert(ctx context.Context, db DBTX, t *tax.TaxTransaction) error

	// Read operations
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*tax.TaxTransaction, error)
	GetByTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) ([]*tax.TaxTransaction, error)
	List(ctx context.Context, db DBTX, filter TaxTransactionFilter, p Pagination, s Sort) ([]*tax.TaxTransaction, error)
	Count(ctx context.Context, db DBTX, filter TaxTransactionFilter) (int64, error)

	// Aggregation (compliance & reporting)
	SumByPeriod(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) (taxable float64, taxAmount float64, err error)
	SumByRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TaxRateSummary, error)
	SumByRule(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TaxRuleSummary, error)

	// Compliance support
	GetForReturn(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*tax.TaxTransaction, error)

	// Validation / safety
	ExistsForTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) (bool, error)
	DeleteByTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) error
}

// taxTransactionRepository implements TaxTransactionRepository
type taxTransactionRepository struct {
	logger *zap.Logger
}

// NewTaxTransactionRepository creates a new tax transaction repository instance
func NewTaxTransactionRepository(logger *zap.Logger) TaxTransactionRepository {
	return &taxTransactionRepository{
		logger: logger.Named("tax_transaction_repo"),
	}
}

// allowed sort fields for tax transactions
var allowedTaxTransactionSortFields = map[string]bool{
	"transaction_date": true,
	"taxable_amount":   true,
	"tax_amount":       true,
	"created_at":       true,
}

// validateSort returns a safe ORDER BY clause
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

// validatePagination returns sanitized limit and offset
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

// buildTaxTransactionFilter constructs WHERE clause and arguments
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
		// Search by transaction_id (cast to text) or maybe other fields
		conditions = append(conditions, fmt.Sprintf("transaction_id::text ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// scanTaxTransaction scans a row into a TaxTransaction model
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

// Create inserts a new tax transaction
func (r *taxTransactionRepository) Create(ctx context.Context, db DBTX, t *tax.TaxTransaction) error {
	// Note: base_currency_amount is GENERATED ALWAYS, so we omit it in INSERT
	query := `
		INSERT INTO accounting.tax_transactions (
			tax_transaction_id, company_id, transaction_type, transaction_id,
			tax_rule_id, tax_rate_id, taxable_amount, tax_amount,
			currency, exchange_rate, transaction_date, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		t.TaxTransactionID, t.CompanyID, t.TransactionType, t.TransactionID,
		t.TaxRuleID, t.TaxRateID, t.TaxableAmount, t.TaxAmount,
		t.Currency, t.ExchangeRate, t.TransactionDate,
	)
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

// BulkCreate inserts multiple tax transactions using a prepared statement
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
		_, err = stmt.ExecContext(ctx,
			tt.TaxTransactionID, tt.CompanyID, tt.TransactionType, tt.TransactionID,
			tt.TaxRuleID, tt.TaxRateID, tt.TaxableAmount, tt.TaxAmount,
			tt.Currency, tt.ExchangeRate, tt.TransactionDate,
		)
		if err != nil {
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

// Upsert idempotently inserts or updates a tax transaction.
// Assumes a unique constraint on (company_id, transaction_type, transaction_id, tax_rate_id)
// If the record exists, it updates the amounts (should be idempotent – same values).
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

// GetByID retrieves a tax transaction by its ID
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
			return nil, nil
		}
		r.logger.Error("failed to get tax transaction by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax transaction by ID: %w", err)
	}
	return tt, nil
}

// GetByTransaction returns all tax transactions linked to a source transaction
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

// List returns a paginated list of tax transactions matching the filter
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
	return result, nil
}

// Count returns the number of tax transactions matching the filter
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

// SumByPeriod returns total taxable amount and tax amount for a company within a date range
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
			util.Time("from", from),
			util.Time("to", to),
			util.ErrorField(err))
		return 0, 0, fmt.Errorf("sum by period: %w", err)
	}
	return taxable, taxAmount, nil
}

// SumByRate returns tax amounts grouped by tax rate
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
		err := rows.Scan(&s.TaxRateID, &s.TaxName, &s.TaxableAmount, &s.TaxAmount)
		if err != nil {
			return nil, fmt.Errorf("scan tax rate summary: %w", err)
		}
		results = append(results, &s)
	}
	return results, nil
}

// SumByRule returns tax amounts grouped by tax rule
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
		err := rows.Scan(&s.TaxRuleID, &s.RuleName, &s.TaxableAmount, &s.TaxAmount)
		if err != nil {
			return nil, fmt.Errorf("scan tax rule summary: %w", err)
		}
		results = append(results, &s)
	}
	return results, nil
}

// GetForReturn retrieves all tax transactions for a compliance return period
func (r *taxTransactionRepository) GetForReturn(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*tax.TaxTransaction, error) {
	// This is essentially List with date filter, but we use it explicitly for compliance.
	filter := TaxTransactionFilter{
		CompanyID: companyID,
		FromDate:  &from,
		ToDate:    &to,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 10000}, Sort{Field: "transaction_date", Direction: "ASC"})
}

// ExistsForTransaction checks if any tax transaction exists for the given source transaction
func (r *taxTransactionRepository) ExistsForTransaction(ctx context.Context, db DBTX, transactionType string, transactionID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM accounting.tax_transactions
			WHERE transaction_type = $1 AND transaction_id = $2
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, transactionType, transactionID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence for transaction",
			util.String("type", transactionType),
			util.String("id", transactionID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("exists for transaction: %w", err)
	}
	return exists, nil
}

// DeleteByTransaction deletes all tax transactions linked to a source transaction
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
