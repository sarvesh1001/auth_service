// FILE: repository/lookup_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"

	"auth-service/internal/subscription/models"

	"go.uber.org/zap"
)

// DBTX is the common interface for *sql.DB and *sql.Tx.
// It is used to allow both single queries and transactions.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// LookupRepository defines read-only access to subscription lookup tables.
// These tables are seed/master data and are not modified via the repository.
type LookupRepository interface {
	// -------------------------------------------------------------------------
	// Plan Types
	// -------------------------------------------------------------------------

	GetPlanTypes(ctx context.Context, db DBTX) ([]*models.PlanType, error)
	GetPlanTypeByID(ctx context.Context, db DBTX, id int16) (*models.PlanType, error)
	GetPlanTypeByCode(ctx context.Context, db DBTX, code string) (*models.PlanType, error)

	// -------------------------------------------------------------------------
	// Billing Frequencies
	// -------------------------------------------------------------------------

	GetBillingFrequencies(ctx context.Context, db DBTX) ([]*models.BillingFrequency, error)
	GetBillingFrequencyByID(ctx context.Context, db DBTX, id int16) (*models.BillingFrequency, error)
	GetBillingFrequencyByCode(ctx context.Context, db DBTX, code string) (*models.BillingFrequency, error)

	// -------------------------------------------------------------------------
	// Pricing Models
	// -------------------------------------------------------------------------

	GetPricingModels(ctx context.Context, db DBTX) ([]*models.PricingModel, error)
	GetPricingModelByID(ctx context.Context, db DBTX, id int16) (*models.PricingModel, error)
	GetPricingModelByCode(ctx context.Context, db DBTX, code string) (*models.PricingModel, error)

	// -------------------------------------------------------------------------
	// Statuses
	// -------------------------------------------------------------------------

	GetStatuses(ctx context.Context, db DBTX) ([]*models.Status, error)
	GetStatusesByCategory(ctx context.Context, db DBTX, category string) ([]*models.Status, error)
	GetStatusByID(ctx context.Context, db DBTX, id int16) (*models.Status, error)
	GetStatusByCode(ctx context.Context, db DBTX, category, code string) (*models.Status, error)
}

type lookupRepository struct {
	logger *zap.Logger
}

// NewLookupRepository creates a new LookupRepository.
func NewLookupRepository(logger *zap.Logger) LookupRepository {
	return &lookupRepository{
		logger: logger.Named("subscription_lookup_repo"),
	}
}

// -------------------------------------------------------------------------
// Plan Types
// -------------------------------------------------------------------------

func (r *lookupRepository) GetPlanTypes(ctx context.Context, db DBTX) ([]*models.PlanType, error) {
	query := `SELECT plan_type_id, code, name, created_at FROM subscription.plan_type ORDER BY plan_type_id`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		r.logger.Error("failed to get plan types", zap.Error(err))
		return nil, fmt.Errorf("get plan types: %w", err)
	}
	defer rows.Close()

	var result []*models.PlanType
	for rows.Next() {
		var pt models.PlanType
		if err := rows.Scan(&pt.PlanTypeID, &pt.Code, &pt.Name, &pt.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan plan type: %w", err)
		}
		result = append(result, &pt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *lookupRepository) GetPlanTypeByID(ctx context.Context, db DBTX, id int16) (*models.PlanType, error) {
	query := `SELECT plan_type_id, code, name, created_at FROM subscription.plan_type WHERE plan_type_id = $1`
	var pt models.PlanType
	err := db.QueryRowContext(ctx, query, id).Scan(&pt.PlanTypeID, &pt.Code, &pt.Name, &pt.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get plan type by ID", zap.Int16("id", id), zap.Error(err))
		return nil, fmt.Errorf("get plan type by ID: %w", err)
	}
	return &pt, nil
}

func (r *lookupRepository) GetPlanTypeByCode(ctx context.Context, db DBTX, code string) (*models.PlanType, error) {
	query := `SELECT plan_type_id, code, name, created_at FROM subscription.plan_type WHERE code = $1`
	var pt models.PlanType
	err := db.QueryRowContext(ctx, query, code).Scan(&pt.PlanTypeID, &pt.Code, &pt.Name, &pt.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get plan type by code", zap.String("code", code), zap.Error(err))
		return nil, fmt.Errorf("get plan type by code: %w", err)
	}
	return &pt, nil
}

// -------------------------------------------------------------------------
// Billing Frequencies
// -------------------------------------------------------------------------

func (r *lookupRepository) GetBillingFrequencies(ctx context.Context, db DBTX) ([]*models.BillingFrequency, error) {
	query := `SELECT frequency_id, code, name, created_at FROM subscription.billing_frequency ORDER BY frequency_id`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		r.logger.Error("failed to get billing frequencies", zap.Error(err))
		return nil, fmt.Errorf("get billing frequencies: %w", err)
	}
	defer rows.Close()

	var result []*models.BillingFrequency
	for rows.Next() {
		var bf models.BillingFrequency
		if err := rows.Scan(&bf.FrequencyID, &bf.Code, &bf.Name, &bf.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan billing frequency: %w", err)
		}
		result = append(result, &bf)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *lookupRepository) GetBillingFrequencyByID(ctx context.Context, db DBTX, id int16) (*models.BillingFrequency, error) {
	query := `SELECT frequency_id, code, name, created_at FROM subscription.billing_frequency WHERE frequency_id = $1`
	var bf models.BillingFrequency
	err := db.QueryRowContext(ctx, query, id).Scan(&bf.FrequencyID, &bf.Code, &bf.Name, &bf.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get billing frequency by ID", zap.Int16("id", id), zap.Error(err))
		return nil, fmt.Errorf("get billing frequency by ID: %w", err)
	}
	return &bf, nil
}

func (r *lookupRepository) GetBillingFrequencyByCode(ctx context.Context, db DBTX, code string) (*models.BillingFrequency, error) {
	query := `SELECT frequency_id, code, name, created_at FROM subscription.billing_frequency WHERE code = $1`
	var bf models.BillingFrequency
	err := db.QueryRowContext(ctx, query, code).Scan(&bf.FrequencyID, &bf.Code, &bf.Name, &bf.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get billing frequency by code", zap.String("code", code), zap.Error(err))
		return nil, fmt.Errorf("get billing frequency by code: %w", err)
	}
	return &bf, nil
}

// -------------------------------------------------------------------------
// Pricing Models
// -------------------------------------------------------------------------

func (r *lookupRepository) GetPricingModels(ctx context.Context, db DBTX) ([]*models.PricingModel, error) {
	query := `SELECT model_id, code, name, created_at FROM subscription.pricing_model ORDER BY model_id`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		r.logger.Error("failed to get pricing models", zap.Error(err))
		return nil, fmt.Errorf("get pricing models: %w", err)
	}
	defer rows.Close()

	var result []*models.PricingModel
	for rows.Next() {
		var pm models.PricingModel
		if err := rows.Scan(&pm.ModelID, &pm.Code, &pm.Name, &pm.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan pricing model: %w", err)
		}
		result = append(result, &pm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *lookupRepository) GetPricingModelByID(ctx context.Context, db DBTX, id int16) (*models.PricingModel, error) {
	query := `SELECT model_id, code, name, created_at FROM subscription.pricing_model WHERE model_id = $1`
	var pm models.PricingModel
	err := db.QueryRowContext(ctx, query, id).Scan(&pm.ModelID, &pm.Code, &pm.Name, &pm.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get pricing model by ID", zap.Int16("id", id), zap.Error(err))
		return nil, fmt.Errorf("get pricing model by ID: %w", err)
	}
	return &pm, nil
}

func (r *lookupRepository) GetPricingModelByCode(ctx context.Context, db DBTX, code string) (*models.PricingModel, error) {
	query := `SELECT model_id, code, name, created_at FROM subscription.pricing_model WHERE code = $1`
	var pm models.PricingModel
	err := db.QueryRowContext(ctx, query, code).Scan(&pm.ModelID, &pm.Code, &pm.Name, &pm.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get pricing model by code", zap.String("code", code), zap.Error(err))
		return nil, fmt.Errorf("get pricing model by code: %w", err)
	}
	return &pm, nil
}

// -------------------------------------------------------------------------
// Statuses
// -------------------------------------------------------------------------

func (r *lookupRepository) GetStatuses(ctx context.Context, db DBTX) ([]*models.Status, error) {
	query := `SELECT status_id, code, category, name, created_at FROM subscription.statuses ORDER BY status_id`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		r.logger.Error("failed to get statuses", zap.Error(err))
		return nil, fmt.Errorf("get statuses: %w", err)
	}
	defer rows.Close()

	var result []*models.Status
	for rows.Next() {
		var s models.Status
		if err := rows.Scan(&s.StatusID, &s.Code, &s.Category, &s.Name, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan status: %w", err)
		}
		result = append(result, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *lookupRepository) GetStatusesByCategory(ctx context.Context, db DBTX, category string) ([]*models.Status, error) {
	query := `SELECT status_id, code, category, name, created_at FROM subscription.statuses WHERE category = $1 ORDER BY status_id`
	rows, err := db.QueryContext(ctx, query, category)
	if err != nil {
		r.logger.Error("failed to get statuses by category", zap.String("category", category), zap.Error(err))
		return nil, fmt.Errorf("get statuses by category: %w", err)
	}
	defer rows.Close()

	var result []*models.Status
	for rows.Next() {
		var s models.Status
		if err := rows.Scan(&s.StatusID, &s.Code, &s.Category, &s.Name, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan status: %w", err)
		}
		result = append(result, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *lookupRepository) GetStatusByID(ctx context.Context, db DBTX, id int16) (*models.Status, error) {
	query := `SELECT status_id, code, category, name, created_at FROM subscription.statuses WHERE status_id = $1`
	var s models.Status
	err := db.QueryRowContext(ctx, query, id).Scan(&s.StatusID, &s.Code, &s.Category, &s.Name, &s.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get status by ID", zap.Int16("id", id), zap.Error(err))
		return nil, fmt.Errorf("get status by ID: %w", err)
	}
	return &s, nil
}

func (r *lookupRepository) GetStatusByCode(ctx context.Context, db DBTX, category, code string) (*models.Status, error) {
	query := `SELECT status_id, code, category, name, created_at FROM subscription.statuses WHERE category = $1 AND code = $2`
	var s models.Status
	err := db.QueryRowContext(ctx, query, category, code).Scan(&s.StatusID, &s.Code, &s.Category, &s.Name, &s.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get status by code", zap.String("category", category), zap.String("code", code), zap.Error(err))
		return nil, fmt.Errorf("get status by code: %w", err)
	}
	return &s, nil
}
