package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type DBTX interface {
	Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row
	Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

type txQuerier struct {
	tx *sql.Tx
}

func (q *txQuerier) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return q.tx.QueryContext(ctx, query, args...)
}
func (q *txQuerier) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return q.tx.QueryRowContext(ctx, query, args...)
}
func (q *txQuerier) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return q.tx.ExecContext(ctx, query, args...)
}

type statutoryRepository struct {
	db     DBTX
	logger *zap.Logger
}

func NewStatutoryRepository(postgresClient *client.PostgresClient, logger *zap.Logger) StatutoryRepository {
	return &statutoryRepository{
		db:     postgresClient,
		logger: logger,
	}
}

func (r *statutoryRepository) WithTx(ctx context.Context, fn func(StatutoryRepository) error) error {
	pgClient, ok := r.db.(*client.PostgresClient)
	if !ok {
		return fmt.Errorf("WithTx can only be used with a PostgresClient-based repository")
	}
	tx, err := pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	txRepo := &statutoryRepository{
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

// ----------------------------------------------------------------------
// Existing methods (unchanged except removal of old rate/threshold methods)
// ----------------------------------------------------------------------

func (r *statutoryRepository) ResolveRuleSet(ctx context.Context, companyID uuid.UUID, asOf time.Time) (*models.StatutoryRuleSet, error) {
	const query = `
		SELECT rule_set_id, company_id, country_code, version_label,
		       effective_from, effective_to, is_active,
		       created_at, created_by
		FROM payroll.statutory_rule_set
		WHERE company_id = $1
		  AND is_active = true
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	var rs models.StatutoryRuleSet
	err := r.db.QueryRow(ctx, query, companyID, asOf).Scan(
		&rs.RuleSetID,
		&rs.CompanyID,
		&rs.CountryCode,
		&rs.VersionLabel,
		&rs.EffectiveFrom,
		&rs.EffectiveTo,
		&rs.IsActive,
		&rs.CreatedAt,
		&rs.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to resolve rule set",
			util.String("company_id", companyID.String()),
			util.Time("as_of", asOf),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to resolve rule set: %w", err)
	}
	return &rs, nil
}

func (r *statutoryRepository) LoadStatutoryComponentMappingsByRuleSet(ctx context.Context, ruleSetID uuid.UUID) ([]models.StatutoryComponentMapping, error) {
	const query = `
		SELECT mapping_id, company_id, statutory_code, component_code,
		       effective_from, effective_to, is_active,
		       version, created_at, created_by,
		       deactivated_at, deactivated_by, rule_set_id
		FROM payroll.statutory_component_mapping
		WHERE rule_set_id = $1
		  AND is_active = true
		ORDER BY statutory_code, component_code
	`
	rows, err := r.db.Query(ctx, query, ruleSetID)
	if err != nil {
		r.logger.Error("Failed to load component mappings by rule set",
			util.String("rule_set_id", ruleSetID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to load component mappings: %w", err)
	}
	defer rows.Close()
	var mappings []models.StatutoryComponentMapping
	for rows.Next() {
		var m models.StatutoryComponentMapping
		if err := rows.Scan(
			&m.MappingID,
			&m.CompanyID,
			&m.StatutoryCode,
			&m.ComponentCode,
			&m.EffectiveFrom,
			&m.EffectiveTo,
			&m.IsActive,
			&m.Version,
			&m.CreatedAt,
			&m.CreatedBy,
			&m.DeactivatedAt,
			&m.DeactivatedBy,
			&m.RuleSetID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan component mapping: %w", err)
		}
		mappings = append(mappings, m)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return mappings, nil
}

func (r *statutoryRepository) LoadTaxSlabsByRuleSet(ctx context.Context, ruleSetID uuid.UUID) ([]models.StatutoryTaxSlab, error) {
	const query = `
		SELECT slab_id, company_id, statutory_code, slab_order,
		       min_income, max_income, tax_percentage, is_percentage,
		       effective_from, effective_to, is_active,
		       version, created_at, created_by,
		       deactivated_at, deactivated_by, rule_set_id
		FROM payroll.company_tax_slab
		WHERE rule_set_id = $1
		  AND is_active = true
		ORDER BY slab_order
	`
	rows, err := r.db.Query(ctx, query, ruleSetID)
	if err != nil {
		r.logger.Error("Failed to load tax slabs by rule set",
			util.String("rule_set_id", ruleSetID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to load tax slabs: %w", err)
	}
	defer rows.Close()
	var slabs []models.StatutoryTaxSlab
	for rows.Next() {
		var s models.StatutoryTaxSlab
		if err := rows.Scan(
			&s.SlabID,
			&s.CompanyID,
			&s.StatutoryCode,
			&s.SlabOrder,
			&s.MinAmount,
			&s.MaxAmount,
			&s.Rate,
			&s.IsPercentage,
			&s.EffectiveFrom,
			&s.EffectiveTo,
			&s.IsActive,
			&s.Version,
			&s.CreatedAt,
			&s.CreatedBy,
			&s.DeactivatedAt,
			&s.DeactivatedBy,
			&s.RuleSetID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan tax slab: %w", err)
		}
		slabs = append(slabs, s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return slabs, nil
}

func (r *statutoryRepository) LoadDeductionLimitsByRuleSet(ctx context.Context, ruleSetID uuid.UUID) ([]models.StatutoryDeductionLimit, error) {
	const query = `
		SELECT limit_id, company_id, rule_set_id, limit_code, limit_value, metadata, created_at
		FROM payroll.statutory_deduction_limit
		WHERE rule_set_id = $1
	`
	rows, err := r.db.Query(ctx, query, ruleSetID)
	if err != nil {
		r.logger.Error("Failed to load deduction limits by rule set",
			util.String("rule_set_id", ruleSetID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to load deduction limits: %w", err)
	}
	defer rows.Close()
	var limits []models.StatutoryDeductionLimit
	for rows.Next() {
		var l models.StatutoryDeductionLimit
		if err := rows.Scan(
			&l.LimitID,
			&l.CompanyID,
			&l.RuleSetID,
			&l.LimitCode,
			&l.LimitValue,
			&l.Metadata,
			&l.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan deduction limit: %w", err)
		}
		limits = append(limits, l)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return limits, nil
}

func (r *statutoryRepository) GetEmployeeStatutoryProfiles(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) ([]models.EmployeeStatutoryProfile, error) {

	const query = `
		SELECT profile_id, company_id, user_id, statutory_code,
		       opt_in, special_category, regime,
		       effective_from, effective_to, is_active,
		       version, created_at, created_by,
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
		r.logger.Error("Failed to get employee statutory profiles",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.Time("as_of", asOf),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get employee statutory profiles: %w", err)
	}
	defer rows.Close()

	var profiles []models.EmployeeStatutoryProfile

	for rows.Next() {
		var p models.EmployeeStatutoryProfile

		var specialCategory sql.NullString
		var regime sql.NullString
		var effectiveTo sql.NullTime
		var createdBy uuid.NullUUID
		var deactivatedAt sql.NullTime
		var deactivatedBy uuid.NullUUID
		var ruleSetID uuid.NullUUID

		if err := rows.Scan(
			&p.ProfileID,
			&p.CompanyID,
			&p.UserID,
			&p.StatutoryCode,
			&p.OptIn,
			&specialCategory,
			&regime,
			&p.EffectiveFrom,
			&effectiveTo,
			&p.IsActive,
			&p.Version,
			&p.CreatedAt,
			&createdBy,
			&deactivatedAt,
			&deactivatedBy,
			&ruleSetID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan employee statutory profile: %w", err)
		}

		// Convert nullable fields

		if specialCategory.Valid {
			p.SpecialCategory = &specialCategory.String
		}

		if regime.Valid {
			p.Regime = &regime.String
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

		profiles = append(profiles, p)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return profiles, nil
}

func (r *statutoryRepository) GetYTDStatutorySummary(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, statutoryCode string, financialYearStart time.Time, asOf time.Time) (*models.YTDStatutorySummary, error) {
	const query = `
		SELECT
			COALESCE(SUM(employee_amount), 0) as ytd_employee,
			COALESCE(SUM(employer_amount), 0) as ytd_employer,
			COALESCE(SUM(total_amount), 0) as ytd_total
		FROM payroll.employee_statutory_contribution
		WHERE company_id = $1
		  AND user_id = $2
		  AND statutory_code = $3
		  AND period_start >= $4
		  AND period_end <= $5
	`
	var ytdEmp, ytdEpr, ytdTotal float64
	err := r.db.QueryRow(ctx, query, companyID, userID, statutoryCode, financialYearStart, asOf).Scan(
		&ytdEmp, &ytdEpr, &ytdTotal,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		r.logger.Error("Failed to get YTD statutory summary",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("statutory_code", statutoryCode),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get YTD summary: %w", err)
	}
	return &models.YTDStatutorySummary{
		CompanyID:          companyID,
		UserID:             userID,
		StatutoryCode:      statutoryCode,
		FinancialYearStart: financialYearStart,
		AsOf:               asOf,
		YTDEmployeeAmount:  ytdEmp,
		YTDEmployerAmount:  ytdEpr,
		YTDTotalAmount:     ytdTotal,
	}, nil
}

func (r *statutoryRepository) InsertEmployeeStatutoryContribution(ctx context.Context, contribution *models.EmployeeStatutoryContribution) error {
	const query = `
		INSERT INTO payroll.employee_statutory_contribution (
			contribution_id, company_id, user_id, statutory_code,
			period_start, period_end,
			employee_amount, employer_amount, total_amount,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (company_id, user_id, statutory_code, period_start, period_end)
		DO UPDATE SET
			employee_amount = EXCLUDED.employee_amount,
			employer_amount = EXCLUDED.employer_amount,
			total_amount    = EXCLUDED.total_amount,
			created_at      = EXCLUDED.created_at
	`
	if contribution.ContributionID == uuid.Nil {
		contribution.ContributionID = uuid.New()
	}
	if contribution.CreatedAt.IsZero() {
		contribution.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.Exec(ctx, query,
		contribution.ContributionID,
		contribution.CompanyID,
		contribution.UserID,
		contribution.StatutoryCode,
		contribution.PeriodStart,
		contribution.PeriodEnd,
		contribution.EmployeeAmount,
		contribution.EmployerAmount,
		contribution.TotalAmount,
		contribution.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to upsert employee statutory contribution",
			util.String("company_id", contribution.CompanyID.String()),
			util.String("user_id", contribution.UserID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to upsert contribution: %w", err)
	}
	return nil
}

func (r *statutoryRepository) InsertStatutorySnapshot(
	ctx context.Context,
	snapshot *models.StatutorySnapshot,
) error {

	if snapshot == nil {
		return fmt.Errorf("snapshot is nil")
	}

	if snapshot.PayrollRunID == uuid.Nil {
		return fmt.Errorf("payroll_run_id is required for statutory snapshot")
	}

	if snapshot.CompanyID == uuid.Nil {
		return fmt.Errorf("company_id is required for statutory snapshot")
	}

	// 🔥 CRITICAL: enforce created_by
	if snapshot.CreatedBy == nil || *snapshot.CreatedBy == uuid.Nil {
		return fmt.Errorf("created_by is required for statutory snapshot")
	}

	breakdownJSON, err := json.Marshal(snapshot.Breakdown)
	if err != nil {
		return fmt.Errorf("failed to marshal breakdown: %w", err)
	}

	if snapshot.SnapshotID == uuid.Nil {
		snapshot.SnapshotID = uuid.New()
	}

	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = time.Now().UTC()
	}

	const query = `
        INSERT INTO payroll.payroll_snapshot (
            snapshot_id,
            payroll_run_id,
            company_id,
            snapshot_type,
            snapshot_data,
            created_at,
            created_by,
            rule_set_id,
            rule_hash
        ) VALUES ($1, $2, $3, 'statutory', $4, $5, $6, $7, $8)
    `

	_, err = r.db.Exec(ctx, query,
		snapshot.SnapshotID,
		snapshot.PayrollRunID,
		snapshot.CompanyID,
		breakdownJSON,
		snapshot.CreatedAt,
		*snapshot.CreatedBy, // 🔥 FIXED
		snapshot.RuleSetID,
		snapshot.RuleHash,
	)

	if err != nil {
		r.logger.Error("Failed to insert statutory snapshot",
			util.String("snapshot_id", snapshot.SnapshotID.String()),
			util.String("payroll_run_id", snapshot.PayrollRunID.String()),
			util.String("rule_set_id", snapshot.RuleSetID.String()),
			util.String("created_by", snapshot.CreatedBy.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to insert statutory snapshot: %w", err)
	}

	return nil
}

func (r *statutoryRepository) CreateStatutoryRuleSet(ctx context.Context, ruleSet *models.StatutoryRuleSet) error {
	return r.WithTx(ctx, func(txRepo StatutoryRepository) error {
		repo := txRepo.(*statutoryRepository)
		const deactivateQuery = `
            UPDATE payroll.statutory_rule_set
            SET is_active = false,
                effective_to = $1
            WHERE company_id = $2
              AND country_code = $3
              AND is_active = true
        `
		_, err := repo.db.Exec(ctx,
			deactivateQuery,
			ruleSet.EffectiveFrom.AddDate(0, 0, -1),
			ruleSet.CompanyID,
			ruleSet.CountryCode,
		)
		if err != nil {
			return fmt.Errorf("failed to deactivate old rule sets: %w", err)
		}
		const insertQuery = `
            INSERT INTO payroll.statutory_rule_set (
                rule_set_id, company_id, country_code, version_label,
                effective_from, effective_to, is_active,
                created_at, created_by
            ) VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8)
        `
		if ruleSet.RuleSetID == uuid.Nil {
			ruleSet.RuleSetID = uuid.New()
		}
		if ruleSet.CreatedAt.IsZero() {
			ruleSet.CreatedAt = time.Now().UTC()
		}
		_, err = repo.db.Exec(ctx,
			insertQuery,
			ruleSet.RuleSetID,
			ruleSet.CompanyID,
			ruleSet.CountryCode,
			ruleSet.VersionLabel,
			ruleSet.EffectiveFrom,
			ruleSet.EffectiveTo,
			ruleSet.CreatedAt,
			ruleSet.CreatedBy,
		)
		return err
	})
}

func (r *statutoryRepository) UpdateStatutoryRuleSet(ctx context.Context, ruleSet *models.StatutoryRuleSet) error {
	const query = `
		UPDATE payroll.statutory_rule_set
		SET
			version_label = $1,
			effective_from = $2,
			effective_to = $3,
			is_active = $4
		WHERE rule_set_id = $5
		  AND company_id = $6
	`
	result, err := r.db.Exec(ctx, query,
		ruleSet.VersionLabel,
		ruleSet.EffectiveFrom,
		ruleSet.EffectiveTo,
		ruleSet.IsActive,
		ruleSet.RuleSetID,
		ruleSet.CompanyID,
	)
	if err != nil {
		r.logger.Error("Failed to update statutory rule set",
			util.String("rule_set_id", ruleSet.RuleSetID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update statutory rule set: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("statutory rule set not found")
	}
	return nil
}
func (r *statutoryRepository) DeactivateStatutoryRuleSet(ctx context.Context, ruleSetID uuid.UUID, deactivatedBy uuid.UUID) error {
	const query = `
        UPDATE payroll.statutory_rule_set
        SET is_active = false,
            effective_to = NOW()
        WHERE rule_set_id = $1
          AND is_active = true
    `
	result, err := r.db.Exec(ctx, query, ruleSetID)
	if err != nil {
		r.logger.Error("Failed to deactivate statutory rule set",
			zap.String("rule_set_id", ruleSetID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("failed to deactivate statutory rule set: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("statutory rule set not found or already inactive")
	}
	return nil
}

func (r *statutoryRepository) HealthCheck(ctx context.Context) error {
	const query = `SELECT 1 FROM payroll.statutory_rule_set LIMIT 1`
	var one int
	err := r.db.QueryRow(ctx, query).Scan(&one)
	if err != nil {
		r.logger.Error("Statutory repository health check failed", util.ErrorField(err))
		return fmt.Errorf("statutory repository health check failed: %w", err)
	}
	return nil
}

func (r *statutoryRepository) ListRuleSets(ctx context.Context, companyID uuid.UUID) ([]models.StatutoryRuleSet, error) {
	const query = `
		SELECT rule_set_id, company_id, country_code, version_label,
		       effective_from, effective_to, is_active,
		       created_at, created_by
		FROM payroll.statutory_rule_set
		WHERE company_id = $1
		ORDER BY effective_from DESC
	`
	rows, err := r.db.Query(ctx, query, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sets []models.StatutoryRuleSet
	for rows.Next() {
		var rs models.StatutoryRuleSet
		err := rows.Scan(
			&rs.RuleSetID,
			&rs.CompanyID,
			&rs.CountryCode,
			&rs.VersionLabel,
			&rs.EffectiveFrom,
			&rs.EffectiveTo,
			&rs.IsActive,
			&rs.CreatedAt,
			&rs.CreatedBy,
		)
		if err != nil {
			return nil, err
		}
		sets = append(sets, rs)
	}
	return sets, rows.Err()
}

func (r *statutoryRepository) GetRuleSetByID(ctx context.Context, ruleSetID uuid.UUID) (*models.StatutoryRuleSet, error) {
	const query = `
		SELECT rule_set_id, company_id, country_code, version_label,
		       effective_from, effective_to, is_active,
		       created_at, created_by
		FROM payroll.statutory_rule_set
		WHERE rule_set_id = $1
	`
	var rs models.StatutoryRuleSet
	err := r.db.QueryRow(ctx, query, ruleSetID).Scan(
		&rs.RuleSetID,
		&rs.CompanyID,
		&rs.CountryCode,
		&rs.VersionLabel,
		&rs.EffectiveFrom,
		&rs.EffectiveTo,
		&rs.IsActive,
		&rs.CreatedAt,
		&rs.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &rs, nil
}

func (r *statutoryRepository) DeactivateActiveRuleSetsByCountry(ctx context.Context, companyID uuid.UUID, countryCode string, actorID uuid.UUID) error {
	const query = `
        UPDATE payroll.statutory_rule_set
        SET is_active = false,
            effective_to = NOW()
        WHERE company_id = $1
          AND country_code = $2
          AND is_active = true
    `
	_, err := r.db.Exec(ctx, query, companyID, countryCode)
	return err
}

func (r *statutoryRepository) ActivateRuleSet(ctx context.Context, ruleSetID uuid.UUID, actorID uuid.UUID) error {
	const query = `
        UPDATE payroll.statutory_rule_set
        SET is_active = true,
            effective_to = NULL
        WHERE rule_set_id = $1
    `
	_, err := r.db.Exec(ctx, query, ruleSetID)
	return err
}

// ----------------------------------------------------------------------
// statutory_component_definition (company-aware)
// ----------------------------------------------------------------------

func (r *statutoryRepository) CreateStatutoryComponentDefinition(ctx context.Context, def *models.StatutoryComponentDefinition) error {
	const query = `
		INSERT INTO payroll.statutory_component_definition (
			company_id,
			statutory_code,
			description,
			country_code,
			calculation_basis,
			has_employee_contribution,
			has_employer_contribution,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	if def.CreatedAt.IsZero() {
		def.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.Exec(ctx, query,
		def.CompanyID,
		def.StatutoryCode,
		def.Description,
		def.CountryCode,
		def.CalculationBasis,
		def.HasEmployeeContribution,
		def.HasEmployerContribution,
		def.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create statutory component definition",
			util.String("company_id", def.CompanyID.String()),
			util.String("statutory_code", def.StatutoryCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("create statutory component definition: %w", err)
	}
	return nil
}

func (r *statutoryRepository) UpdateStatutoryComponentDefinition(ctx context.Context, def *models.StatutoryComponentDefinition) error {
	const query = `
		UPDATE payroll.statutory_component_definition
		SET description = $1,
		    country_code = $2,
		    calculation_basis = $3,
		    has_employee_contribution = $4,
		    has_employer_contribution = $5
		WHERE company_id = $6
		  AND statutory_code = $7
	`
	result, err := r.db.Exec(ctx, query,
		def.Description,
		def.CountryCode,
		def.CalculationBasis,
		def.HasEmployeeContribution,
		def.HasEmployerContribution,
		def.CompanyID,
		def.StatutoryCode,
	)
	if err != nil {
		r.logger.Error("Failed to update statutory component definition",
			util.String("company_id", def.CompanyID.String()),
			util.String("statutory_code", def.StatutoryCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("update statutory component definition: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("statutory component definition not found")
	}
	return nil
}

func (r *statutoryRepository) GetStatutoryComponentDefinition(ctx context.Context, companyID uuid.UUID, statutoryCode string) (*models.StatutoryComponentDefinition, error) {
	const query = `
		SELECT company_id, statutory_code, description,
		       country_code, calculation_basis,
		       has_employee_contribution,
		       has_employer_contribution,
		       created_at
		FROM payroll.statutory_component_definition
		WHERE company_id = $1
		  AND statutory_code = $2
	`
	var def models.StatutoryComponentDefinition
	err := r.db.QueryRow(ctx, query, companyID, statutoryCode).Scan(
		&def.CompanyID,
		&def.StatutoryCode,
		&def.Description,
		&def.CountryCode,
		&def.CalculationBasis,
		&def.HasEmployeeContribution,
		&def.HasEmployerContribution,
		&def.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get statutory component definition",
			util.String("company_id", companyID.String()),
			util.String("statutory_code", statutoryCode),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("get statutory component definition: %w", err)
	}
	return &def, nil
}

func (r *statutoryRepository) ListStatutoryComponentDefinitions(ctx context.Context, companyID uuid.UUID) ([]models.StatutoryComponentDefinition, error) {
	const query = `
		SELECT company_id, statutory_code, description,
		       country_code, calculation_basis,
		       has_employee_contribution,
		       has_employer_contribution,
		       created_at
		FROM payroll.statutory_component_definition
		WHERE company_id = $1
		ORDER BY statutory_code
	`
	rows, err := r.db.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to list statutory component definitions",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("list statutory component definitions: %w", err)
	}
	defer rows.Close()
	var defs []models.StatutoryComponentDefinition
	for rows.Next() {
		var d models.StatutoryComponentDefinition
		if err := rows.Scan(
			&d.CompanyID,
			&d.StatutoryCode,
			&d.Description,
			&d.CountryCode,
			&d.CalculationBasis,
			&d.HasEmployeeContribution,
			&d.HasEmployerContribution,
			&d.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan statutory component definition: %w", err)
		}
		defs = append(defs, d)
	}
	return defs, rows.Err()
}

// ----------------------------------------------------------------------
// statutory_contribution_rule
// ----------------------------------------------------------------------

func (r *statutoryRepository) LoadStatutoryContributionRulesByRuleSet(ctx context.Context, ruleSetID uuid.UUID, companyID uuid.UUID) ([]models.StatutoryContributionRule, error) {
	const query = `
		SELECT rule_id, company_id, rule_set_id, statutory_code,
		       contribution_side, calculation_type, rate_value,
		       wage_ceiling, min_threshold,
		       effective_from, effective_to,
		       is_active, version,
		       created_at, created_by
		FROM payroll.statutory_contribution_rule
		WHERE rule_set_id = $1
		  AND company_id = $2
		  AND is_active = true
		ORDER BY statutory_code, contribution_side
	`
	rows, err := r.db.Query(ctx, query, ruleSetID, companyID)
	if err != nil {
		r.logger.Error("Failed to load contribution rules by rule set",
			util.String("rule_set_id", ruleSetID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("load contribution rules: %w", err)
	}
	defer rows.Close()
	var rules []models.StatutoryContributionRule
	for rows.Next() {
		var rule models.StatutoryContributionRule
		err := rows.Scan(
			&rule.RuleID,
			&rule.CompanyID,
			&rule.RuleSetID,
			&rule.StatutoryCode,
			&rule.ContributionSide,
			&rule.CalculationType,
			&rule.RateValue,
			&rule.WageCeiling,
			&rule.MinThreshold,
			&rule.EffectiveFrom,
			&rule.EffectiveTo,
			&rule.IsActive,
			&rule.Version,
			&rule.CreatedAt,
			&rule.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan contribution rule: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (r *statutoryRepository) UpsertStatutoryContributionRule(ctx context.Context, input models.CreateStatutoryContributionRuleInput) error {
	const deactivateQuery = `
		UPDATE payroll.statutory_contribution_rule
		SET is_active = false,
		    effective_to = $1
		WHERE rule_set_id = $2
		  AND statutory_code = $3
		  AND contribution_side = $4
		  AND company_id = $5
		  AND is_active = true
	`
	_, err := r.db.Exec(ctx,
		deactivateQuery,
		input.EffectiveFrom.AddDate(0, 0, -1),
		input.RuleSetID,
		input.StatutoryCode,
		input.ContributionSide,
		input.CompanyID,
	)
	if err != nil {
		return fmt.Errorf("deactivate contribution rule: %w", err)
	}
	const insertQuery = `
		INSERT INTO payroll.statutory_contribution_rule (
			rule_id, company_id, rule_set_id, statutory_code,
			contribution_side, calculation_type, rate_value,
			wage_ceiling, min_threshold,
			effective_from, effective_to,
			is_active, version,
			created_at, created_by
		)
		VALUES (
			$1,$2,$3,$4,
			$5,$6,$7,
			$8,$9,
			$10,NULL,
			true,1,
			NOW(),$11
		)
	`
	_, err = r.db.Exec(ctx,
		insertQuery,
		uuid.New(),
		input.CompanyID,
		input.RuleSetID,
		input.StatutoryCode,
		input.ContributionSide,
		input.CalculationType,
		input.RateValue,
		input.WageCeiling,
		input.MinThreshold,
		input.EffectiveFrom,
		input.ActorID,
	)
	if err != nil {
		return fmt.Errorf("insert contribution rule: %w", err)
	}
	return nil
}

func (r *statutoryRepository) LoadActiveContributionRules(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]models.StatutoryContributionRule, error) {
	// First resolve the active rule set for the company at the given date
	ruleSet, err := r.ResolveRuleSet(ctx, companyID, asOf)
	if err != nil {
		return nil, err
	}
	if ruleSet == nil {
		return nil, nil // no active rule set
	}
	// Then load all contribution rules for that rule set (with company_id safety)
	return r.LoadStatutoryContributionRulesByRuleSet(ctx, ruleSet.RuleSetID, companyID)
}

func (r *statutoryRepository) GetStatutoryContributionRuleByID(ctx context.Context, ruleID uuid.UUID) (*models.StatutoryContributionRule, error) {
	const query = `
		SELECT rule_id, company_id, rule_set_id, statutory_code,
		       contribution_side, calculation_type, rate_value,
		       wage_ceiling, min_threshold,
		       effective_from, effective_to,
		       is_active, version,
		       created_at, created_by
		FROM payroll.statutory_contribution_rule
		WHERE rule_id = $1
	`
	var rule models.StatutoryContributionRule
	err := r.db.QueryRow(ctx, query, ruleID).Scan(
		&rule.RuleID,
		&rule.CompanyID,
		&rule.RuleSetID,
		&rule.StatutoryCode,
		&rule.ContributionSide,
		&rule.CalculationType,
		&rule.RateValue,
		&rule.WageCeiling,
		&rule.MinThreshold,
		&rule.EffectiveFrom,
		&rule.EffectiveTo,
		&rule.IsActive,
		&rule.Version,
		&rule.CreatedAt,
		&rule.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get contribution rule by ID: %w", err)
	}
	return &rule, nil
}

func (r *statutoryRepository) DeactivateStatutoryContributionRule(ctx context.Context, ruleID uuid.UUID, actorID uuid.UUID) error {
	const query = `
		UPDATE payroll.statutory_contribution_rule
		SET is_active = false,
		    deactivated_at = NOW(),
		    deactivated_by = $1
		WHERE rule_id = $2
		  AND is_active = true
	`
	result, err := r.db.Exec(ctx, query, actorID, ruleID)
	if err != nil {
		r.logger.Error("Failed to deactivate statutory contribution rule",
			util.String("rule_id", ruleID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("deactivate contribution rule: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("contribution rule not found or already inactive")
	}
	return nil
}

func (r *statutoryRepository) ListContributionRulesByStatutoryCode(ctx context.Context, companyID uuid.UUID, statutoryCode string) ([]models.StatutoryContributionRule, error) {
	// This returns all rules (active and inactive) for the given statutory code across all rule sets,
	// ordered by effective_from descending (newest first)
	const query = `
		SELECT rule_id, company_id, rule_set_id, statutory_code,
		       contribution_side, calculation_type, rate_value,
		       wage_ceiling, min_threshold,
		       effective_from, effective_to,
		       is_active, version,
		       created_at, created_by
		FROM payroll.statutory_contribution_rule
		WHERE company_id = $1
		  AND statutory_code = $2
		ORDER BY effective_from DESC
	`
	rows, err := r.db.Query(ctx, query, companyID, statutoryCode)
	if err != nil {
		r.logger.Error("Failed to list contribution rules by statutory code",
			util.String("company_id", companyID.String()),
			util.String("statutory_code", statutoryCode),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("list contribution rules by statutory code: %w", err)
	}
	defer rows.Close()
	var rules []models.StatutoryContributionRule
	for rows.Next() {
		var rule models.StatutoryContributionRule
		err := rows.Scan(
			&rule.RuleID,
			&rule.CompanyID,
			&rule.RuleSetID,
			&rule.StatutoryCode,
			&rule.ContributionSide,
			&rule.CalculationType,
			&rule.RateValue,
			&rule.WageCeiling,
			&rule.MinThreshold,
			&rule.EffectiveFrom,
			&rule.EffectiveTo,
			&rule.IsActive,
			&rule.Version,
			&rule.CreatedAt,
			&rule.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan contribution rule: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ==================== Component Definition ====================

func (r *statutoryRepository) DeleteStatutoryComponentDefinition(ctx context.Context, companyID uuid.UUID, statutoryCode string) error {
	const query = `
		DELETE FROM payroll.statutory_component_definition
		WHERE company_id = $1 AND statutory_code = $2
	`
	result, err := r.db.Exec(ctx, query, companyID, statutoryCode)
	if err != nil {
		r.logger.Error("Failed to delete statutory component definition",
			util.String("company_id", companyID.String()),
			util.String("statutory_code", statutoryCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("delete statutory component definition: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("statutory component definition not found")
	}
	return nil
}

// ==================== Tax Slab ====================

func (r *statutoryRepository) CreateTaxSlab(ctx context.Context, input models.CreateTaxSlabInput) error {
	const query = `
		INSERT INTO payroll.company_tax_slab (
			slab_id, company_id, statutory_code, min_income, max_income,
			tax_percentage, is_percentage, slab_order,
			effective_from, effective_to, is_active, version,
			created_at, created_by, rule_set_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, true, 1, NOW(), $10, $11)
	`
	slabID := uuid.New()
	_, err := r.db.Exec(ctx, query,
		slabID,
		input.CompanyID,
		input.StatutoryCode,
		input.MinAmount,
		input.MaxAmount,
		input.Rate,
		input.IsPercentage,
		input.SlabOrder,
		input.EffectiveFrom,
		input.CreatedBy,
		input.RuleSetID,
	)
	if err != nil {
		r.logger.Error("Failed to create tax slab",
			util.String("company_id", input.CompanyID.String()),
			util.String("statutory_code", input.StatutoryCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("create tax slab: %w", err)
	}
	return nil
}

func (r *statutoryRepository) UpdateTaxSlab(ctx context.Context, input models.UpdateTaxSlabInput) error {
	// Fetch current values
	var current struct {
		MinAmount     float64
		MaxAmount     *float64
		Rate          float64
		IsPercentage  bool
		SlabOrder     int
		EffectiveFrom time.Time
		Version       int
	}
	const getQuery = `
		SELECT min_income, max_income, tax_percentage, is_percentage, slab_order, effective_from, version
		FROM payroll.company_tax_slab
		WHERE slab_id = $1
	`
	err := r.db.QueryRow(ctx, getQuery, input.SlabID).Scan(
		&current.MinAmount, &current.MaxAmount, &current.Rate,
		&current.IsPercentage, &current.SlabOrder, &current.EffectiveFrom, &current.Version,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("tax slab not found")
		}
		return fmt.Errorf("failed to fetch current tax slab: %w", err)
	}

	// Apply updates
	newMin := current.MinAmount
	if input.MinAmount != nil {
		newMin = *input.MinAmount
	}
	newMax := current.MaxAmount
	if input.MaxAmount != nil {
		newMax = input.MaxAmount
	}
	newRate := current.Rate
	if input.Rate != nil {
		newRate = *input.Rate
	}
	newIsPercentage := current.IsPercentage
	if input.IsPercentage != nil {
		newIsPercentage = *input.IsPercentage
	}
	newOrder := current.SlabOrder
	if input.SlabOrder != nil {
		newOrder = *input.SlabOrder
	}
	newEffectiveFrom := current.EffectiveFrom
	if input.EffectiveFrom != nil {
		newEffectiveFrom = *input.EffectiveFrom
	}

	const updateQuery = `
		UPDATE payroll.company_tax_slab
		SET min_income = $1,
			max_income = $2,
			tax_percentage = $3,
			is_percentage = $4,
			slab_order = $5,
			effective_from = $6,
			version = version + 1,
			updated_at = NOW(),
			updated_by = $7
		WHERE slab_id = $8 AND version = $9
	`
	result, err := r.db.Exec(ctx, updateQuery,
		newMin, newMax, newRate, newIsPercentage, newOrder, newEffectiveFrom,
		input.UpdatedBy, input.SlabID, current.Version,
	)
	if err != nil {
		r.logger.Error("Failed to update tax slab",
			util.String("slab_id", input.SlabID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("update tax slab: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("tax slab not found or version mismatch")
	}
	return nil
}

func (r *statutoryRepository) DeactivateTaxSlab(ctx context.Context, slabID uuid.UUID, deactivatedBy uuid.UUID) error {
	const query = `
		UPDATE payroll.company_tax_slab
		SET is_active = false,
			deactivated_at = NOW(),
			deactivated_by = $1,
			version = version + 1
		WHERE slab_id = $2 AND is_active = true
	`
	result, err := r.db.Exec(ctx, query, deactivatedBy, slabID)
	if err != nil {
		r.logger.Error("Failed to deactivate tax slab",
			util.String("slab_id", slabID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("deactivate tax slab: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("tax slab not found or already inactive")
	}
	return nil
}

func (r *statutoryRepository) ListTaxSlabsByStatutoryCode(ctx context.Context, companyID uuid.UUID, statutoryCode string) ([]models.StatutoryTaxSlab, error) {
	const query = `
		SELECT slab_id, company_id, statutory_code, min_income, max_income,
		       tax_percentage, is_percentage, slab_order,
		       effective_from, effective_to, is_active,
		       version, created_at, created_by,
		       deactivated_at, deactivated_by, rule_set_id
		FROM payroll.company_tax_slab
		WHERE company_id = $1
		  AND statutory_code = $2
		ORDER BY effective_from DESC, slab_order
	`
	rows, err := r.db.Query(ctx, query, companyID, statutoryCode)
	if err != nil {
		r.logger.Error("Failed to list tax slabs by statutory code",
			util.String("company_id", companyID.String()),
			util.String("statutory_code", statutoryCode),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("list tax slabs by statutory code: %w", err)
	}
	defer rows.Close()

	var slabs []models.StatutoryTaxSlab
	for rows.Next() {
		var s models.StatutoryTaxSlab
		if err := rows.Scan(
			&s.SlabID,
			&s.CompanyID,
			&s.StatutoryCode,
			&s.MinAmount,
			&s.MaxAmount,
			&s.Rate,
			&s.IsPercentage,
			&s.SlabOrder,
			&s.EffectiveFrom,
			&s.EffectiveTo,
			&s.IsActive,
			&s.Version,
			&s.CreatedAt,
			&s.CreatedBy,
			&s.DeactivatedAt,
			&s.DeactivatedBy,
			&s.RuleSetID,
		); err != nil {
			return nil, fmt.Errorf("scan tax slab: %w", err)
		}
		slabs = append(slabs, s)
	}
	return slabs, rows.Err()
}

// ==================== Deduction Limit ====================

func (r *statutoryRepository) CreateDeductionLimit(ctx context.Context, input models.CreateDeductionLimitInput) error {
	metadataJSON, err := json.Marshal(input.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	const query = `
		INSERT INTO payroll.statutory_deduction_limit (
			limit_id, company_id, rule_set_id, limit_code, limit_value, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`
	limitID := uuid.New()
	_, err = r.db.Exec(ctx, query,
		limitID,
		input.CompanyID,
		input.RuleSetID,
		input.LimitCode,
		input.LimitValue,
		metadataJSON,
	)
	if err != nil {
		r.logger.Error("Failed to create deduction limit",
			util.String("company_id", input.CompanyID.String()),
			util.String("limit_code", input.LimitCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("create deduction limit: %w", err)
	}
	return nil
}

func (r *statutoryRepository) UpdateDeductionLimit(ctx context.Context, input models.UpdateDeductionLimitInput) error {
	var updates []string
	args := []interface{}{input.LimitID}
	argPos := 2

	if input.LimitValue != nil {
		updates = append(updates, fmt.Sprintf("limit_value = $%d", argPos))
		args = append(args, *input.LimitValue)
		argPos++
	}
	if input.Metadata != nil {
		metadataJSON, err := json.Marshal(input.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		updates = append(updates, fmt.Sprintf("metadata = $%d", argPos))
		args = append(args, metadataJSON)
		argPos++
	}
	if len(updates) == 0 {
		return fmt.Errorf("no fields to update")
	}

	query := fmt.Sprintf(`
		UPDATE payroll.statutory_deduction_limit
		SET %s
		WHERE limit_id = $1
	`, strings.Join(updates, ", "))

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to update deduction limit",
			util.String("limit_id", input.LimitID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("update deduction limit: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("deduction limit not found")
	}
	return nil
}

func (r *statutoryRepository) DeleteDeductionLimit(ctx context.Context, limitID uuid.UUID) error {
	const query = `DELETE FROM payroll.statutory_deduction_limit WHERE limit_id = $1`
	result, err := r.db.Exec(ctx, query, limitID)
	if err != nil {
		r.logger.Error("Failed to delete deduction limit",
			util.String("limit_id", limitID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("delete deduction limit: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("deduction limit not found")
	}
	return nil
}

func (r *statutoryRepository) ListDeductionLimits(ctx context.Context, companyID uuid.UUID, ruleSetID *uuid.UUID) ([]models.StatutoryDeductionLimit, error) {
	query := `
		SELECT limit_id, company_id, rule_set_id, limit_code, limit_value, metadata, created_at
		FROM payroll.statutory_deduction_limit
		WHERE company_id = $1
	`
	args := []interface{}{companyID}
	if ruleSetID != nil {
		query += " AND rule_set_id = $2"
		args = append(args, *ruleSetID)
	}
	query += " ORDER BY limit_code"

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to list deduction limits",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("list deduction limits: %w", err)
	}
	defer rows.Close()

	var limits []models.StatutoryDeductionLimit
	for rows.Next() {
		var l models.StatutoryDeductionLimit
		if err := rows.Scan(
			&l.LimitID,
			&l.CompanyID,
			&l.RuleSetID,
			&l.LimitCode,
			&l.LimitValue,
			&l.Metadata,
			&l.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan deduction limit: %w", err)
		}
		limits = append(limits, l)
	}
	return limits, rows.Err()
}

// ==================== Component Mapping (with validation) ====================

// componentExistsForCompany checks whether a component_code exists and is active
// either for the given company OR globally (company_id IS NULL).
func (r *statutoryRepository) componentExistsForCompany(
	ctx context.Context,
	companyID uuid.UUID,
	componentCode string,
) (bool, error) {

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM payroll.payroll_component
			WHERE component_code = $2
			  AND is_active = true
			  AND (company_id = $1 OR company_id IS NULL)
		)
	`

	var exists bool

	err := r.db.QueryRow(ctx, query, companyID, componentCode).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check component existence: %w", err)
	}

	return exists, nil
}

func (r *statutoryRepository) CreateComponentMapping(ctx context.Context, input models.CreateComponentMappingInput) error {
	// Validate that the component exists for the company
	exists, err := r.componentExistsForCompany(ctx, input.CompanyID, input.ComponentCode)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("component_code %s does not exist or is not active for company %s", input.ComponentCode, input.CompanyID)
	}

	const query = `
		INSERT INTO payroll.statutory_component_mapping (
			mapping_id, company_id, statutory_code, component_code,
			effective_from, effective_to, is_active, version,
			created_at, created_by, rule_set_id
		) VALUES ($1, $2, $3, $4, $5, NULL, true, 1, NOW(), $6, $7)
	`
	mappingID := uuid.New()
	_, err = r.db.Exec(ctx, query,
		mappingID,
		input.CompanyID,
		input.StatutoryCode,
		input.ComponentCode,
		input.EffectiveFrom,
		input.CreatedBy,
		input.RuleSetID,
	)
	if err != nil {
		r.logger.Error("Failed to create component mapping",
			util.String("company_id", input.CompanyID.String()),
			util.String("statutory_code", input.StatutoryCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("create component mapping: %w", err)
	}
	return nil
}

func (r *statutoryRepository) UpdateComponentMapping(ctx context.Context, input models.UpdateComponentMappingInput) error {
	// Verify current version
	var currentVersion int
	const getVersionQuery = `SELECT version FROM payroll.statutory_component_mapping WHERE mapping_id = $1`
	err := r.db.QueryRow(ctx, getVersionQuery, input.MappingID).Scan(&currentVersion)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("component mapping not found")
		}
		return fmt.Errorf("failed to fetch current mapping version: %w", err)
	}
	if currentVersion != input.Version {
		return fmt.Errorf("version mismatch: expected %d, got %d", input.Version, currentVersion)
	}

	// If component_code is being changed, validate that the new code exists for the company.
	// We need to fetch the company_id for this mapping first.
	var companyID uuid.UUID
	const getCompanyQuery = `SELECT company_id FROM payroll.statutory_component_mapping WHERE mapping_id = $1`
	err = r.db.QueryRow(ctx, getCompanyQuery, input.MappingID).Scan(&companyID)
	if err != nil {
		return fmt.Errorf("failed to fetch company_id for mapping: %w", err)
	}

	if input.ComponentCode != nil {
		exists, err := r.componentExistsForCompany(ctx, companyID, *input.ComponentCode)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("component_code %s does not exist or is not active for company %s", *input.ComponentCode, companyID)
		}
	}

	// Build dynamic update
	var updates []string
	args := []interface{}{input.MappingID}
	argPos := 2

	if input.ComponentCode != nil {
		updates = append(updates, fmt.Sprintf("component_code = $%d", argPos))
		args = append(args, *input.ComponentCode)
		argPos++
	}
	if input.EffectiveFrom != nil {
		updates = append(updates, fmt.Sprintf("effective_from = $%d", argPos))
		args = append(args, *input.EffectiveFrom)
		argPos++
	}
	// Always increment version and set updated_by
	updates = append(updates, fmt.Sprintf("version = version + 1, updated_at = NOW(), updated_by = $%d", argPos))
	args = append(args, input.UpdatedBy)
	argPos++

	query := fmt.Sprintf(`
		UPDATE payroll.statutory_component_mapping
		SET %s
		WHERE mapping_id = $1 AND version = $%d
	`, strings.Join(updates, ", "), argPos)
	args = append(args, input.Version)

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to update component mapping",
			util.String("mapping_id", input.MappingID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("update component mapping: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("component mapping not found or version mismatch")
	}
	return nil
}

func (r *statutoryRepository) DeactivateComponentMapping(ctx context.Context, mappingID uuid.UUID, deactivatedBy uuid.UUID) error {
	const query = `
		UPDATE payroll.statutory_component_mapping
		SET is_active = false,
			deactivated_at = NOW(),
			deactivated_by = $1,
			version = version + 1
		WHERE mapping_id = $2 AND is_active = true
	`
	result, err := r.db.Exec(ctx, query, deactivatedBy, mappingID)
	if err != nil {
		r.logger.Error("Failed to deactivate component mapping",
			util.String("mapping_id", mappingID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("deactivate component mapping: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("component mapping not found or already inactive")
	}
	return nil
}

func (r *statutoryRepository) ListComponentMappings(ctx context.Context, companyID uuid.UUID, statutoryCode *string) ([]models.StatutoryComponentMapping, error) {
	query := `
		SELECT mapping_id, company_id, statutory_code, component_code,
		       effective_from, effective_to, is_active,
		       version, created_at, created_by,
		       deactivated_at, deactivated_by, rule_set_id
		FROM payroll.statutory_component_mapping
		WHERE company_id = $1
	`
	args := []interface{}{companyID}
	if statutoryCode != nil {
		query += " AND statutory_code = $2"
		args = append(args, *statutoryCode)
	}
	query += " ORDER BY statutory_code, effective_from DESC"

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to list component mappings",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("list component mappings: %w", err)
	}
	defer rows.Close()

	var mappings []models.StatutoryComponentMapping
	for rows.Next() {
		var m models.StatutoryComponentMapping
		if err := rows.Scan(
			&m.MappingID,
			&m.CompanyID,
			&m.StatutoryCode,
			&m.ComponentCode,
			&m.EffectiveFrom,
			&m.EffectiveTo,
			&m.IsActive,
			&m.Version,
			&m.CreatedAt,
			&m.CreatedBy,
			&m.DeactivatedAt,
			&m.DeactivatedBy,
			&m.RuleSetID,
		); err != nil {
			return nil, fmt.Errorf("scan component mapping: %w", err)
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

func NewStatutoryRepositoryFromTx(tx *sql.Tx, logger *zap.Logger) StatutoryRepository {
	return &statutoryRepository{
		db:     &txQuerier{tx: tx},
		logger: logger,
	}
}
