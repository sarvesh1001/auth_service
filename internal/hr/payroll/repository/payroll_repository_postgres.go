package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgconn"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type payrollRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewPayrollRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) PayrollRepository {
	return &payrollRepository{
		client: postgresClient,
		logger: logger,
	}
}

// ---------------------------------------------------------------------
// Payroll Run
// ---------------------------------------------------------------------

func (r *payrollRepository) CreatePayrollRun(ctx context.Context, run *models.PayrollRun) error {
	query := `
        INSERT INTO payroll.payroll_run (
            payroll_run_id, company_id, period_start, period_end,
            status, created_at, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    `
	if run.PayrollRunID == uuid.Nil {
		run.PayrollRunID = uuid.New()
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		run.PayrollRunID,
		run.CompanyID,
		run.PeriodStart,
		run.PeriodEnd,
		run.Status,
		run.CreatedAt,
		run.CreatedBy,
	)
	if err != nil {
		r.logger.Error("Failed to create payroll run",
			util.String("company_id", run.CompanyID.String()),
			util.String("period", fmt.Sprintf("%s to %s",
				run.PeriodStart.Format("2006-01-02"),
				run.PeriodEnd.Format("2006-01-02"))),
			util.ErrorField(err))
		return fmt.Errorf("failed to create payroll run: %w", err)
	}
	return nil
}

func (r *payrollRepository) GetPayrollRunByID(ctx context.Context, runID uuid.UUID) (*models.PayrollRun, error) {
	query := `
        SELECT payroll_run_id, company_id, period_start, period_end,
               status, created_at, created_by
        FROM payroll.payroll_run
        WHERE payroll_run_id = $1
    `
	row := r.client.QueryRow(ctx, query, runID)
	var run models.PayrollRun
	err := row.Scan(
		&run.PayrollRunID,
		&run.CompanyID,
		&run.PeriodStart,
		&run.PeriodEnd,
		&run.Status,
		&run.CreatedAt,
		&run.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get payroll run",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll run: %w", err)
	}
	return &run, nil
}

func (r *payrollRepository) GetPayrollRuns(ctx context.Context, filter models.PayrollRunFilter) ([]*models.PayrollRun, int64, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("company_id = $%d", argIdx))
	args = append(args, filter.CompanyID)
	argIdx++

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *filter.Status)
		argIdx++
	}
	if filter.PeriodStart != nil {
		conditions = append(conditions, fmt.Sprintf("period_start >= $%d", argIdx))
		args = append(args, *filter.PeriodStart)
		argIdx++
	}
	if filter.PeriodEnd != nil {
		conditions = append(conditions, fmt.Sprintf("period_end <= $%d", argIdx))
		args = append(args, *filter.PeriodEnd)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM payroll.payroll_run %s", whereClause)
	var total int64
	row := r.client.QueryRow(ctx, countQuery, args...)
	if err := row.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count payroll runs: %w", err)
	}

	offset := (filter.Page - 1) * filter.PageSize
	query := fmt.Sprintf(`
        SELECT payroll_run_id, company_id, period_start, period_end,
               status, created_at, created_by
        FROM payroll.payroll_run
        %s
        ORDER BY created_at DESC
        LIMIT $%d OFFSET $%d
    `, whereClause, argIdx, argIdx+1)

	args = append(args, filter.PageSize, offset)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to get payroll runs",
			util.String("company_id", filter.CompanyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get payroll runs: %w", err)
	}
	defer rows.Close()

	var runs []*models.PayrollRun
	for rows.Next() {
		var run models.PayrollRun
		if err := rows.Scan(
			&run.PayrollRunID,
			&run.CompanyID,
			&run.PeriodStart,
			&run.PeriodEnd,
			&run.Status,
			&run.CreatedAt,
			&run.CreatedBy,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan payroll run: %w", err)
		}
		runs = append(runs, &run)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}
	return runs, total, nil
}

func (r *payrollRepository) UpdatePayrollRunStatus(ctx context.Context, runID uuid.UUID, status string) error {
	query := `
        UPDATE payroll.payroll_run
        SET status = $1
        WHERE payroll_run_id = $2
    `
	result, err := r.client.Exec(ctx, query, status, runID)
	if err != nil {
		r.logger.Error("Failed to update payroll run status",
			util.String("run_id", runID.String()),
			util.String("status", status),
			util.ErrorField(err))
		return fmt.Errorf("failed to update payroll run status: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payroll run not found")
	}
	return nil
}

func (r *payrollRepository) DeletePayrollRun(
	ctx context.Context,
	runID uuid.UUID,
) error {

	query := `
        DELETE FROM payroll.payroll_run
        WHERE payroll_run_id = $1
          AND status = 'draft'
    `

	result, err := r.client.Exec(ctx, query, runID)
	if err != nil {
		r.logger.Error("Failed to delete payroll run",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete payroll run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("cannot delete run (not found or not draft)")
	}

	return nil
}

func (r *payrollRepository) GetPayrollRunSummary(ctx context.Context, runID uuid.UUID) (*models.PayrollRunSummary, error) {
	query := `
        SELECT
            pr.payroll_run_id,
            pr.period_start,
            pr.period_end,
            pr.status,
            pr.created_at,
            COUNT(pi.payroll_item_id) as total_employees,
            COALESCE(SUM(pi.gross_amount), 0) as total_gross,
            COALESCE(SUM(pi.net_amount), 0) as total_net,
            COALESCE(SUM(pi.gross_amount - pi.net_amount), 0) as total_deductions
        FROM payroll.payroll_run pr
        LEFT JOIN payroll.payroll_item pi 
            ON pr.payroll_run_id = pi.payroll_run_id
            AND pi.is_superseded = FALSE   -- only count active items
        WHERE pr.payroll_run_id = $1
        GROUP BY pr.payroll_run_id, pr.period_start, pr.period_end, pr.status, pr.created_at
    `
	row := r.client.QueryRow(ctx, query, runID)
	var summary models.PayrollRunSummary
	err := row.Scan(
		&summary.PayrollRunID,
		&summary.PeriodStart,
		&summary.PeriodEnd,
		&summary.Status,
		&summary.CreatedAt,
		&summary.TotalEmployees,
		&summary.TotalGross,
		&summary.TotalNet,
		&summary.TotalDeductions,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get payroll run summary",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll run summary: %w", err)
	}
	return &summary, nil
}

// ---------------------------------------------------------------------
// Payroll Item (versioned)
// ---------------------------------------------------------------------

func (r *payrollRepository) CreatePayrollItem(ctx context.Context, item *models.PayrollItem) error {
	query := `
		INSERT INTO payroll.payroll_item (
			payroll_item_id, payroll_run_id, user_id,
			payable_days, unpaid_days,
			gross_amount, net_amount,
			version_number, is_superseded, superseded_at, superseded_by,
			created_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (payroll_run_id, user_id)
		DO UPDATE SET
			payable_days = EXCLUDED.payable_days,
			unpaid_days = EXCLUDED.unpaid_days,
			gross_amount = EXCLUDED.gross_amount,
			net_amount = EXCLUDED.net_amount,
			version_number = payroll.payroll_item.version_number + 1
	`

	if item.PayrollItemID == uuid.Nil {
		item.PayrollItemID = uuid.New()
	}
	if item.VersionNumber == 0 {
		item.VersionNumber = 1
	}

	item.IsSuperseded = false
	item.SupersededAt = nil
	item.SupersededBy = nil

	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		item.PayrollItemID,
		item.PayrollRunID,
		item.UserID,
		item.PayableDays,
		item.UnpaidDays,
		item.GrossAmount,
		item.NetAmount,
		item.VersionNumber,
		item.IsSuperseded,
		item.SupersededAt,
		item.SupersededBy,
		item.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create payroll item",
			util.String("run_id", item.PayrollRunID.String()),
			util.String("user_id", item.UserID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create payroll item: %w", err)
	}

	return nil
}

func (r *payrollRepository) GetPayrollItemByID(ctx context.Context, itemID uuid.UUID) (*models.PayrollItem, error) {
	query := `
        SELECT payroll_item_id, payroll_run_id, user_id,
               payable_days, unpaid_days,
               gross_amount, net_amount,
               version_number, is_superseded, superseded_at, superseded_by,
               created_at
        FROM payroll.payroll_item
        WHERE payroll_item_id = $1
    `
	row := r.client.QueryRow(ctx, query, itemID)
	var item models.PayrollItem
	err := row.Scan(
		&item.PayrollItemID,
		&item.PayrollRunID,
		&item.UserID,
		&item.PayableDays,
		&item.UnpaidDays,
		&item.GrossAmount,
		&item.NetAmount,
		&item.VersionNumber,
		&item.IsSuperseded,
		&item.SupersededAt,
		&item.SupersededBy,
		&item.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get payroll item",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll item: %w", err)
	}
	return &item, nil
}

func (r *payrollRepository) GetPayrollItemsByRun(ctx context.Context, runID uuid.UUID) ([]*models.PayrollItem, error) {
	query := `
        SELECT payroll_item_id, payroll_run_id, user_id,
               payable_days, unpaid_days,
               gross_amount, net_amount,
               version_number, is_superseded, superseded_at, superseded_by,
               created_at
        FROM payroll.payroll_item
        WHERE payroll_run_id = $1
          AND is_superseded = FALSE   -- only active items
        ORDER BY user_id, version_number
    `
	rows, err := r.client.Query(ctx, query, runID)
	if err != nil {
		r.logger.Error("Failed to get payroll items by run",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll items: %w", err)
	}
	defer rows.Close()

	var items []*models.PayrollItem
	for rows.Next() {
		var item models.PayrollItem
		if err := rows.Scan(
			&item.PayrollItemID,
			&item.PayrollRunID,
			&item.UserID,
			&item.PayableDays,
			&item.UnpaidDays,
			&item.GrossAmount,
			&item.NetAmount,
			&item.VersionNumber,
			&item.IsSuperseded,
			&item.SupersededAt,
			&item.SupersededBy,
			&item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan payroll item: %w", err)
		}
		items = append(items, &item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return items, nil
}

// GetPayrollItemDetail now includes global components by allowing pc.company_id IS NULL
func (r *payrollRepository) GetPayrollItemDetail(ctx context.Context, itemID uuid.UUID) (*models.PayrollItemDetail, error) {
	// First get the item detail including company_id from payroll_run
	query := `
        SELECT
            pi.payroll_item_id,
            pi.payroll_run_id,
            pi.user_id,
            pi.payable_days,
            pi.unpaid_days,
            pi.gross_amount,
            pi.net_amount,
            pi.version_number,
            pi.is_superseded,
            pi.superseded_at,
            pi.superseded_by,
            pi.created_at,
            u.username,
            u.full_name,
            ce.employee_id,
            p.title as position_title,
            d.department_name,
            pr.company_id   -- added to use in ledger join
        FROM payroll.payroll_item pi
        JOIN payroll.payroll_run pr ON pi.payroll_run_id = pr.payroll_run_id
        JOIN users u ON pi.user_id = u.user_id
        JOIN company_employees ce ON pi.user_id = ce.user_id AND ce.company_id = pr.company_id
        LEFT JOIN positions p ON ce.position_id = p.position_id
        LEFT JOIN departments d ON p.department_id = d.department_id
        WHERE pi.payroll_item_id = $1
    `
	row := r.client.QueryRow(ctx, query, itemID)
	var detail models.PayrollItemDetail
	var companyID uuid.UUID
	err := row.Scan(
		&detail.PayrollItemID,
		&detail.PayrollRunID,
		&detail.UserID,
		&detail.PayableDays,
		&detail.UnpaidDays,
		&detail.GrossAmount,
		&detail.NetAmount,
		&detail.VersionNumber,
		&detail.IsSuperseded,
		&detail.SupersededAt,
		&detail.SupersededBy,
		&detail.CreatedAt,
		&detail.Username,
		&detail.FullName,
		&detail.EmployeeID,
		&detail.PositionTitle,
		&detail.DepartmentName,
		&companyID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get payroll item detail",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll item detail: %w", err)
	}

	// Fetch ledger entries, joining with payroll_component using company_id, including global components
	ledgerQuery := `
        SELECT
            pl.component_code,
            pc.component_type,
            pc.description,
            pl.amount,
            pc.is_taxable
        FROM payroll.payroll_ledger pl
        JOIN payroll.payroll_item pi ON pl.payroll_item_id = pi.payroll_item_id
        JOIN payroll.payroll_run pr ON pi.payroll_run_id = pr.payroll_run_id
        JOIN payroll.payroll_component pc 
            ON pl.component_code = pc.component_code 
            AND (pc.company_id = pr.company_id OR pc.company_id IS NULL)
        WHERE pl.payroll_item_id = $1
    `
	rows, err := r.client.Query(ctx, ledgerQuery, itemID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ledger entries: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ledgerItem models.PayrollLedgerItem
		if err := rows.Scan(
			&ledgerItem.ComponentCode,
			&ledgerItem.ComponentType,
			&ledgerItem.Description,
			&ledgerItem.Amount,
			&ledgerItem.IsTaxable,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ledger entry: %w", err)
		}
		detail.Components = append(detail.Components, ledgerItem)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return &detail, nil
}

// SupersedePayrollItemTx marks the current active item as superseded and returns its version number.
// It must be called inside a transaction before inserting a new version.
func (r *payrollRepository) SupersedePayrollItemTx(
	ctx context.Context,
	tx *sql.Tx,
	runID uuid.UUID,
	userID uuid.UUID,
	actorID uuid.UUID,
) (int, error) {

	var currentVersion int

	query := `
        SELECT version_number
        FROM payroll.payroll_item
        WHERE payroll_run_id = $1
          AND user_id = $2
          AND is_superseded = FALSE
        FOR UPDATE
    `

	err := tx.QueryRowContext(ctx, query, runID, userID).Scan(&currentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil // no active item to supersede
	}
	if err != nil {
		return 0, fmt.Errorf("failed to lock current item: %w", err)
	}

	updateQuery := `
        UPDATE payroll.payroll_item
        SET is_superseded = TRUE,
            superseded_at = NOW(),
            superseded_by = $3
        WHERE payroll_run_id = $1
          AND user_id = $2
          AND is_superseded = FALSE
    `

	_, err = tx.ExecContext(ctx, updateQuery, runID, userID, actorID)
	if err != nil {
		return 0, fmt.Errorf("failed to supersede item: %w", err)
	}

	return currentVersion, nil
}

// ---------------------------------------------------------------------
// Bulk operations (no hard deletes)
// ---------------------------------------------------------------------

func (r *payrollRepository) BulkCreatePayrollItems(
	ctx context.Context,
	items []*models.PayrollItem,
) error {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	query := `
		INSERT INTO payroll.payroll_item (
			payroll_item_id, payroll_run_id, user_id,
			payable_days, unpaid_days,
			gross_amount, net_amount,
			version_number, is_superseded, superseded_at, superseded_by,
			created_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (payroll_run_id, user_id)
		DO UPDATE SET
			payable_days = EXCLUDED.payable_days,
			unpaid_days = EXCLUDED.unpaid_days,
			gross_amount = EXCLUDED.gross_amount,
			net_amount = EXCLUDED.net_amount,
			version_number = payroll.payroll_item.version_number + 1
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}

	defer stmt.Close()

	for _, item := range items {

		if item.PayrollItemID == uuid.Nil {
			item.PayrollItemID = uuid.New()
		}

		if item.VersionNumber == 0 {
			item.VersionNumber = 1
		}

		item.IsSuperseded = false
		item.SupersededAt = nil
		item.SupersededBy = nil

		if item.CreatedAt.IsZero() {
			item.CreatedAt = time.Now().UTC()
		}

		_, err := stmt.ExecContext(ctx,
			item.PayrollItemID,
			item.PayrollRunID,
			item.UserID,
			item.PayableDays,
			item.UnpaidDays,
			item.GrossAmount,
			item.NetAmount,
			item.VersionNumber,
			item.IsSuperseded,
			item.SupersededAt,
			item.SupersededBy,
			item.CreatedAt,
		)

		if err != nil {
			return fmt.Errorf("failed to insert payroll item %s: %w",
				item.PayrollItemID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// PayrollItemExists checks if an active item exists for the given run and user.
func (r *payrollRepository) PayrollItemExists(
	ctx context.Context,
	runID uuid.UUID,
	userID uuid.UUID,
) (bool, error) {
	query := `
        SELECT EXISTS (
            SELECT 1
            FROM payroll.payroll_item
            WHERE payroll_run_id = $1
              AND user_id = $2
              AND is_superseded = FALSE
        )
    `
	var exists bool
	err := r.client.QueryRow(ctx, query, runID, userID).Scan(&exists)
	if err != nil {
		r.logger.Error("Failed to check payroll item existence",
			util.String("run_id", runID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check payroll item: %w", err)
	}
	return exists, nil
}

// ---------------------------------------------------------------------
// Payroll Component – company‑specific + global
// ---------------------------------------------------------------------

func (r *payrollRepository) CreateComponent(ctx context.Context, component *models.PayrollComponent) error {
	query := `
        INSERT INTO payroll.payroll_component (
            company_id, component_code, component_type, description,
            is_taxable, is_system, is_active, contribution_side
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (company_id, component_code) DO UPDATE SET
            component_type = EXCLUDED.component_type,
            description = EXCLUDED.description,
            is_taxable = EXCLUDED.is_taxable,
            is_active = EXCLUDED.is_active,
            contribution_side = EXCLUDED.contribution_side
        WHERE payroll.payroll_component.is_system = FALSE
    `
	_, err := r.client.Exec(ctx, query,
		component.CompanyID,
		component.ComponentCode,
		component.ComponentType,
		component.Description,
		component.IsTaxable,
		component.IsSystem,
		component.IsActive,
		component.ContributionSide,
	)
	if err != nil {
		r.logger.Error("Failed to create payroll component",
			util.String("company_id", component.CompanyID.String()),
			util.String("code", component.ComponentCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create payroll component: %w", err)
	}
	return nil
}

func (r *payrollRepository) GetComponent(
	ctx context.Context,
	companyID uuid.UUID,
	code string,
) (*models.PayrollComponent, error) {

	query := `
		SELECT
			component_code,
			component_type,
			description,
			is_taxable,
			is_system,
			is_active,
			contribution_side,
			company_id
		FROM payroll.payroll_component
		WHERE component_code = $2
		  AND (company_id = $1 OR company_id IS NULL)
		ORDER BY company_id DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, code)

	var component models.PayrollComponent
	var dbCompanyID *uuid.UUID

	err := row.Scan(
		&component.ComponentCode,
		&component.ComponentType,
		&component.Description,
		&component.IsTaxable,
		&component.IsSystem,
		&component.IsActive,
		&component.ContributionSide,
		&dbCompanyID,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		r.logger.Error(
			"Failed to get payroll component",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err),
		)

		return nil, fmt.Errorf("failed to get payroll component: %w", err)
	}

	// If global component, assign requesting companyID logically
	if dbCompanyID != nil {
		component.CompanyID = *dbCompanyID
	} else {
		component.CompanyID = companyID
	}

	return &component, nil
}

// GetComponents now returns both company‑specific and global components
func (r *payrollRepository) GetComponents(ctx context.Context, companyID uuid.UUID, filter models.ComponentFilter) ([]*models.PayrollComponent, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("(company_id = $%d OR company_id IS NULL)", argIdx))
	args = append(args, companyID)
	argIdx++

	if filter.ComponentType != nil {
		conditions = append(conditions, fmt.Sprintf("component_type = $%d", argIdx))
		args = append(args, *filter.ComponentType)
		argIdx++
	}
	if filter.IsTaxable != nil {
		conditions = append(conditions, fmt.Sprintf("is_taxable = $%d", argIdx))
		args = append(args, *filter.IsTaxable)
		argIdx++
	}
	if filter.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("is_system = $%d", argIdx))
		args = append(args, *filter.IsSystem)
		argIdx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIdx))
		args = append(args, *filter.IsActive)
		argIdx++
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
        SELECT component_code, component_type, description,
               is_taxable, is_system, is_active, contribution_side
        FROM payroll.payroll_component
        %s
        ORDER BY component_code
    `, whereClause)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to get payroll components",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll components: %w", err)
	}
	defer rows.Close()

	var components []*models.PayrollComponent
	for rows.Next() {
		var component models.PayrollComponent
		component.CompanyID = companyID
		if err := rows.Scan(
			&component.ComponentCode,
			&component.ComponentType,
			&component.Description,
			&component.IsTaxable,
			&component.IsSystem,
			&component.IsActive,
			&component.ContributionSide,
		); err != nil {
			return nil, fmt.Errorf("failed to scan payroll component: %w", err)
		}
		components = append(components, &component)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return components, nil
}

func (r *payrollRepository) UpdateComponent(ctx context.Context, component *models.PayrollComponent) error {
	query := `
        UPDATE payroll.payroll_component
        SET component_type = $1,
            description = $2,
            is_taxable = $3,
            is_active = $4,
            contribution_side = $5
        WHERE company_id = $6 AND component_code = $7
          AND is_system = FALSE
    `
	result, err := r.client.Exec(ctx, query,
		component.ComponentType,
		component.Description,
		component.IsTaxable,
		component.IsActive,
		component.ContributionSide,
		component.CompanyID,
		component.ComponentCode,
	)
	if err != nil {
		r.logger.Error("Failed to update payroll component",
			util.String("company_id", component.CompanyID.String()),
			util.String("code", component.ComponentCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to update payroll component: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payroll component not found or is system component")
	}
	return nil
}

func (r *payrollRepository) DeactivateComponent(ctx context.Context, companyID uuid.UUID, code string) error {
	query := `
        UPDATE payroll.payroll_component
        SET is_active = false
        WHERE company_id = $1 AND component_code = $2
          AND is_system = FALSE
    `
	result, err := r.client.Exec(ctx, query, companyID, code)
	if err != nil {
		r.logger.Error("Failed to deactivate payroll component",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return fmt.Errorf("failed to deactivate payroll component: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payroll component not found or is system component")
	}
	return nil
}

// ---------------------------------------------------------------------
// Payroll Ledger – joins with payroll_component now include global components
// ---------------------------------------------------------------------

func (r *payrollRepository) CreateLedgerEntry(ctx context.Context, entry *models.PayrollLedger) error {
	query := `
        INSERT INTO payroll.payroll_ledger (
            ledger_id, payroll_item_id, component_code, amount, created_at
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (payroll_item_id, component_code)
        DO UPDATE SET
            amount = EXCLUDED.amount
    `
	if entry.LedgerID == uuid.Nil {
		entry.LedgerID = uuid.New()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		entry.LedgerID,
		entry.PayrollItemID,
		entry.ComponentCode,
		entry.Amount,
		entry.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to upsert payroll ledger entry",
			util.String("item_id", entry.PayrollItemID.String()),
			util.String("component", entry.ComponentCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to upsert payroll ledger entry: %w", err)
	}
	return nil
}

func (r *payrollRepository) GetLedgerEntriesByItem(ctx context.Context, itemID uuid.UUID) ([]*models.PayrollLedger, error) {
	query := `
        SELECT ledger_id, payroll_item_id, component_code, amount, created_at
        FROM payroll.payroll_ledger
        WHERE payroll_item_id = $1
        ORDER BY created_at
    `
	rows, err := r.client.Query(ctx, query, itemID)
	if err != nil {
		r.logger.Error("Failed to get ledger entries by item",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get ledger entries: %w", err)
	}
	defer rows.Close()

	var entries []*models.PayrollLedger
	for rows.Next() {
		var entry models.PayrollLedger
		if err := rows.Scan(
			&entry.LedgerID,
			&entry.PayrollItemID,
			&entry.ComponentCode,
			&entry.Amount,
			&entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ledger entry: %w", err)
		}
		entries = append(entries, &entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return entries, nil
}

// GetLedgerSummaryByRun now includes global components
func (r *payrollRepository) GetLedgerSummaryByRun(ctx context.Context, runID uuid.UUID) ([]*models.LedgerSummary, error) {
	query := `
        SELECT
            pl.component_code,
            pc.component_type,
            pc.description,
            SUM(pl.amount) as total_amount,
            pc.is_taxable,
            pc.contribution_side
        FROM payroll.payroll_ledger pl
        JOIN payroll.payroll_item pi ON pl.payroll_item_id = pi.payroll_item_id
        JOIN payroll.payroll_run pr ON pi.payroll_run_id = pr.payroll_run_id
        JOIN payroll.payroll_component pc 
            ON pl.component_code = pc.component_code 
            AND (pc.company_id = pr.company_id OR pc.company_id IS NULL)
        WHERE pi.payroll_run_id = $1
          AND pi.is_superseded = FALSE   -- only active items
        GROUP BY pl.component_code, pc.component_type, pc.description, pc.is_taxable, pc.contribution_side
        ORDER BY pc.component_type, pl.component_code
    `
	rows, err := r.client.Query(ctx, query, runID)
	if err != nil {
		r.logger.Error("Failed to get ledger summary by run",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get ledger summary: %w", err)
	}
	defer rows.Close()

	var summaries []*models.LedgerSummary
	for rows.Next() {
		var summary models.LedgerSummary
		if err := rows.Scan(
			&summary.ComponentCode,
			&summary.ComponentType,
			&summary.Description,
			&summary.TotalAmount,
			&summary.IsTaxable,
			&summary.ContributionSide,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ledger summary: %w", err)
		}
		summaries = append(summaries, &summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return summaries, nil
}

func (r *payrollRepository) BulkCreateLedgerEntries(ctx context.Context, entries []*models.PayrollLedger) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	query := `
        INSERT INTO payroll.payroll_ledger (
            ledger_id, payroll_item_id, component_code, amount, created_at
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (payroll_item_id, component_code)
        DO UPDATE SET
            amount = EXCLUDED.amount
    `
	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, entry := range entries {
		if entry.LedgerID == uuid.Nil {
			entry.LedgerID = uuid.New()
		}
		if entry.CreatedAt.IsZero() {
			entry.CreatedAt = time.Now().UTC()
		}
		_, err := stmt.ExecContext(ctx,
			entry.LedgerID,
			entry.PayrollItemID,
			entry.ComponentCode,
			entry.Amount,
			entry.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to upsert ledger entry %s: %w", entry.LedgerID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Payroll Snapshot
// ---------------------------------------------------------------------

func (r *payrollRepository) CreateSnapshot(ctx context.Context, snapshot *models.PayrollSnapshot) error {
	query := `
        INSERT INTO payroll.payroll_snapshot (
            snapshot_id, payroll_run_id, company_id, snapshot_type,
            snapshot_data, created_at, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    `
	if snapshot.SnapshotID == uuid.Nil {
		snapshot.SnapshotID = uuid.New()
	}
	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		snapshot.SnapshotID,
		snapshot.PayrollRunID,
		snapshot.CompanyID,
		snapshot.SnapshotType,
		snapshot.SnapshotData,
		snapshot.CreatedAt,
		snapshot.CreatedBy,
	)
	if err != nil {
		r.logger.Error("Failed to create payroll snapshot",
			util.String("run_id", snapshot.PayrollRunID.String()),
			util.String("type", snapshot.SnapshotType),
			util.ErrorField(err))
		return fmt.Errorf("failed to create payroll snapshot: %w", err)
	}
	return nil
}

func (r *payrollRepository) GetSnapshot(ctx context.Context, snapshotID uuid.UUID) (*models.PayrollSnapshot, error) {
	query := `
        SELECT snapshot_id, payroll_run_id, company_id, snapshot_type,
               snapshot_data, created_at, created_by
        FROM payroll.payroll_snapshot
        WHERE snapshot_id = $1
    `
	row := r.client.QueryRow(ctx, query, snapshotID)
	var snapshot models.PayrollSnapshot
	err := row.Scan(
		&snapshot.SnapshotID,
		&snapshot.PayrollRunID,
		&snapshot.CompanyID,
		&snapshot.SnapshotType,
		&snapshot.SnapshotData,
		&snapshot.CreatedAt,
		&snapshot.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get payroll snapshot",
			util.String("snapshot_id", snapshotID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll snapshot: %w", err)
	}
	return &snapshot, nil
}

func (r *payrollRepository) GetSnapshotsByRun(ctx context.Context, runID uuid.UUID) ([]*models.PayrollSnapshot, error) {
	query := `
        SELECT snapshot_id, payroll_run_id, company_id, snapshot_type,
               snapshot_data, created_at, created_by
        FROM payroll.payroll_snapshot
        WHERE payroll_run_id = $1
        ORDER BY created_at DESC
    `
	rows, err := r.client.Query(ctx, query, runID)
	if err != nil {
		r.logger.Error("Failed to get payroll snapshots by run",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll snapshots: %w", err)
	}
	defer rows.Close()

	var snapshots []*models.PayrollSnapshot
	for rows.Next() {
		var snapshot models.PayrollSnapshot
		if err := rows.Scan(
			&snapshot.SnapshotID,
			&snapshot.PayrollRunID,
			&snapshot.CompanyID,
			&snapshot.SnapshotType,
			&snapshot.SnapshotData,
			&snapshot.CreatedAt,
			&snapshot.CreatedBy,
		); err != nil {
			return nil, fmt.Errorf("failed to scan payroll snapshot: %w", err)
		}
		snapshots = append(snapshots, &snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return snapshots, nil
}

// ---------------------------------------------------------------------
// Payroll Period Lock
// ---------------------------------------------------------------------

func (r *payrollRepository) CreatePayrollPeriodLock(
	ctx context.Context,
	lock *models.PayrollPeriodLock,
) error {
	query := `
        INSERT INTO payroll.payroll_period_lock (
            lock_id, company_id, period_start, period_end,
            locked_by, locked_at, reason
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    `
	if lock.LockID == uuid.Nil {
		lock.LockID = uuid.New()
	}
	if lock.LockedAt.IsZero() {
		lock.LockedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		lock.LockID,
		lock.CompanyID,
		lock.PeriodStart,
		lock.PeriodEnd,
		lock.LockedBy,
		lock.LockedAt,
		lock.Reason,
	)
	if err != nil {
		r.logger.Error("Failed to create payroll period lock",
			util.String("company_id", lock.CompanyID.String()),
			util.String("period", fmt.Sprintf("%s to %s",
				lock.PeriodStart.Format("2006-01-02"),
				lock.PeriodEnd.Format("2006-01-02"))),
			util.ErrorField(err))
		return fmt.Errorf("failed to create payroll period lock: %w", err)
	}
	return nil
}

func (r *payrollRepository) DeletePayrollPeriodLock(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) error {
	query := `
        DELETE FROM payroll.payroll_period_lock
        WHERE company_id = $1
          AND period_start = $2
          AND period_end = $3
    `
	result, err := r.client.Exec(ctx, query, companyID, periodStart, periodEnd)
	if err != nil {
		r.logger.Error("Failed to delete payroll period lock",
			util.String("company_id", companyID.String()),
			util.String("period", fmt.Sprintf("%s to %s",
				periodStart.Format("2006-01-02"),
				periodEnd.Format("2006-01-02"))),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete payroll period lock: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payroll period lock not found")
	}
	return nil
}

func (r *payrollRepository) IsPayrollPeriodLocked(
	ctx context.Context,
	companyID uuid.UUID,
	date time.Time,
) (bool, error) {
	query := `
        SELECT EXISTS (
            SELECT 1
            FROM payroll.payroll_period_lock
            WHERE company_id = $1
              AND period_start <= $2
              AND period_end >= $2
        )
    `
	var locked bool
	err := r.client.QueryRow(ctx, query, companyID, date).Scan(&locked)
	if err != nil {
		r.logger.Error("Failed to check if payroll period is locked",
			util.String("company_id", companyID.String()),
			util.String("date", date.Format("2006-01-02")),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check payroll period lock: %w", err)
	}
	return locked, nil
}

func (r *payrollRepository) IsPayrollPeriodLockedRange(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (bool, error) {
	query := `
        SELECT EXISTS (
            SELECT 1
            FROM payroll.payroll_period_lock
            WHERE company_id = $1
              AND period_start <= $3
              AND period_end >= $2
        )
    `
	var locked bool
	err := r.client.QueryRow(ctx, query, companyID, startDate, endDate).Scan(&locked)
	if err != nil {
		r.logger.Error("Failed to check payroll period lock range",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check payroll period lock range: %w", err)
	}
	return locked, nil
}

func (r *payrollRepository) ListPayrollLocks(
	ctx context.Context,
	companyID uuid.UUID,
	from, to time.Time,
) ([]*models.PayrollPeriodLock, error) {

	query := `
		SELECT
			lock_id,
			company_id,
			period_start,
			period_end,
			locked_by,
			locked_at,
			reason
		FROM payroll.payroll_period_lock
		WHERE company_id = $1
		  AND NOT (
			period_end < $2
			OR period_start > $3
		  )
		ORDER BY period_start DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, from, to)
	if err != nil {
		r.logger.Error("Failed to list payroll locks",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list payroll locks: %w", err)
	}
	defer rows.Close()

	var locks []*models.PayrollPeriodLock

	for rows.Next() {
		var l models.PayrollPeriodLock
		err := rows.Scan(
			&l.LockID,
			&l.CompanyID,
			&l.PeriodStart,
			&l.PeriodEnd,
			&l.LockedBy,
			&l.LockedAt,
			&l.Reason,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan payroll lock: %w", err)
		}
		locks = append(locks, &l)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return locks, nil
}

// ---------------------------------------------------------------------
// Attendance related
// ---------------------------------------------------------------------

func (r *payrollRepository) GetPayrollAttendanceDays(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (float64, float64, error) {
	query := `
        SELECT
            COUNT(*)::float8 AS total_days,
            COALESCE(
                SUM(
                    CASE
                        WHEN status IN ('present', 'late') THEN 1.0
                        WHEN status = 'half_day' THEN 0.5
                        ELSE 0.0
                    END
                ),
                0
            ) AS payable_days
        FROM attendance_daily_summary
        WHERE company_id = $1
          AND user_id = $2
          AND attendance_date BETWEEN $3 AND $4
    `
	var totalDays float64
	var payableDays float64
	err := r.client.QueryRow(
		ctx,
		query,
		companyID,
		userID,
		startDate,
		endDate,
	).Scan(&totalDays, &payableDays)
	if err != nil {
		r.logger.Error("Failed to get payroll attendance days",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return 0, 0, fmt.Errorf("failed to get payroll attendance days: %w", err)
	}
	return totalDays, payableDays, nil
}

func (r *payrollRepository) GetEmployeeIDsForPayroll(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) ([]uuid.UUID, error) {

	query := `
		SELECT DISTINCT es.user_id
		FROM payroll.employee_salary es

		-- Must belong to active company employee
		JOIN company_employees ce
		  ON ce.user_id = es.user_id
		 AND ce.company_id = es.company_id

		-- Profile is optional (defensive)
		LEFT JOIN employee_profiles ep
		  ON ep.user_id = es.user_id
		 AND ep.company_id = es.company_id

		-- Exit handling
		LEFT JOIN employee_exit ee
		  ON ee.company_id = es.company_id
		 AND ee.user_id = es.user_id
		 AND ee.exit_state = 'effective'

		WHERE es.company_id = $1
		  -- Salary must be active and overlap payroll period
		  AND es.is_active = TRUE
		  AND es.effective_from <= $3
		  AND (es.effective_to IS NULL OR es.effective_to >= $2)

		  -- Company employee must be active
		  AND ce.is_active = TRUE
		  AND (ce.hire_date IS NULL OR ce.hire_date <= $3)

		  -- Employment status (profile optional)
		  AND (
		        ep.employment_status IS NULL
		        OR ep.employment_status IN ('active','notice')
		      )

		  -- Exit must not block payroll
		  AND (
		        ee.exit_date IS NULL
		        OR ee.exit_date >= $2
		      )
	`

	rows, err := r.client.Query(ctx, query,
		companyID,
		periodStart, // $2
		periodEnd,   // $3
	)
	if err != nil {
		r.logger.Error("Failed to get employee IDs for payroll",
			util.String("company_id", companyID.String()),
			util.String("period_start", periodStart.Format("2006-01-02")),
			util.String("period_end", periodEnd.Format("2006-01-02")),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get employee IDs: %w", err)
	}
	defer rows.Close()

	var employeeIDs []uuid.UUID

	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("failed to scan user ID: %w", err)
		}
		employeeIDs = append(employeeIDs, userID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return employeeIDs, nil
}

// ---------------------------------------------------------------------
// Health Check
// ---------------------------------------------------------------------

func (r *payrollRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM payroll.payroll_run LIMIT 1`
	var result int
	row := r.client.QueryRow(ctx, query)
	err := row.Scan(&result)
	if err != nil {
		r.logger.Error("Payroll repository health check failed", util.ErrorField(err))
		return fmt.Errorf("payroll repository health check failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Transactional Helpers (used by processing service)
// ---------------------------------------------------------------------

func (r *payrollRepository) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	tx, err := r.client.BeginTx(ctx, opts)
	if err != nil {
		r.logger.Error("Failed to begin transaction",
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	return tx, nil
}

func (r *payrollRepository) GetPayrollRunForUpdateTx(
	ctx context.Context,
	tx *sql.Tx,
	runID uuid.UUID,
) (*models.PayrollRun, error) {
	query := `
        SELECT payroll_run_id, company_id, period_start, period_end,
               status, total_employees, processed_count, failed_count,
               last_processed_at, created_at, created_by
        FROM payroll.payroll_run
        WHERE payroll_run_id = $1
        FOR UPDATE
    `
	row := tx.QueryRowContext(ctx, query, runID)
	var run models.PayrollRun
	err := row.Scan(
		&run.PayrollRunID,
		&run.CompanyID,
		&run.PeriodStart,
		&run.PeriodEnd,
		&run.Status,
		&run.TotalEmployees,
		&run.ProcessedCount,
		&run.FailedCount,
		&run.LastProcessedAt,
		&run.CreatedAt,
		&run.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to lock payroll run: %w", err)
	}
	return &run, nil
}

func (r *payrollRepository) UpdatePayrollRunStatusTx(
	ctx context.Context,
	tx *sql.Tx,
	runID uuid.UUID,
	status string,
) error {
	query := `
        UPDATE payroll.payroll_run
        SET status = $1
        WHERE payroll_run_id = $2
    `
	result, err := tx.ExecContext(ctx, query, status, runID)
	if err != nil {
		return fmt.Errorf("failed to update payroll run status: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payroll run not found")
	}
	return nil
}

func (r *payrollRepository) PayrollItemExistsTx(
	ctx context.Context,
	tx *sql.Tx,
	runID uuid.UUID,
	userID uuid.UUID,
) (bool, error) {
	query := `
        SELECT EXISTS (
            SELECT 1
            FROM payroll.payroll_item
            WHERE payroll_run_id = $1
              AND user_id = $2
              AND is_superseded = FALSE
        )
    `
	var exists bool
	err := tx.QueryRowContext(ctx, query, runID, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check payroll item: %w", err)
	}
	return exists, nil
}

func (r *payrollRepository) CreatePayrollItemTx(
	ctx context.Context,
	tx *sql.Tx,
	item *models.PayrollItem,
) error {

	query := `
		INSERT INTO payroll.payroll_item (
			payroll_item_id, payroll_run_id, user_id,
			payable_days, unpaid_days,
			gross_amount, net_amount,
			version_number, is_superseded, superseded_at, superseded_by,
			created_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (payroll_run_id, user_id)
		DO UPDATE SET
			payable_days = EXCLUDED.payable_days,
			unpaid_days = EXCLUDED.unpaid_days,
			gross_amount = EXCLUDED.gross_amount,
			net_amount = EXCLUDED.net_amount,
			version_number = payroll.payroll_item.version_number + 1
	`

	if item.PayrollItemID == uuid.Nil {
		item.PayrollItemID = uuid.New()
	}

	if item.VersionNumber == 0 {
		item.VersionNumber = 1
	}

	item.IsSuperseded = false
	item.SupersededAt = nil
	item.SupersededBy = nil

	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}

	_, err := tx.ExecContext(ctx, query,
		item.PayrollItemID,
		item.PayrollRunID,
		item.UserID,
		item.PayableDays,
		item.UnpaidDays,
		item.GrossAmount,
		item.NetAmount,
		item.VersionNumber,
		item.IsSuperseded,
		item.SupersededAt,
		item.SupersededBy,
		item.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create payroll item: %w", err)
	}

	return nil
}

func (r *payrollRepository) BulkCreateLedgerEntriesTx(
	ctx context.Context,
	tx *sql.Tx,
	entries []*models.PayrollLedger,
) error {
	query := `
        INSERT INTO payroll.payroll_ledger (
            ledger_id, payroll_item_id, component_code, amount, created_at
        ) VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (payroll_item_id, component_code)
        DO UPDATE SET
            amount = EXCLUDED.amount
    `
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, entry := range entries {
		if entry.LedgerID == uuid.Nil {
			entry.LedgerID = uuid.New()
		}
		if entry.CreatedAt.IsZero() {
			entry.CreatedAt = time.Now().UTC()
		}
		_, err := stmt.ExecContext(ctx,
			entry.LedgerID,
			entry.PayrollItemID,
			entry.ComponentCode,
			entry.Amount,
			entry.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed ledger upsert: %w", err)
		}
	}
	return nil
}

func (r *payrollRepository) CreateSnapshotTx(
	ctx context.Context,
	tx *sql.Tx,
	snapshot *models.PayrollSnapshot,
) error {
	query := `
        INSERT INTO payroll.payroll_snapshot (
            snapshot_id, payroll_run_id, company_id,
            snapshot_type, snapshot_data,
            created_at, created_by
        ) VALUES ($1,$2,$3,$4,$5,$6,$7)
    `
	_, err := tx.ExecContext(ctx, query,
		snapshot.SnapshotID,
		snapshot.PayrollRunID,
		snapshot.CompanyID,
		snapshot.SnapshotType,
		snapshot.SnapshotData,
		snapshot.CreatedAt,
		snapshot.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}
	return nil
}

func (r *payrollRepository) BuildStatutoryYTDContext(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	financialYearStart time.Time,
) (*models.StatutoryYTDContext, error) {

	query := `
		SELECT statutory_code,
		       COALESCE(SUM(employee_amount), 0) AS total_employee,
		       COALESCE(SUM(employer_amount), 0) AS total_employer
		FROM payroll.employee_statutory_contribution
		WHERE company_id = $1
		  AND user_id = $2
		  AND period_start >= $3
		GROUP BY statutory_code
	`

	rows, err := r.client.Query(ctx, query, companyID, userID, financialYearStart)
	if err != nil {
		return nil, fmt.Errorf("failed to build YTD context: %w", err)
	}
	defer rows.Close()

	ytdAmount := make(map[string]float64)

	for rows.Next() {
		var code string
		var emp float64
		var emr float64

		if err := rows.Scan(&code, &emp, &emr); err != nil {
			return nil, err
		}

		ytdAmount[code] = emp
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &models.StatutoryYTDContext{
		FinancialYearStart: financialYearStart,
		YTDStatutoryBase:   map[string]float64{}, // fill later if needed
		YTDStatutoryAmount: ytdAmount,
	}, nil
}

// ---------------------------------------------------------------------
// Payroll Run (continued)
// ---------------------------------------------------------------------

func (r *payrollRepository) GetPayrollRunByPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*models.PayrollRun, error) {

	query := `
		SELECT
			payroll_run_id,
			company_id,
			period_start,
			period_end,
			status,
			total_employees,
			processed_count,
			failed_count,
			last_processed_at,
			created_at,
			created_by
		FROM payroll.payroll_run
		WHERE company_id = $1
		  AND period_start = $2
		  AND period_end = $3
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, startDate, endDate)

	var run models.PayrollRun
	err := row.Scan(
		&run.PayrollRunID,
		&run.CompanyID,
		&run.PeriodStart,
		&run.PeriodEnd,
		&run.Status,
		&run.TotalEmployees,
		&run.ProcessedCount,
		&run.FailedCount,
		&run.LastProcessedAt,
		&run.CreatedAt,
		&run.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get payroll run by period",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll run by period: %w", err)
	}

	return &run, nil
}

func (r *payrollRepository) GetPayrollRunByPeriodTx(
	ctx context.Context,
	tx *sql.Tx,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*models.PayrollRun, error) {

	query := `
		SELECT
			payroll_run_id,
			company_id,
			period_start,
			period_end,
			status,
			total_employees,
			processed_count,
			failed_count,
			last_processed_at,
			created_at,
			created_by
		FROM payroll.payroll_run
		WHERE company_id = $1
		  AND period_start = $2
		  AND period_end = $3
		FOR UPDATE
	`

	row := tx.QueryRowContext(ctx, query, companyID, startDate, endDate)

	var run models.PayrollRun
	err := row.Scan(
		&run.PayrollRunID,
		&run.CompanyID,
		&run.PeriodStart,
		&run.PeriodEnd,
		&run.Status,
		&run.TotalEmployees,
		&run.ProcessedCount,
		&run.FailedCount,
		&run.LastProcessedAt,
		&run.CreatedAt,
		&run.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get payroll run by period (tx): %w", err)
	}

	return &run, nil
}

func (r *payrollRepository) DeletePayrollPeriodLockTx(
	ctx context.Context,
	tx *sql.Tx,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) error {

	query := `
		DELETE FROM payroll.payroll_period_lock
		WHERE company_id = $1
		  AND period_start = $2
		  AND period_end = $3
	`

	result, err := tx.ExecContext(ctx, query, companyID, periodStart, periodEnd)
	if err != nil {
		return fmt.Errorf("failed to delete payroll period lock (tx): %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payroll period lock not found")
	}

	return nil
}

// ---------------------------------------------------------------------
// Employee Payroll History (including superseded items for full history)
// ---------------------------------------------------------------------

// GetEmployeePayrollHistory now includes global components
func (r *payrollRepository) GetEmployeePayrollHistory(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	from, to time.Time,
) ([]*models.PayrollItemDetail, error) {
	// Include all items (superseded and active) for history.
	query := `
        SELECT
            pi.payroll_item_id,
            pi.payroll_run_id,
            pi.user_id,
            pi.payable_days,
            pi.unpaid_days,
            pi.gross_amount,
            pi.net_amount,
            pi.version_number,
            pi.is_superseded,
            pi.superseded_at,
            pi.superseded_by,
            pi.created_at,
            u.username,
            u.full_name,
            ce.employee_id,
            p.title,
            d.department_name
        FROM payroll.payroll_item pi
        JOIN payroll.payroll_run pr ON pr.payroll_run_id = pi.payroll_run_id
        JOIN users u ON u.user_id = pi.user_id
        JOIN company_employees ce
            ON ce.user_id = pi.user_id AND ce.company_id = pr.company_id
        LEFT JOIN positions p ON ce.position_id = p.position_id
        LEFT JOIN departments d ON p.department_id = d.department_id
        WHERE pr.company_id = $1
          AND pi.user_id = $2
          AND pr.period_start >= $3
          AND pr.period_end <= $4
        ORDER BY pr.period_start, pi.version_number
    `
	rows, err := r.client.Query(ctx, query, companyID, userID, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to get payroll history: %w", err)
	}
	defer rows.Close()

	// Map itemID -> detail
	itemMap := make(map[uuid.UUID]*models.PayrollItemDetail)
	var itemIDs []uuid.UUID

	for rows.Next() {
		var d models.PayrollItemDetail
		err := rows.Scan(
			&d.PayrollItemID,
			&d.PayrollRunID,
			&d.UserID,
			&d.PayableDays,
			&d.UnpaidDays,
			&d.GrossAmount,
			&d.NetAmount,
			&d.VersionNumber,
			&d.IsSuperseded,
			&d.SupersededAt,
			&d.SupersededBy,
			&d.CreatedAt,
			&d.Username,
			&d.FullName,
			&d.EmployeeID,
			&d.PositionTitle,
			&d.DepartmentName,
		)
		if err != nil {
			return nil, err
		}
		itemMap[d.PayrollItemID] = &d
		itemIDs = append(itemIDs, d.PayrollItemID)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	if len(itemIDs) == 0 {
		return []*models.PayrollItemDetail{}, nil
	}

	// Fetch ledger entries for all items, joining with payroll_component via company_id, including global components
	ledgerQuery := `
        SELECT
            pl.payroll_item_id,
            pl.component_code,
            pl.amount,
            pc.component_type,
            pc.description,
            pc.is_taxable
        FROM payroll.payroll_ledger pl
        JOIN payroll.payroll_item pi ON pl.payroll_item_id = pi.payroll_item_id
        JOIN payroll.payroll_run pr ON pi.payroll_run_id = pr.payroll_run_id
        JOIN payroll.payroll_component pc 
            ON pl.component_code = pc.component_code 
            AND (pc.company_id = pr.company_id OR pc.company_id IS NULL)
        WHERE pl.payroll_item_id = ANY($1)
        ORDER BY pl.payroll_item_id
    `
	ledgerRows, err := r.client.Query(ctx, ledgerQuery, itemIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get ledger entries: %w", err)
	}
	defer ledgerRows.Close()

	for ledgerRows.Next() {
		var itemID uuid.UUID
		var ledgerItem models.PayrollLedgerItem
		if err := ledgerRows.Scan(
			&itemID,
			&ledgerItem.ComponentCode,
			&ledgerItem.Amount,
			&ledgerItem.ComponentType,
			&ledgerItem.Description,
			&ledgerItem.IsTaxable,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ledger entry: %w", err)
		}
		if detail, ok := itemMap[itemID]; ok {
			detail.Components = append(detail.Components, ledgerItem)
		}
	}
	if err = ledgerRows.Err(); err != nil {
		return nil, err
	}

	// Rebuild ordered result
	result := make([]*models.PayrollItemDetail, 0, len(itemIDs))
	for _, id := range itemIDs {
		result = append(result, itemMap[id])
	}
	return result, nil
}

// ---------------------------------------------------------------------
// YTD and Trend Queries (filter superseded)
// ---------------------------------------------------------------------

// GetEmployeeYTDSummary now includes global components
func (r *payrollRepository) GetEmployeeYTDSummary(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	financialYearStart time.Time,
	asOf time.Time,
) (*models.EmployeeYTDSummary, error) {
	// 1. Gross, Net, Deductions (only active items)
	query := `
        SELECT
            COALESCE(SUM(pi.gross_amount),0),
            COALESCE(SUM(pi.net_amount),0),
            COALESCE(SUM(pi.gross_amount - pi.net_amount),0)
        FROM payroll.payroll_item pi
        JOIN payroll.payroll_run pr ON pr.payroll_run_id = pi.payroll_run_id
        WHERE pr.company_id = $1
          AND pi.user_id = $2
          AND pr.period_start >= $3
          AND pr.period_end <= $4
          AND pi.is_superseded = FALSE
    `
	var gross, net, deductions float64
	err := r.client.QueryRow(ctx, query,
		companyID, userID, financialYearStart, asOf,
	).Scan(&gross, &net, &deductions)
	if err != nil {
		return nil, err
	}

	// 2. Component breakdown with contribution_side (only active items), including global components
	componentQuery := `
        SELECT
            pl.component_code,
            pc.component_type,
            pc.description,
            COALESCE(SUM(pl.amount),0),
            pc.is_taxable,
            pc.contribution_side
        FROM payroll.payroll_ledger pl
        JOIN payroll.payroll_item pi ON pl.payroll_item_id = pi.payroll_item_id
        JOIN payroll.payroll_run pr ON pi.payroll_run_id = pr.payroll_run_id
        JOIN payroll.payroll_component pc 
            ON pl.component_code = pc.component_code 
            AND (pc.company_id = pr.company_id OR pc.company_id IS NULL)
        WHERE pr.company_id = $1
          AND pi.user_id = $2
          AND pr.period_start >= $3
          AND pr.period_end <= $4
          AND pi.is_superseded = FALSE
        GROUP BY pl.component_code, pc.component_type, pc.description, pc.is_taxable, pc.contribution_side
    `
	rows, err := r.client.Query(ctx, componentQuery,
		companyID, userID, financialYearStart, asOf,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var breakdown []models.LedgerSummary
	var totalTax, totalEmployer float64

	for rows.Next() {
		var l models.LedgerSummary
		if err := rows.Scan(
			&l.ComponentCode,
			&l.ComponentType,
			&l.Description,
			&l.TotalAmount,
			&l.IsTaxable,
			&l.ContributionSide,
		); err != nil {
			return nil, err
		}
		breakdown = append(breakdown, l)

		// Accumulate tax (component_type = deduction AND code in tax list)
		if l.ComponentType == models.ComponentTypeDeduction &&
			(l.ComponentCode == "TDS" || l.ComponentCode == "TAX") { // adjust to your tax codes
			totalTax += l.TotalAmount
		}

		// Accumulate employer contributions
		if l.ContributionSide == models.ContributionSideEmployer {
			totalEmployer += l.TotalAmount
		}
	}

	return &models.EmployeeYTDSummary{
		UserID:             userID,
		TotalGross:         gross,
		TotalNet:           net,
		TotalDeductions:    deductions,
		TotalTax:           totalTax,
		TotalEmployer:      totalEmployer,
		ComponentBreakdown: breakdown,
	}, nil
}

func (r *payrollRepository) GetPayrollTrend(
	ctx context.Context,
	companyID uuid.UUID,
	from, to time.Time,
) ([]*models.PayrollTrendPoint, error) {

	query := `
		SELECT
			pr.period_start,
			pr.period_end,
			COALESCE(SUM(pi.gross_amount),0),
			COALESCE(SUM(pi.net_amount),0)
		FROM payroll.payroll_run pr
		LEFT JOIN payroll.payroll_item pi 
			ON pr.payroll_run_id = pi.payroll_run_id
			AND pi.is_superseded = FALSE
		WHERE pr.company_id = $1
		  AND pr.period_start >= $2
		  AND pr.period_end <= $3
		GROUP BY pr.period_start, pr.period_end
		ORDER BY pr.period_start
	`

	rows, err := r.client.Query(ctx, query, companyID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*models.PayrollTrendPoint

	for rows.Next() {
		var t models.PayrollTrendPoint
		err := rows.Scan(
			&t.PeriodStart,
			&t.PeriodEnd,
			&t.TotalGross,
			&t.TotalNet,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, &t)
	}

	return result, nil
}

// GetComponentTrend now includes global components
func (r *payrollRepository) GetComponentTrend(
	ctx context.Context,
	companyID uuid.UUID,
	componentCode string,
	from, to time.Time,
) ([]*models.ComponentTrendPoint, error) {

	query := `
		SELECT
			pr.period_start,
			pl.component_code,
			COALESCE(SUM(pl.amount),0)
		FROM payroll.payroll_ledger pl
		JOIN payroll.payroll_item pi ON pl.payroll_item_id = pi.payroll_item_id
		JOIN payroll.payroll_run pr ON pi.payroll_run_id = pr.payroll_run_id
		JOIN payroll.payroll_component pc 
			ON pl.component_code = pc.component_code 
			AND (pc.company_id = pr.company_id OR pc.company_id IS NULL)
		WHERE pr.company_id = $1
		  AND pl.component_code = $2
		  AND pr.period_start >= $3
		  AND pr.period_end <= $4
		  AND pi.is_superseded = FALSE
		GROUP BY pr.period_start, pl.component_code
		ORDER BY pr.period_start
	`

	rows, err := r.client.Query(ctx, query,
		companyID, componentCode, from, to,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*models.ComponentTrendPoint

	for rows.Next() {
		var t models.ComponentTrendPoint
		err := rows.Scan(
			&t.PeriodStart,
			&t.ComponentCode,
			&t.TotalAmount,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, &t)
	}

	return result, nil
}

func (r *payrollRepository) GetRunStatutorySummary(
	ctx context.Context,
	runID uuid.UUID,
) ([]*models.StatutoryAggregate, error) {

	query := `
	SELECT
	    esc.statutory_code,
	    COALESCE(SUM(esc.employee_amount),0),
	    COALESCE(SUM(esc.employer_amount),0),
	    COALESCE(SUM(esc.total_amount),0)
	FROM payroll.employee_statutory_contribution esc
	JOIN payroll.payroll_item pi
	    ON esc.payroll_item_id = pi.payroll_item_id
	WHERE pi.payroll_run_id = $1
	GROUP BY esc.statutory_code
	ORDER BY esc.statutory_code
	`

	rows, err := r.client.Query(ctx, query, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*models.StatutoryAggregate

	for rows.Next() {
		var s models.StatutoryAggregate

		err := rows.Scan(
			&s.StatutoryCode,
			&s.EmployeeTotal,
			&s.EmployerTotal,
			&s.CombinedTotal,
		)
		if err != nil {
			return nil, err
		}

		result = append(result, &s)
	}

	return result, nil
}

// ---------------------------------------------------------------------
// Payroll Adjustments
// ---------------------------------------------------------------------

func (r *payrollRepository) CreatePayrollAdjustment(
	ctx context.Context,
	adjustment *models.PayrollAdjustment,
) error {

	query := `
		INSERT INTO payroll.payroll_adjustment (
			adjustment_id,
			company_id,
			user_id,
			component_code,
			amount,
			adjustment_type,
			reason,
			applicable_month,
			created_at,
			created_by
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`

	if adjustment.AdjustmentID == uuid.Nil {
		adjustment.AdjustmentID = uuid.New()
	}
	if adjustment.CreatedAt.IsZero() {
		adjustment.CreatedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		adjustment.AdjustmentID,
		adjustment.CompanyID,
		adjustment.UserID,
		adjustment.ComponentCode,
		adjustment.Amount,
		adjustment.AdjustmentType,
		adjustment.Reason,
		adjustment.ApplicableMonth,
		adjustment.CreatedAt,
		adjustment.CreatedBy,
	)

	if err != nil {
		r.logger.Error("Failed to create payroll adjustment",
			util.String("company_id", adjustment.CompanyID.String()),
			util.String("user_id", adjustment.UserID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create payroll adjustment: %w", err)
	}

	return nil
}

func (r *payrollRepository) UpdatePayrollAdjustment(
	ctx context.Context,
	adjustment *models.PayrollAdjustment,
) error {

	query := `
		UPDATE payroll.payroll_adjustment
		SET amount = $1,
			reason = $2
		WHERE adjustment_id = $3
	`

	result, err := r.client.Exec(ctx, query,
		adjustment.Amount,
		adjustment.Reason,
		adjustment.AdjustmentID,
	)
	if err != nil {
		return fmt.Errorf("failed to update payroll adjustment: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("adjustment not found")
	}

	return nil
}

func (r *payrollRepository) DeletePayrollAdjustment(
	ctx context.Context,
	adjustmentID uuid.UUID,
) error {

	query := `
		DELETE FROM payroll.payroll_adjustment
		WHERE adjustment_id = $1
	`

	result, err := r.client.Exec(ctx, query, adjustmentID)
	if err != nil {
		return fmt.Errorf("failed to delete payroll adjustment: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("adjustment not found")
	}

	return nil
}

func (r *payrollRepository) GetPayrollAdjustmentByID(
	ctx context.Context,
	adjustmentID uuid.UUID,
) (*models.PayrollAdjustment, error) {

	query := `
		SELECT
			adjustment_id,
			company_id,
			user_id,
			component_code,
			amount,
			adjustment_type,
			reason,
			applicable_month,
			created_at,
			created_by
		FROM payroll.payroll_adjustment
		WHERE adjustment_id = $1
	`

	row := r.client.QueryRow(ctx, query, adjustmentID)

	var a models.PayrollAdjustment

	err := row.Scan(
		&a.AdjustmentID,
		&a.CompanyID,
		&a.UserID,
		&a.ComponentCode,
		&a.Amount,
		&a.AdjustmentType,
		&a.Reason,
		&a.ApplicableMonth,
		&a.CreatedAt,
		&a.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get payroll adjustment: %w", err)
	}

	return &a, nil
}

func (r *payrollRepository) ListPayrollAdjustments(
	ctx context.Context,
	filter models.PayrollAdjustmentFilter,
) ([]*models.PayrollAdjustment, int64, error) {

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

	if filter.ComponentCode != nil {
		conditions = append(conditions, fmt.Sprintf("component_code = $%d", argIdx))
		args = append(args, *filter.ComponentCode)
		argIdx++
	}

	if filter.AdjustmentType != nil {
		conditions = append(conditions, fmt.Sprintf("adjustment_type = $%d", argIdx))
		args = append(args, *filter.AdjustmentType)
		argIdx++
	}

	if filter.FromMonth != nil {
		conditions = append(conditions, fmt.Sprintf("applicable_month >= $%d", argIdx))
		args = append(args, *filter.FromMonth)
		argIdx++
	}

	if filter.ToMonth != nil {
		conditions = append(conditions, fmt.Sprintf("applicable_month <= $%d", argIdx))
		args = append(args, *filter.ToMonth)
		argIdx++
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")

	// Count
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM payroll.payroll_adjustment
		%s
	`, whereClause)

	var total int64
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count payroll adjustments: %w", err)
	}

	offset := (filter.Page - 1) * filter.PageSize

	query := fmt.Sprintf(`
		SELECT
			adjustment_id,
			company_id,
			user_id,
			component_code,
			amount,
			adjustment_type,
			reason,
			applicable_month,
			created_at,
			created_by
		FROM payroll.payroll_adjustment
		%s
		ORDER BY applicable_month DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, filter.PageSize, offset)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list payroll adjustments: %w", err)
	}
	defer rows.Close()

	var result []*models.PayrollAdjustment

	for rows.Next() {
		var a models.PayrollAdjustment
		if err := rows.Scan(
			&a.AdjustmentID,
			&a.CompanyID,
			&a.UserID,
			&a.ComponentCode,
			&a.Amount,
			&a.AdjustmentType,
			&a.Reason,
			&a.ApplicableMonth,
			&a.CreatedAt,
			&a.CreatedBy,
		); err != nil {
			return nil, 0, err
		}
		result = append(result, &a)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return result, total, nil
}

// ---------------------------------------------------------------------
// Payroll Run State Transitions
// ---------------------------------------------------------------------

func (r *payrollRepository) GetPayrollRunForUpdate(
	ctx context.Context,
	runID uuid.UUID,
) (*models.PayrollRun, error) {

	query := `
        SELECT payroll_run_id, company_id, period_start, period_end,
               status, total_employees, processed_count, failed_count,
               last_processed_at, created_at, created_by
        FROM payroll.payroll_run
        WHERE payroll_run_id = $1
        FOR UPDATE
    `

	row := r.client.QueryRow(ctx, query, runID)

	var run models.PayrollRun
	err := row.Scan(
		&run.PayrollRunID,
		&run.CompanyID,
		&run.PeriodStart,
		&run.PeriodEnd,
		&run.Status,
		&run.TotalEmployees,
		&run.ProcessedCount,
		&run.FailedCount,
		&run.LastProcessedAt,
		&run.CreatedAt,
		&run.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to lock payroll run",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to lock payroll run: %w", err)
	}

	return &run, nil
}

func (r *payrollRepository) MarkRunProcessing(
	ctx context.Context,
	runID uuid.UUID,
	totalEmployees int,
) error {

	query := `
        UPDATE payroll.payroll_run
        SET status = 'processing',
            total_employees = $1,
            processed_count = 0,
            failed_count = 0,
            last_processed_at = NOW()
        WHERE payroll_run_id = $2
          AND status = 'draft'
    `

	result, err := r.client.Exec(ctx, query, totalEmployees, runID)
	if err != nil {
		r.logger.Error("Failed to mark run as processing",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to mark run processing: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("invalid state transition to processing (must be draft)")
	}

	return nil
}

func (r *payrollRepository) UpdateRunProgress(
	ctx context.Context,
	runID uuid.UUID,
	processedInc int,
	failedInc int,
) error {

	query := `
        UPDATE payroll.payroll_run
        SET processed_count = processed_count + $1,
            failed_count    = failed_count + $2,
            last_processed_at = NOW()
        WHERE payroll_run_id = $3
          AND status IN ('processing','executing')
    `

	result, err := r.client.Exec(ctx, query, processedInc, failedInc, runID)
	if err != nil {
		r.logger.Error("Failed to update run progress",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update run progress: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("run not in processing or executing state")
	}

	return nil
}

func (r *payrollRepository) TransitionRunToExecutingTx(
	ctx context.Context,
	tx *sql.Tx,
	runID uuid.UUID,
) (bool, error) {

	query := `
		UPDATE payroll.payroll_run
		SET status = 'executing',
		    last_processed_at = NOW()
		WHERE payroll_run_id = $1
		  AND status = 'processing'
	`

	result, err := tx.ExecContext(ctx, query, runID)
	if err != nil {
		return false, fmt.Errorf("failed to transition run to executing: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	if rowsAffected == 0 {
		return false, nil
	}

	return true, nil
}

func (r *payrollRepository) TransitionRunToProcessing(
	ctx context.Context,
	runID uuid.UUID,
	totalEmployees int,
) (bool, error) {

	query := `
        UPDATE payroll.payroll_run
        SET status = 'processing',
            total_employees = $1,
            processed_count = 0,
            failed_count = 0,
            last_processed_at = NOW()
        WHERE payroll_run_id = $2
          AND status = 'draft'
    `

	result, err := r.client.Exec(ctx, query, totalEmployees, runID)
	if err != nil {
		return false, fmt.Errorf("failed to transition run to processing: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	if rowsAffected == 0 {
		return false, nil // not in draft
	}

	return true, nil
}

// ---------------------------------------------------------------------
// Adjustments (continued)
// ---------------------------------------------------------------------

func (r *payrollRepository) GetAdjustmentsForEmployee(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*models.PayrollAdjustment, error) {

	query := `
        SELECT adjustment_id, company_id, user_id,
               component_code, amount, adjustment_type,
               reason, applicable_month, created_at, created_by
        FROM payroll.payroll_adjustment
        WHERE company_id = $1
          AND user_id = $2
          AND applicable_month >= $3
          AND applicable_month <= $4
        ORDER BY applicable_month
    `

	rows, err := r.client.Query(ctx, query, companyID, userID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get payroll adjustments",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get adjustments: %w", err)
	}
	defer rows.Close()

	var adjustments []*models.PayrollAdjustment

	for rows.Next() {
		var a models.PayrollAdjustment

		err := rows.Scan(
			&a.AdjustmentID,
			&a.CompanyID,
			&a.UserID,
			&a.ComponentCode,
			&a.Amount,
			&a.AdjustmentType,
			&a.Reason,
			&a.ApplicableMonth,
			&a.CreatedAt,
			&a.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan adjustment: %w", err)
		}

		adjustments = append(adjustments, &a)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return adjustments, nil
}

// ---------------------------------------------------------------------
// AttendanceRepository Implementation (for CompensationService)
// ---------------------------------------------------------------------

func (r *payrollRepository) GetPayableDaysInRange(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (float64, error) {

	totalDays, payableDays, err := r.GetPayrollAttendanceDays(
		ctx,
		companyID,
		userID,
		startDate,
		endDate,
	)
	if err != nil {
		r.logger.Error("Failed to fetch payable days in range",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("start_date", startDate.Format("2006-01-02")),
			util.String("end_date", endDate.Format("2006-01-02")),
			util.ErrorField(err),
		)
		return 0, fmt.Errorf("failed to get payable days: %w", err)
	}

	// Enterprise safety: payable days cannot exceed total days
	if payableDays > totalDays {
		return 0, fmt.Errorf(
			"data integrity error: payable_days (%.2f) exceeds total_days (%.2f)",
			payableDays,
			totalDays,
		)
	}

	return payableDays, nil
}

func (r *payrollRepository) CleanupFailedRun(
	ctx context.Context,
	runID uuid.UUID,
) error {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin cleanup tx: %w", err)
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// 1️⃣ Delete ledger entries
	_, err = tx.ExecContext(ctx, `
        DELETE FROM payroll.payroll_ledger
        WHERE payroll_item_id IN (
            SELECT payroll_item_id
            FROM payroll.payroll_item
            WHERE payroll_run_id = $1
        )
    `, runID)
	if err != nil {
		return fmt.Errorf("failed to delete ledger entries: %w", err)
	}

	// 2️⃣ Delete payroll items
	_, err = tx.ExecContext(ctx, `
        DELETE FROM payroll.payroll_item
        WHERE payroll_run_id = $1
    `, runID)
	if err != nil {
		return fmt.Errorf("failed to delete payroll items: %w", err)
	}

	// 3️⃣ Delete snapshots
	_, err = tx.ExecContext(ctx, `
        DELETE FROM payroll.payroll_snapshot
        WHERE payroll_run_id = $1
    `, runID)
	if err != nil {
		return fmt.Errorf("failed to delete snapshots: %w", err)
	}

	// 4️⃣ Reset run counters
	_, err = tx.ExecContext(ctx, `
        UPDATE payroll.payroll_run
        SET processed_count = 0,
            failed_count = 0,
            last_processed_at = NULL
        WHERE payroll_run_id = $1
    `, runID)
	if err != nil {
		return fmt.Errorf("failed to reset run counters: %w", err)
	}

	return tx.Commit()
}
func (r *payrollRepository) CleanupFailedRunTx(
	ctx context.Context,
	tx *sql.Tx,
	runID uuid.UUID,
) error {

	var currentStatus string
	err := tx.QueryRowContext(ctx, `
		SELECT status
		FROM payroll.payroll_run
		WHERE payroll_run_id = $1
		FOR UPDATE
	`, runID).Scan(&currentStatus)
	if err != nil {
		return fmt.Errorf("failed to fetch run status: %w", err)
	}

	if currentStatus != "failed" {
		return fmt.Errorf("cleanup allowed only for failed runs")
	}

	// Delete ledger entries
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM payroll.payroll_ledger
		WHERE payroll_item_id IN (
			SELECT payroll_item_id
			FROM payroll.payroll_item
			WHERE payroll_run_id = $1
		)
	`, runID); err != nil {
		return fmt.Errorf("failed to delete ledger entries: %w", err)
	}

	// Delete payroll items
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM payroll.payroll_item
		WHERE payroll_run_id = $1
	`, runID); err != nil {
		return fmt.Errorf("failed to delete payroll items: %w", err)
	}

	// Delete snapshots
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM payroll.payroll_snapshot
		WHERE payroll_run_id = $1
	`, runID); err != nil {
		return fmt.Errorf("failed to delete snapshots: %w", err)
	}

	// Reset counters
	if _, err := tx.ExecContext(ctx, `
		UPDATE payroll.payroll_run
		SET processed_count = 0,
		    failed_count = 0,
		    last_processed_at = NULL
		WHERE payroll_run_id = $1
	`, runID); err != nil {
		return fmt.Errorf("failed to reset counters: %w", err)
	}

	return nil
}

func (r *payrollRepository) UpdatePayrollRunStatusIfCurrentTx(
	ctx context.Context,
	tx *sql.Tx,
	runID uuid.UUID,
	fromStatus string,
	toStatus string,
) (bool, error) {

	result, err := tx.ExecContext(ctx, `
		UPDATE payroll.payroll_run
		SET status = $2
		WHERE payroll_run_id = $1
		  AND status = $3
	`, runID, toStatus, fromStatus)
	if err != nil {
		return false, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rows > 0, nil
}

func (r *payrollRepository) UpdatePayrollRunStatusIfCurrent(
	ctx context.Context,
	runID uuid.UUID,
	fromStatus string,
	toStatus string,
) error {

	result, err := r.client.Exec(ctx, `
		UPDATE payroll.payroll_run
		SET status = $2
		WHERE payroll_run_id = $1
		  AND status = $3
	`, runID, toStatus, fromStatus)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return fmt.Errorf(
			"invalid state transition from %s to %s",
			fromStatus,
			toStatus,
		)
	}

	return nil
}
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
func (r *payrollRepository) CountIncompleteEmployeeJobs(
	ctx context.Context,
	runID uuid.UUID,
) (int, error) {

	query := `
		SELECT COUNT(*)
		FROM payroll.payroll_employee_job
		WHERE payroll_run_id = $1
		  AND status IN ('pending','processing')
	`

	var count int

	err := r.client.QueryRow(ctx, query, runID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count incomplete employee jobs: %w", err)
	}

	return count, nil
}

func (r *payrollRepository) GetPayrollRunTx(
	ctx context.Context,
	tx *sql.Tx,
	runID uuid.UUID,
) (*models.PayrollRun, error) {

	query := `
        SELECT payroll_run_id, company_id, period_start, period_end,
               status, total_employees, processed_count, failed_count,
               last_processed_at, created_at, created_by
        FROM payroll.payroll_run
        WHERE payroll_run_id = $1
    `

	row := tx.QueryRowContext(ctx, query, runID)

	var run models.PayrollRun

	err := row.Scan(
		&run.PayrollRunID,
		&run.CompanyID,
		&run.PeriodStart,
		&run.PeriodEnd,
		&run.Status,
		&run.TotalEmployees,
		&run.ProcessedCount,
		&run.FailedCount,
		&run.LastProcessedAt,
		&run.CreatedAt,
		&run.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get payroll run: %w", err)
	}

	return &run, nil
}

// RecalculatePayrollItemNet updates the net_amount of a payroll item
// by subtracting all deduction-type ledger entries from gross_amount.
func (r *payrollRepository) RecalculatePayrollItemNet(
	ctx context.Context,
	itemID uuid.UUID,
) error {
	query := `
		UPDATE payroll.payroll_item pi
		SET net_amount = pi.gross_amount - COALESCE((
			SELECT SUM(pl.amount)
			FROM payroll.payroll_ledger pl
			JOIN payroll.payroll_component pc
				ON pc.component_code = pl.component_code
			WHERE pl.payroll_item_id = pi.payroll_item_id
			  AND pc.component_type = 'deduction'
		), 0)
		WHERE pi.payroll_item_id = $1
	`

	_, err := r.client.Exec(ctx, query, itemID)
	if err != nil {
		r.logger.Error("Failed to recalculate payroll item net",
			zap.String("item_id", itemID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to recalculate payroll net: %w", err)
	}
	return nil
}

func (r *payrollRepository) GetPayrollRunExecutionStatus(
	ctx context.Context,
	runID uuid.UUID,
) (*models.PayrollRun, error) {

	query := `
	SELECT
	    payroll_run_id,
	    company_id,
	    status,
	    total_employees,
	    processed_count,
	    failed_count,
	    last_processed_at
	FROM payroll.payroll_run
	WHERE payroll_run_id = $1
	`

	row := r.client.QueryRow(ctx, query, runID)

	var run models.PayrollRun

	err := row.Scan(
		&run.PayrollRunID,
		&run.CompanyID,
		&run.Status,
		&run.TotalEmployees,
		&run.ProcessedCount,
		&run.FailedCount,
		&run.LastProcessedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		r.logger.Error("Failed to get payroll run execution status",
			util.String("run_id", runID.String()),
			util.ErrorField(err),
		)

		return nil, fmt.Errorf("failed to fetch payroll run execution status: %w", err)
	}

	return &run, nil
}

// ResetPayrollRunDataTx deletes all employee jobs, payroll items, ledger entries,
// and snapshots for a given run, and resets its counters.
func (r *payrollRepository) ResetPayrollRunDataTx(
	ctx context.Context,
	tx *sql.Tx,
	runID uuid.UUID,
) error {

	// Delete employee jobs
	if _, err := tx.ExecContext(ctx, `
        DELETE FROM payroll.payroll_employee_job
        WHERE payroll_run_id = $1
    `, runID); err != nil {
		return fmt.Errorf("failed to delete employee jobs: %w", err)
	}

	// Delete ledger entries (via payroll items)
	if _, err := tx.ExecContext(ctx, `
        DELETE FROM payroll.payroll_ledger
        WHERE payroll_item_id IN (
            SELECT payroll_item_id
            FROM payroll.payroll_item
            WHERE payroll_run_id = $1
        )
    `, runID); err != nil {
		return fmt.Errorf("failed to delete ledger entries: %w", err)
	}

	// Delete payroll items
	if _, err := tx.ExecContext(ctx, `
        DELETE FROM payroll.payroll_item
        WHERE payroll_run_id = $1
    `, runID); err != nil {
		return fmt.Errorf("failed to delete payroll items: %w", err)
	}

	// Delete snapshots
	if _, err := tx.ExecContext(ctx, `
        DELETE FROM payroll.payroll_snapshot
        WHERE payroll_run_id = $1
    `, runID); err != nil {
		return fmt.Errorf("failed to delete snapshots: %w", err)
	}

	// Reset run counters
	if _, err := tx.ExecContext(ctx, `
        UPDATE payroll.payroll_run
        SET total_employees = NULL,
            processed_count = 0,
            failed_count = 0,
            last_processed_at = NULL
        WHERE payroll_run_id = $1
    `, runID); err != nil {
		return fmt.Errorf("failed to reset run counters: %w", err)
	}

	return nil
}
