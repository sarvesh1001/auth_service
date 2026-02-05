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
        SELECT * FROM payroll.payroll_run 
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

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM payroll.payroll_run %s", whereClause)
	var total int64
	row := r.client.QueryRow(ctx, countQuery, args...)
	if err := row.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count payroll runs: %w", err)
	}

	// Get paginated results
	offset := (filter.Page - 1) * filter.PageSize
	query := fmt.Sprintf(`
        SELECT * FROM payroll.payroll_run 
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

func (r *payrollRepository) DeletePayrollRun(ctx context.Context, runID uuid.UUID) error {
	query := `
        DELETE FROM payroll.payroll_run 
        WHERE payroll_run_id = $1
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
		return fmt.Errorf("payroll run not found")
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
        LEFT JOIN payroll.payroll_item pi ON pr.payroll_run_id = pi.payroll_run_id
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

func (r *payrollRepository) CreatePayrollItem(ctx context.Context, item *models.PayrollItem) error {
	query := `
        INSERT INTO payroll.payroll_item (
            payroll_item_id, payroll_run_id, user_id, payable_days, 
            unpaid_days, gross_amount, net_amount, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `

	if item.PayrollItemID == uuid.Nil {
		item.PayrollItemID = uuid.New()
	}
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
		item.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create payroll item",
			util.String("run_id", item.PayrollRunID.String()),
			util.String("user_id", item.UserID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create payroll item: %w", err)
	}

	return nil
}

func (r *payrollRepository) GetPayrollItemByID(ctx context.Context, itemID uuid.UUID) (*models.PayrollItem, error) {
	query := `
        SELECT * FROM payroll.payroll_item 
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
        SELECT * FROM payroll.payroll_item 
        WHERE payroll_run_id = $1
        ORDER BY created_at
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

func (r *payrollRepository) GetPayrollItemDetail(ctx context.Context, itemID uuid.UUID) (*models.PayrollItemDetail, error) {
	query := `
        SELECT 
            pi.*,
            u.username,
            u.full_name,
            ce.employee_id,
            p.title as position_title,
            d.department_name
        FROM payroll.payroll_item pi
        JOIN users u ON pi.user_id = u.user_id
        JOIN company_employees ce ON pi.user_id = ce.user_id 
            AND ce.company_id = (SELECT company_id FROM payroll.payroll_run WHERE payroll_run_id = pi.payroll_run_id)
        LEFT JOIN positions p ON ce.position_id = p.position_id
        LEFT JOIN departments d ON p.department_id = d.department_id
        WHERE pi.payroll_item_id = $1
    `

	row := r.client.QueryRow(ctx, query, itemID)
	var detail models.PayrollItemDetail
	err := row.Scan(
		&detail.PayrollItemID,
		&detail.PayrollRunID,
		&detail.UserID,
		&detail.PayableDays,
		&detail.UnpaidDays,
		&detail.GrossAmount,
		&detail.NetAmount,
		&detail.CreatedAt,
		&detail.Username,
		&detail.FullName,
		&detail.EmployeeID,
		&detail.PositionTitle,
		&detail.DepartmentName,
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

	// Get ledger entries
	ledgerQuery := `
        SELECT 
            pl.component_code,
            pc.component_type,
            pc.description,
            pl.amount,
            pc.is_taxable
        FROM payroll.payroll_ledger pl
        JOIN payroll.payroll_component pc ON pl.component_code = pc.component_code
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

	return &detail, nil
}

func (r *payrollRepository) DeletePayrollItem(ctx context.Context, itemID uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Delete ledger entries first
	_, err = tx.ExecContext(ctx, "DELETE FROM payroll.payroll_ledger WHERE payroll_item_id = $1", itemID)
	if err != nil {
		return fmt.Errorf("failed to delete ledger entries: %w", err)
	}

	// Delete payroll item
	result, err := tx.ExecContext(ctx, "DELETE FROM payroll.payroll_item WHERE payroll_item_id = $1", itemID)
	if err != nil {
		return fmt.Errorf("failed to delete payroll item: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payroll item not found")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *payrollRepository) BulkCreatePayrollItems(ctx context.Context, items []*models.PayrollItem) error {
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
            payroll_item_id, payroll_run_id, user_id, payable_days, 
            unpaid_days, gross_amount, net_amount, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `

	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, item := range items {
		if item.PayrollItemID == uuid.Nil {
			item.PayrollItemID = uuid.New()
		}
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
			item.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert payroll item %s: %w", item.PayrollItemID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *payrollRepository) CreateComponent(ctx context.Context, component *models.PayrollComponent) error {
	query := `
        INSERT INTO payroll.payroll_component (
            component_code, component_type, description, 
            is_taxable, is_system, is_active
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (component_code) DO UPDATE SET
            component_type = EXCLUDED.component_type,
            description = EXCLUDED.description,
            is_taxable = EXCLUDED.is_taxable,
            is_active = EXCLUDED.is_active
    `

	_, err := r.client.Exec(ctx, query,
		component.ComponentCode,
		component.ComponentType,
		component.Description,
		component.IsTaxable,
		component.IsSystem,
		component.IsActive,
	)

	if err != nil {
		r.logger.Error("Failed to create payroll component",
			util.String("code", component.ComponentCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create payroll component: %w", err)
	}

	return nil
}

func (r *payrollRepository) GetComponent(ctx context.Context, code string) (*models.PayrollComponent, error) {
	query := `
        SELECT * FROM payroll.payroll_component 
        WHERE component_code = $1
    `

	row := r.client.QueryRow(ctx, query, code)
	var component models.PayrollComponent
	err := row.Scan(
		&component.ComponentCode,
		&component.ComponentType,
		&component.Description,
		&component.IsTaxable,
		&component.IsSystem,
		&component.IsActive,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get payroll component",
			util.String("code", code),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll component: %w", err)
	}

	return &component, nil
}

func (r *payrollRepository) GetComponents(ctx context.Context, filter models.ComponentFilter) ([]*models.PayrollComponent, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

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

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
        SELECT * FROM payroll.payroll_component 
        %s 
        ORDER BY component_code
    `, whereClause)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to get payroll components",
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get payroll components: %w", err)
	}
	defer rows.Close()

	var components []*models.PayrollComponent
	for rows.Next() {
		var component models.PayrollComponent
		if err := rows.Scan(
			&component.ComponentCode,
			&component.ComponentType,
			&component.Description,
			&component.IsTaxable,
			&component.IsSystem,
			&component.IsActive,
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
            is_active = $4
        WHERE component_code = $5
    `

	result, err := r.client.Exec(ctx, query,
		component.ComponentType,
		component.Description,
		component.IsTaxable,
		component.IsActive,
		component.ComponentCode,
	)

	if err != nil {
		r.logger.Error("Failed to update payroll component",
			util.String("code", component.ComponentCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to update payroll component: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payroll component not found")
	}

	return nil
}

func (r *payrollRepository) DeactivateComponent(ctx context.Context, code string) error {
	query := `
        UPDATE payroll.payroll_component 
        SET is_active = false 
        WHERE component_code = $1
    `

	result, err := r.client.Exec(ctx, query, code)
	if err != nil {
		r.logger.Error("Failed to deactivate payroll component",
			util.String("code", code),
			util.ErrorField(err))
		return fmt.Errorf("failed to deactivate payroll component: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payroll component not found")
	}

	return nil
}

func (r *payrollRepository) CreateLedgerEntry(ctx context.Context, entry *models.PayrollLedger) error {
	query := `
        INSERT INTO payroll.payroll_ledger (
            ledger_id, payroll_item_id, component_code, amount, created_at
        ) VALUES ($1, $2, $3, $4, $5)
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
		r.logger.Error("Failed to create payroll ledger entry",
			util.String("item_id", entry.PayrollItemID.String()),
			util.String("component", entry.ComponentCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create payroll ledger entry: %w", err)
	}

	return nil
}

func (r *payrollRepository) GetLedgerEntriesByItem(ctx context.Context, itemID uuid.UUID) ([]*models.PayrollLedger, error) {
	query := `
        SELECT * FROM payroll.payroll_ledger 
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

func (r *payrollRepository) GetLedgerSummaryByRun(ctx context.Context, runID uuid.UUID) ([]*models.LedgerSummary, error) {
	query := `
        SELECT 
            pl.component_code,
            pc.component_type,
            pc.description,
            SUM(pl.amount) as total_amount,
            pc.is_taxable
        FROM payroll.payroll_ledger pl
        JOIN payroll.payroll_component pc ON pl.component_code = pc.component_code
        JOIN payroll.payroll_item pi ON pl.payroll_item_id = pi.payroll_item_id
        WHERE pi.payroll_run_id = $1
        GROUP BY pl.component_code, pc.component_type, pc.description, pc.is_taxable
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
			return fmt.Errorf("failed to insert ledger entry %s: %w", entry.LedgerID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *payrollRepository) CreateTaxProfile(ctx context.Context, profile *models.TaxProfile) error {
	query := `
        INSERT INTO payroll.payroll_tax_profile (
            tax_profile_id, company_id, country_code, name, 
            is_active, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6)
    `

	if profile.TaxProfileID == uuid.Nil {
		profile.TaxProfileID = uuid.New()
	}
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		profile.TaxProfileID,
		profile.CompanyID,
		profile.CountryCode,
		profile.Name,
		profile.IsActive,
		profile.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create tax profile",
			util.String("company_id", profile.CompanyID.String()),
			util.String("country", profile.CountryCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create tax profile: %w", err)
	}

	return nil
}

func (r *payrollRepository) GetTaxProfile(ctx context.Context, profileID uuid.UUID) (*models.TaxProfile, error) {
	query := `
        SELECT * FROM payroll.payroll_tax_profile 
        WHERE tax_profile_id = $1
    `

	row := r.client.QueryRow(ctx, query, profileID)
	var profile models.TaxProfile
	err := row.Scan(
		&profile.TaxProfileID,
		&profile.CompanyID,
		&profile.CountryCode,
		&profile.Name,
		&profile.IsActive,
		&profile.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get tax profile",
			util.String("profile_id", profileID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get tax profile: %w", err)
	}

	return &profile, nil
}

func (r *payrollRepository) GetTaxProfiles(ctx context.Context, filter models.TaxProfileFilter) ([]*models.TaxProfile, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("company_id = $%d", argIdx))
	args = append(args, filter.CompanyID)
	argIdx++

	if filter.CountryCode != nil {
		conditions = append(conditions, fmt.Sprintf("country_code = $%d", argIdx))
		args = append(args, *filter.CountryCode)
		argIdx++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIdx))
		args = append(args, *filter.IsActive)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
        SELECT * FROM payroll.payroll_tax_profile 
        %s 
        ORDER BY created_at DESC
    `, whereClause)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to get tax profiles",
			util.String("company_id", filter.CompanyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get tax profiles: %w", err)
	}
	defer rows.Close()

	var profiles []*models.TaxProfile
	for rows.Next() {
		var profile models.TaxProfile
		if err := rows.Scan(
			&profile.TaxProfileID,
			&profile.CompanyID,
			&profile.CountryCode,
			&profile.Name,
			&profile.IsActive,
			&profile.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan tax profile: %w", err)
		}
		profiles = append(profiles, &profile)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return profiles, nil
}

func (r *payrollRepository) UpdateTaxProfile(ctx context.Context, profile *models.TaxProfile) error {
	query := `
        UPDATE payroll.payroll_tax_profile 
        SET country_code = $1,
            name = $2,
            is_active = $3
        WHERE tax_profile_id = $4
    `

	result, err := r.client.Exec(ctx, query,
		profile.CountryCode,
		profile.Name,
		profile.IsActive,
		profile.TaxProfileID,
	)

	if err != nil {
		r.logger.Error("Failed to update tax profile",
			util.String("profile_id", profile.TaxProfileID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update tax profile: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("tax profile not found")
	}

	return nil
}

func (r *payrollRepository) DeactivateTaxProfile(ctx context.Context, profileID uuid.UUID) error {
	query := `
        UPDATE payroll.payroll_tax_profile 
        SET is_active = false 
        WHERE tax_profile_id = $1
    `

	result, err := r.client.Exec(ctx, query, profileID)
	if err != nil {
		r.logger.Error("Failed to deactivate tax profile",
			util.String("profile_id", profileID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to deactivate tax profile: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("tax profile not found")
	}

	return nil
}

func (r *payrollRepository) CreateTaxRule(ctx context.Context, rule *models.TaxRule) error {
	query := `
        INSERT INTO payroll.payroll_tax_rule (
            tax_rule_id, tax_profile_id, component_code, calculation_type,
            value, formula, min_amount, max_amount, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `

	if rule.TaxRuleID == uuid.Nil {
		rule.TaxRuleID = uuid.New()
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		rule.TaxRuleID,
		rule.TaxProfileID,
		rule.ComponentCode,
		rule.CalculationType,
		rule.Value,
		rule.Formula,
		rule.MinAmount,
		rule.MaxAmount,
		rule.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create tax rule",
			util.String("profile_id", rule.TaxProfileID.String()),
			util.String("component", rule.ComponentCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create tax rule: %w", err)
	}

	return nil
}

func (r *payrollRepository) GetTaxRule(ctx context.Context, ruleID uuid.UUID) (*models.TaxRule, error) {
	query := `
        SELECT * FROM payroll.payroll_tax_rule 
        WHERE tax_rule_id = $1
    `

	row := r.client.QueryRow(ctx, query, ruleID)
	var rule models.TaxRule
	err := row.Scan(
		&rule.TaxRuleID,
		&rule.TaxProfileID,
		&rule.ComponentCode,
		&rule.CalculationType,
		&rule.Value,
		&rule.Formula,
		&rule.MinAmount,
		&rule.MaxAmount,
		&rule.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get tax rule",
			util.String("rule_id", ruleID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get tax rule: %w", err)
	}

	return &rule, nil
}

func (r *payrollRepository) GetTaxRulesByProfile(ctx context.Context, profileID uuid.UUID) ([]*models.TaxRule, error) {
	query := `
        SELECT * FROM payroll.payroll_tax_rule 
        WHERE tax_profile_id = $1
        ORDER BY created_at
    `

	rows, err := r.client.Query(ctx, query, profileID)
	if err != nil {
		r.logger.Error("Failed to get tax rules by profile",
			util.String("profile_id", profileID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get tax rules: %w", err)
	}
	defer rows.Close()

	var rules []*models.TaxRule
	for rows.Next() {
		var rule models.TaxRule
		if err := rows.Scan(
			&rule.TaxRuleID,
			&rule.TaxProfileID,
			&rule.ComponentCode,
			&rule.CalculationType,
			&rule.Value,
			&rule.Formula,
			&rule.MinAmount,
			&rule.MaxAmount,
			&rule.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan tax rule: %w", err)
		}
		rules = append(rules, &rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return rules, nil
}

func (r *payrollRepository) GetTaxRulesByComponent(ctx context.Context, companyID uuid.UUID, componentCode string) ([]*models.TaxRule, error) {
	query := `
        SELECT ptr.* 
        FROM payroll.payroll_tax_rule ptr
        JOIN payroll.payroll_tax_profile ptp ON ptr.tax_profile_id = ptp.tax_profile_id
        WHERE ptp.company_id = $1
          AND ptr.component_code = $2
          AND ptp.is_active = true
        ORDER BY ptr.created_at
    `

	rows, err := r.client.Query(ctx, query, companyID, componentCode)
	if err != nil {
		r.logger.Error("Failed to get tax rules by component",
			util.String("company_id", companyID.String()),
			util.String("component", componentCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get tax rules: %w", err)
	}
	defer rows.Close()

	var rules []*models.TaxRule
	for rows.Next() {
		var rule models.TaxRule
		if err := rows.Scan(
			&rule.TaxRuleID,
			&rule.TaxProfileID,
			&rule.ComponentCode,
			&rule.CalculationType,
			&rule.Value,
			&rule.Formula,
			&rule.MinAmount,
			&rule.MaxAmount,
			&rule.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan tax rule: %w", err)
		}
		rules = append(rules, &rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return rules, nil
}

func (r *payrollRepository) UpdateTaxRule(ctx context.Context, rule *models.TaxRule) error {
	query := `
        UPDATE payroll.payroll_tax_rule 
        SET component_code = $1,
            calculation_type = $2,
            value = $3,
            formula = $4,
            min_amount = $5,
            max_amount = $6
        WHERE tax_rule_id = $7
    `

	result, err := r.client.Exec(ctx, query,
		rule.ComponentCode,
		rule.CalculationType,
		rule.Value,
		rule.Formula,
		rule.MinAmount,
		rule.MaxAmount,
		rule.TaxRuleID,
	)

	if err != nil {
		r.logger.Error("Failed to update tax rule",
			util.String("rule_id", rule.TaxRuleID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update tax rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("tax rule not found")
	}

	return nil
}

func (r *payrollRepository) DeleteTaxRule(ctx context.Context, ruleID uuid.UUID) error {
	query := `
        DELETE FROM payroll.payroll_tax_rule 
        WHERE tax_rule_id = $1
    `

	result, err := r.client.Exec(ctx, query, ruleID)
	if err != nil {
		r.logger.Error("Failed to delete tax rule",
			util.String("rule_id", ruleID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete tax rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("tax rule not found")
	}

	return nil
}

func (r *payrollRepository) CreateSnapshot(ctx context.Context, snapshot *models.PayrollSnapshot) error {
	// Note: This is a custom table that needs to be added to the schema
	// We'll create it if it doesn't exist
	createTableQuery := `
        CREATE TABLE IF NOT EXISTS payroll.payroll_snapshot (
            snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            payroll_run_id UUID NOT NULL,
            company_id UUID NOT NULL,
            snapshot_type VARCHAR(20) NOT NULL,
            snapshot_data JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_by UUID NOT NULL,
            CONSTRAINT fk_snapshot_run FOREIGN KEY (payroll_run_id) 
                REFERENCES payroll.payroll_run(payroll_run_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_payroll_snapshot_run ON payroll.payroll_snapshot(payroll_run_id);
        CREATE INDEX IF NOT EXISTS idx_payroll_snapshot_company ON payroll.payroll_snapshot(company_id);
    `

	_, err := r.client.Exec(ctx, createTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create payroll snapshot table: %w", err)
	}

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

	_, err = r.client.Exec(ctx, query,
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
	// First ensure table exists
	_, err := r.client.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS payroll.payroll_snapshot (
            snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            payroll_run_id UUID NOT NULL,
            company_id UUID NOT NULL,
            snapshot_type VARCHAR(20) NOT NULL,
            snapshot_data JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_by UUID NOT NULL
        )
    `)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure payroll snapshot table exists: %w", err)
	}

	query := `
        SELECT * FROM payroll.payroll_snapshot 
        WHERE snapshot_id = $1
    `

	row := r.client.QueryRow(ctx, query, snapshotID)
	var snapshot models.PayrollSnapshot
	err = row.Scan(
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
	// First ensure table exists
	_, err := r.client.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS payroll.payroll_snapshot (
            snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            payroll_run_id UUID NOT NULL,
            company_id UUID NOT NULL,
            snapshot_type VARCHAR(20) NOT NULL,
            snapshot_data JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_by UUID NOT NULL
        )
    `)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure payroll snapshot table exists: %w", err)
	}

	query := `
        SELECT * FROM payroll.payroll_snapshot 
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

func (r *payrollRepository) LockPayrollPeriod(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) error {
	query := `
        UPDATE attendance_daily_summary 
        SET is_payroll_locked = true
        WHERE company_id = $1
          AND attendance_date BETWEEN $2 AND $3
    `

	_, err := r.client.Exec(ctx, query, companyID, periodStart, periodEnd)
	if err != nil {
		r.logger.Error("Failed to lock payroll period",
			util.String("company_id", companyID.String()),
			util.String("period", fmt.Sprintf("%s to %s",
				periodStart.Format("2006-01-02"),
				periodEnd.Format("2006-01-02"))),
			util.ErrorField(err))
		return fmt.Errorf("failed to lock payroll period: %w", err)
	}

	return nil
}

func (r *payrollRepository) UnlockPayrollPeriod(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) error {
	query := `
        UPDATE attendance_daily_summary 
        SET is_payroll_locked = false
        WHERE company_id = $1
          AND attendance_date BETWEEN $2 AND $3
    `

	_, err := r.client.Exec(ctx, query, companyID, periodStart, periodEnd)
	if err != nil {
		r.logger.Error("Failed to unlock payroll period",
			util.String("company_id", companyID.String()),
			util.String("period", fmt.Sprintf("%s to %s",
				periodStart.Format("2006-01-02"),
				periodEnd.Format("2006-01-02"))),
			util.ErrorField(err))
		return fmt.Errorf("failed to unlock payroll period: %w", err)
	}

	return nil
}

func (r *payrollRepository) IsPeriodLocked(ctx context.Context, companyID uuid.UUID, date time.Time) (bool, error) {
	query := `
        SELECT EXISTS(
            SELECT 1 FROM attendance_daily_summary 
            WHERE company_id = $1
              AND attendance_date = $2
              AND is_payroll_locked = true
        )
    `

	var locked bool
	row := r.client.QueryRow(ctx, query, companyID, date)
	err := row.Scan(&locked)
	if err != nil {
		r.logger.Error("Failed to check if period is locked",
			util.String("company_id", companyID.String()),
			util.String("date", date.Format("2006-01-02")),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check period lock: %w", err)
	}

	return locked, nil
}

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
          AND is_payroll_locked = false
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

func (r *payrollRepository) GetEmployeeIDsForPayroll(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) ([]uuid.UUID, error) {
	query := `
        SELECT DISTINCT ce.user_id
        FROM company_employees ce
        JOIN employee_profiles ep ON ce.user_id = ep.user_id AND ce.company_id = ep.company_id
        WHERE ce.company_id = $1
          AND ce.is_active = true
          AND ep.employment_status = 'active'
          AND (ce.hire_date <= $2 OR ce.hire_date IS NULL)
          AND (
            ep.exit_date IS NULL 
            OR ep.exit_date > $3
            OR (ep.exit_date IS NOT NULL AND ep.exit_date >= $2)
          )
    `

	rows, err := r.client.Query(ctx, query, companyID, periodEnd, periodStart)
	if err != nil {
		r.logger.Error("Failed to get employee IDs for payroll",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
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

func (r *payrollRepository) IsPeriodLockedRange(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (bool, error) {

	query := `
        SELECT EXISTS (
            SELECT 1
            FROM attendance_daily_summary
            WHERE company_id = $1
              AND attendance_date BETWEEN $2 AND $3
              AND is_payroll_locked = true
        )
    `

	var locked bool
	err := r.client.QueryRow(
		ctx,
		query,
		companyID,
		startDate,
		endDate,
	).Scan(&locked)

	if err != nil {
		r.logger.Error("Failed to check payroll lock range",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check payroll lock range: %w", err)
	}

	return locked, nil
}
