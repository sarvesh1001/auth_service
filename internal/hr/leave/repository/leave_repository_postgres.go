package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/hr/leave/models"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type leaveRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewLeaveRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) LeaveRepository {
	return &leaveRepository{
		client: postgresClient,
		logger: logger,
	}
}

// ==============================================
// LEAVE TYPE OPERATIONS
// ==============================================

func (r *leaveRepository) CreateLeaveType(ctx context.Context, leaveType *models.LeaveType) error {
	if leaveType.LeaveTypeID == uuid.Nil {
		leaveType.LeaveTypeID = uuid.New()
	}
	if leaveType.CreatedAt.IsZero() {
		leaveType.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_type (
			leave_type_id, company_id, code, name,
			is_paid, requires_approval, accrual_method,
			carry_forward_limit, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.client.Exec(ctx, query,
		leaveType.LeaveTypeID,
		leaveType.CompanyID,
		leaveType.Code,
		leaveType.Name,
		leaveType.IsPaid,
		leaveType.RequiresApproval,
		leaveType.AccrualMethod,
		leaveType.CarryForwardLimit,
		leaveType.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave type",
			util.String("company_id", leaveType.CompanyID.String()),
			util.String("code", leaveType.Code),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave type: %w", err)
	}

	return nil
}

func (r *leaveRepository) GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*models.LeaveType, error) {
	query := `
		SELECT * FROM leave.leave_type
		WHERE leave_type_id = $1
	`

	row := r.client.QueryRow(ctx, query, leaveTypeID)
	var leaveType models.LeaveType
	var carryForwardLimit sql.NullInt32

	err := row.Scan(
		&leaveType.LeaveTypeID,
		&leaveType.CompanyID,
		&leaveType.Code,
		&leaveType.Name,
		&leaveType.IsPaid,
		&leaveType.RequiresApproval,
		&leaveType.AccrualMethod,
		&carryForwardLimit,
		&leaveType.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get leave type",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}

	if carryForwardLimit.Valid {
		limit := int(carryForwardLimit.Int32)
		leaveType.CarryForwardLimit = &limit
	}

	return &leaveType, nil
}

func (r *leaveRepository) GetLeaveTypeByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.LeaveType, error) {
	query := `
		SELECT * FROM leave.leave_type
		WHERE company_id = $1 AND code = $2
	`

	row := r.client.QueryRow(ctx, query, companyID, code)
	var leaveType models.LeaveType
	var carryForwardLimit sql.NullInt32

	err := row.Scan(
		&leaveType.LeaveTypeID,
		&leaveType.CompanyID,
		&leaveType.Code,
		&leaveType.Name,
		&leaveType.IsPaid,
		&leaveType.RequiresApproval,
		&leaveType.AccrualMethod,
		&carryForwardLimit,
		&leaveType.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get leave type by code",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}

	if carryForwardLimit.Valid {
		limit := int(carryForwardLimit.Int32)
		leaveType.CarryForwardLimit = &limit
	}

	return &leaveType, nil
}

func (r *leaveRepository) GetLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.LeaveType, error) {
	query := `
		SELECT * FROM leave.leave_type
		WHERE company_id = $1
		ORDER BY code
	`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to get leave types by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave types: %w", err)
	}
	defer rows.Close()

	var leaveTypes []*models.LeaveType
	for rows.Next() {
		var leaveType models.LeaveType
		var carryForwardLimit sql.NullInt32

		err := rows.Scan(
			&leaveType.LeaveTypeID,
			&leaveType.CompanyID,
			&leaveType.Code,
			&leaveType.Name,
			&leaveType.IsPaid,
			&leaveType.RequiresApproval,
			&leaveType.AccrualMethod,
			&carryForwardLimit,
			&leaveType.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave type: %w", err)
		}

		if carryForwardLimit.Valid {
			limit := int(carryForwardLimit.Int32)
			leaveType.CarryForwardLimit = &limit
		}

		leaveTypes = append(leaveTypes, &leaveType)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return leaveTypes, nil
}

func (r *leaveRepository) UpdateLeaveType(ctx context.Context, leaveTypeID uuid.UUID, update *models.LeaveTypeUpdate) error {
	var setClauses []string
	var args []interface{}
	argIdx := 1

	if update.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *update.Name)
		argIdx++
	}

	if update.IsPaid != nil {
		setClauses = append(setClauses, fmt.Sprintf("is_paid = $%d", argIdx))
		args = append(args, *update.IsPaid)
		argIdx++
	}

	if update.RequiresApproval != nil {
		setClauses = append(setClauses, fmt.Sprintf("requires_approval = $%d", argIdx))
		args = append(args, *update.RequiresApproval)
		argIdx++
	}

	if update.AccrualMethod != nil {
		setClauses = append(setClauses, fmt.Sprintf("accrual_method = $%d", argIdx))
		args = append(args, *update.AccrualMethod)
		argIdx++
	}

	if update.CarryForwardLimit != nil {
		setClauses = append(setClauses, fmt.Sprintf("carry_forward_limit = $%d", argIdx))
		args = append(args, *update.CarryForwardLimit)
		argIdx++
	}

	if len(setClauses) == 0 {
		return nil
	}

	query := fmt.Sprintf(`
		UPDATE leave.leave_type
		SET %s
		WHERE leave_type_id = $%d
	`, strings.Join(setClauses, ", "), argIdx)

	args = append(args, leaveTypeID)

	result, err := r.client.Exec(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to update leave type",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave type: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave type not found")
	}

	return nil
}

func (r *leaveRepository) DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID) error {
	query := `
		DELETE FROM leave.leave_type
		WHERE leave_type_id = $1
	`

	result, err := r.client.Exec(ctx, query, leaveTypeID)
	if err != nil {
		r.logger.Error("Failed to delete leave type",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete leave type: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave type not found")
	}

	return nil
}

// ==============================================
// LEAVE ENTITLEMENT OPERATIONS
// ==============================================

func (r *leaveRepository) CreateLeaveEntitlement(ctx context.Context, entitlement *models.LeaveEntitlement) error {
	if entitlement.EntitlementID == uuid.Nil {
		entitlement.EntitlementID = uuid.New()
	}
	if entitlement.CreatedAt.IsZero() {
		entitlement.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_entitlement (
			entitlement_id, company_id, user_id, leave_type_id,
			total_days, effective_from, effective_to, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.client.Exec(ctx, query,
		entitlement.EntitlementID,
		entitlement.CompanyID,
		entitlement.UserID,
		entitlement.LeaveTypeID,
		entitlement.TotalDays,
		entitlement.EffectiveFrom,
		entitlement.EffectiveTo,
		entitlement.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave entitlement",
			util.String("user_id", entitlement.UserID.String()),
			util.String("leave_type_id", entitlement.LeaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave entitlement: %w", err)
	}

	return nil
}

func (r *leaveRepository) GetLeaveEntitlementByID(ctx context.Context, entitlementID uuid.UUID) (*models.LeaveEntitlement, error) {
	query := `
		SELECT * FROM leave.leave_entitlement
		WHERE entitlement_id = $1
	`

	row := r.client.QueryRow(ctx, query, entitlementID)
	var entitlement models.LeaveEntitlement

	err := row.Scan(
		&entitlement.EntitlementID,
		&entitlement.CompanyID,
		&entitlement.UserID,
		&entitlement.LeaveTypeID,
		&entitlement.TotalDays,
		&entitlement.EffectiveFrom,
		&entitlement.EffectiveTo,
		&entitlement.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get leave entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave entitlement: %w", err)
	}

	return &entitlement, nil
}

func (r *leaveRepository) GetLeaveEntitlementsByUser(ctx context.Context, userID uuid.UUID) ([]*models.LeaveEntitlement, error) {
	query := `
		SELECT * FROM leave.leave_entitlement
		WHERE user_id = $1
		AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
		ORDER BY effective_from DESC
	`

	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to get leave entitlements by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave entitlements: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.LeaveEntitlement
	for rows.Next() {
		var entitlement models.LeaveEntitlement
		err := rows.Scan(
			&entitlement.EntitlementID,
			&entitlement.CompanyID,
			&entitlement.UserID,
			&entitlement.LeaveTypeID,
			&entitlement.TotalDays,
			&entitlement.EffectiveFrom,
			&entitlement.EffectiveTo,
			&entitlement.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave entitlement: %w", err)
		}

		entitlements = append(entitlements, &entitlement)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return entitlements, nil
}

func (r *leaveRepository) GetActiveLeaveEntitlement(ctx context.Context, userID, leaveTypeID uuid.UUID, date time.Time) (*models.LeaveEntitlement, error) {
	query := `
		SELECT * FROM leave.leave_entitlement
		WHERE user_id = $1
		AND leave_type_id = $2
		AND effective_from <= $3
		AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY effective_from DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, userID, leaveTypeID, date)
	var entitlement models.LeaveEntitlement

	err := row.Scan(
		&entitlement.EntitlementID,
		&entitlement.CompanyID,
		&entitlement.UserID,
		&entitlement.LeaveTypeID,
		&entitlement.TotalDays,
		&entitlement.EffectiveFrom,
		&entitlement.EffectiveTo,
		&entitlement.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get active leave entitlement",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get active leave entitlement: %w", err)
	}

	return &entitlement, nil
}

func (r *leaveRepository) GetLeaveEntitlementsByCompany(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]*models.LeaveEntitlement, int64, error) {
	offset := (page - 1) * pageSize

	// Get total count
	countQuery := `
		SELECT COUNT(*) FROM leave.leave_entitlement
		WHERE company_id = $1
	`

	row := r.client.QueryRow(ctx, countQuery, companyID)
	var total int64
	err := row.Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count leave entitlements: %w", err)
	}

	// Get paginated results
	query := `
		SELECT * FROM leave.leave_entitlement
		WHERE company_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.client.Query(ctx, query, companyID, pageSize, offset)
	if err != nil {
		r.logger.Error("Failed to get leave entitlements by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get leave entitlements: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.LeaveEntitlement
	for rows.Next() {
		var entitlement models.LeaveEntitlement
		err := rows.Scan(
			&entitlement.EntitlementID,
			&entitlement.CompanyID,
			&entitlement.UserID,
			&entitlement.LeaveTypeID,
			&entitlement.TotalDays,
			&entitlement.EffectiveFrom,
			&entitlement.EffectiveTo,
			&entitlement.CreatedAt,
		)

		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan leave entitlement: %w", err)
		}

		entitlements = append(entitlements, &entitlement)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}

	return entitlements, total, nil
}

func (r *leaveRepository) UpdateLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, update *models.LeaveEntitlementUpdate) error {
	var setClauses []string
	var args []interface{}
	argIdx := 1

	if update.TotalDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("total_days = $%d", argIdx))
		args = append(args, *update.TotalDays)
		argIdx++
	}

	if update.EffectiveFrom != nil {
		setClauses = append(setClauses, fmt.Sprintf("effective_from = $%d", argIdx))
		args = append(args, *update.EffectiveFrom)
		argIdx++
	}

	if update.EffectiveTo != nil {
		setClauses = append(setClauses, fmt.Sprintf("effective_to = $%d", argIdx))
		args = append(args, *update.EffectiveTo)
		argIdx++
	}

	if len(setClauses) == 0 {
		return nil
	}

	query := fmt.Sprintf(`
		UPDATE leave.leave_entitlement
		SET %s
		WHERE entitlement_id = $%d
	`, strings.Join(setClauses, ", "), argIdx)

	args = append(args, entitlementID)

	result, err := r.client.Exec(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to update leave entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave entitlement: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave entitlement not found")
	}

	return nil
}

func (r *leaveRepository) EndLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, endDate time.Time) error {
	query := `
		UPDATE leave.leave_entitlement
		SET effective_to = $1
		WHERE entitlement_id = $2
		AND (effective_to IS NULL OR effective_to > $1)
	`

	result, err := r.client.Exec(ctx, query, endDate, entitlementID)
	if err != nil {
		r.logger.Error("Failed to end leave entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to end leave entitlement: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave entitlement not found or already ended")
	}

	return nil
}

// ==============================================
// LEAVE ACCRUAL OPERATIONS
// ==============================================

func (r *leaveRepository) CreateLeaveAccrual(ctx context.Context, accrual *models.LeaveAccrual) error {
	if accrual.AccrualID == uuid.Nil {
		accrual.AccrualID = uuid.New()
	}
	if accrual.CreatedAt.IsZero() {
		accrual.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_accrual (
			accrual_id, entitlement_id, accrual_date,
			days_accrued, created_at
		) VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.client.Exec(ctx, query,
		accrual.AccrualID,
		accrual.EntitlementID,
		accrual.AccrualDate,
		accrual.DaysAccrued,
		accrual.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave accrual",
			util.String("entitlement_id", accrual.EntitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave accrual: %w", err)
	}

	return nil
}

func (r *leaveRepository) CreateBulkLeaveAccruals(ctx context.Context, accruals []*models.LeaveAccrual) error {
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
		INSERT INTO leave.leave_accrual (
			accrual_id, entitlement_id, accrual_date,
			days_accrued, created_at
		) VALUES ($1, $2, $3, $4, $5)
	`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, accrual := range accruals {
		if accrual.AccrualID == uuid.Nil {
			accrual.AccrualID = uuid.New()
		}
		if accrual.CreatedAt.IsZero() {
			accrual.CreatedAt = time.Now().UTC()
		}

		_, err := stmt.ExecContext(ctx,
			accrual.AccrualID,
			accrual.EntitlementID,
			accrual.AccrualDate,
			accrual.DaysAccrued,
			accrual.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert accrual %s: %w", accrual.AccrualID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (r *leaveRepository) GetLeaveAccrualsByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveAccrual, error) {
	query := `
		SELECT * FROM leave.leave_accrual
		WHERE entitlement_id = $1
		ORDER BY accrual_date
	`

	rows, err := r.client.Query(ctx, query, entitlementID)
	if err != nil {
		r.logger.Error("Failed to get leave accruals by entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave accruals: %w", err)
	}
	defer rows.Close()

	var accruals []*models.LeaveAccrual
	for rows.Next() {
		var accrual models.LeaveAccrual
		err := rows.Scan(
			&accrual.AccrualID,
			&accrual.EntitlementID,
			&accrual.AccrualDate,
			&accrual.DaysAccrued,
			&accrual.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave accrual: %w", err)
		}

		accruals = append(accruals, &accrual)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return accruals, nil
}

func (r *leaveRepository) GetLeaveAccrualsByDate(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*models.LeaveAccrual, error) {
	query := `
		SELECT la.* 
		FROM leave.leave_accrual la
		JOIN leave.leave_entitlement le ON la.entitlement_id = le.entitlement_id
		WHERE le.company_id = $1
		AND la.accrual_date = $2
		ORDER BY le.user_id, la.accrual_date
	`

	rows, err := r.client.Query(ctx, query, companyID, date)
	if err != nil {
		r.logger.Error("Failed to get leave accruals by date",
			util.String("company_id", companyID.String()),
			util.Time("date", date),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave accruals: %w", err)
	}
	defer rows.Close()

	var accruals []*models.LeaveAccrual
	for rows.Next() {
		var accrual models.LeaveAccrual
		err := rows.Scan(
			&accrual.AccrualID,
			&accrual.EntitlementID,
			&accrual.AccrualDate,
			&accrual.DaysAccrued,
			&accrual.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave accrual: %w", err)
		}

		accruals = append(accruals, &accrual)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return accruals, nil
}

func (r *leaveRepository) GetTotalAccruedDays(ctx context.Context, entitlementID uuid.UUID) (int, error) {
	query := `
		SELECT COALESCE(SUM(days_accrued), 0)
		FROM leave.leave_accrual
		WHERE entitlement_id = $1
	`

	row := r.client.QueryRow(ctx, query, entitlementID)
	var total int
	err := row.Scan(&total)
	if err != nil {
		r.logger.Error("Failed to get total accrued days",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("failed to get total accrued days: %w", err)
	}

	return total, nil
}

// ==============================================
// LEAVE REQUEST OPERATIONS
// ==============================================

func (r *leaveRepository) CreateLeaveRequest(ctx context.Context, request *models.LeaveRequest) error {
	if request.LeaveRequestID == uuid.Nil {
		request.LeaveRequestID = uuid.New()
	}
	if request.RequestedAt.IsZero() {
		request.RequestedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_request (
			leave_request_id, company_id, user_id, leave_type_id,
			start_date, end_date, total_days, status,
			requested_by, approved_by, requested_at, approved_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.client.Exec(ctx, query,
		request.LeaveRequestID,
		request.CompanyID,
		request.UserID,
		request.LeaveTypeID,
		request.StartDate,
		request.EndDate,
		request.TotalDays,
		request.Status,
		request.RequestedBy,
		request.ApprovedBy,
		request.RequestedAt,
		request.ApprovedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave request",
			util.String("user_id", request.UserID.String()),
			util.String("leave_type_id", request.LeaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave request: %w", err)
	}

	return nil
}

func (r *leaveRepository) GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*models.LeaveRequest, error) {
	query := `
		SELECT * FROM leave.leave_request
		WHERE leave_request_id = $1
	`

	row := r.client.QueryRow(ctx, query, requestID)
	var request models.LeaveRequest

	err := row.Scan(
		&request.LeaveRequestID,
		&request.CompanyID,
		&request.UserID,
		&request.LeaveTypeID,
		&request.StartDate,
		&request.EndDate,
		&request.TotalDays,
		&request.Status,
		&request.RequestedBy,
		&request.ApprovedBy,
		&request.RequestedAt,
		&request.ApprovedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get leave request",
			util.String("leave_request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave request: %w", err)
	}

	return &request, nil
}

func (r *leaveRepository) GetLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveRequest, error) {
	query := `
		SELECT * FROM leave.leave_request
		WHERE user_id = $1
		AND (
			(start_date BETWEEN $2 AND $3)
			OR (end_date BETWEEN $2 AND $3)
			OR ($2 BETWEEN start_date AND end_date)
		)
		ORDER BY start_date DESC
	`

	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get leave requests by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave requests: %w", err)
	}
	defer rows.Close()

	var requests []*models.LeaveRequest
	for rows.Next() {
		var request models.LeaveRequest
		err := rows.Scan(
			&request.LeaveRequestID,
			&request.CompanyID,
			&request.UserID,
			&request.LeaveTypeID,
			&request.StartDate,
			&request.EndDate,
			&request.TotalDays,
			&request.Status,
			&request.RequestedBy,
			&request.ApprovedBy,
			&request.RequestedAt,
			&request.ApprovedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave request: %w", err)
		}

		requests = append(requests, &request)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return requests, nil
}

func (r *leaveRepository) GetLeaveRequestsByCompany(ctx context.Context, filter models.LeaveRequestFilter) ([]*models.LeaveRequest, int64, error) {
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

	if filter.LeaveTypeID != nil {
		conditions = append(conditions, fmt.Sprintf("leave_type_id = $%d", argIdx))
		args = append(args, *filter.LeaveTypeID)
		argIdx++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *filter.Status)
		argIdx++
	}

	if filter.StartDate != nil && filter.EndDate != nil {
		conditions = append(conditions, fmt.Sprintf("start_date BETWEEN $%d AND $%d", argIdx, argIdx+1))
		args = append(args, *filter.StartDate, *filter.EndDate)
		argIdx += 2
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM leave.leave_request
		%s
	`, whereClause)

	row := r.client.QueryRow(ctx, countQuery, args...)
	var total int64
	err := row.Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count leave requests: %w", err)
	}

	// Get paginated results
	offset := (filter.Page - 1) * filter.PageSize
	query := fmt.Sprintf(`
		SELECT * FROM leave.leave_request
		%s
		ORDER BY requested_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, filter.PageSize, offset)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to get leave requests by company",
			util.String("company_id", filter.CompanyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get leave requests: %w", err)
	}
	defer rows.Close()

	var requests []*models.LeaveRequest
	for rows.Next() {
		var request models.LeaveRequest
		err := rows.Scan(
			&request.LeaveRequestID,
			&request.CompanyID,
			&request.UserID,
			&request.LeaveTypeID,
			&request.StartDate,
			&request.EndDate,
			&request.TotalDays,
			&request.Status,
			&request.RequestedBy,
			&request.ApprovedBy,
			&request.RequestedAt,
			&request.ApprovedAt,
		)

		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan leave request: %w", err)
		}

		requests = append(requests, &request)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}

	return requests, total, nil
}

func (r *leaveRepository) GetPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*models.LeaveRequest, error) {
	query := `
		SELECT lr.* FROM leave.leave_request lr
		JOIN leave.leave_type lt ON lr.leave_type_id = lt.leave_type_id
		WHERE lr.company_id = $1
		AND lr.status = 'pending'
		AND lt.requires_approval = true
		-- Add logic for approver hierarchy if needed
		ORDER BY lr.requested_at
	`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to get pending leave requests",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get pending leave requests: %w", err)
	}
	defer rows.Close()

	var requests []*models.LeaveRequest
	for rows.Next() {
		var request models.LeaveRequest
		err := rows.Scan(
			&request.LeaveRequestID,
			&request.CompanyID,
			&request.UserID,
			&request.LeaveTypeID,
			&request.StartDate,
			&request.EndDate,
			&request.TotalDays,
			&request.Status,
			&request.RequestedBy,
			&request.ApprovedBy,
			&request.RequestedAt,
			&request.ApprovedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave request: %w", err)
		}

		requests = append(requests, &request)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return requests, nil
}

func (r *leaveRepository) UpdateLeaveRequest(ctx context.Context, requestID uuid.UUID, update *models.LeaveRequestUpdate) error {
	var setClauses []string
	var args []interface{}
	argIdx := 1

	if update.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *update.Status)
		argIdx++
	}

	if update.ApprovedBy != nil {
		setClauses = append(setClauses, fmt.Sprintf("approved_by = $%d", argIdx))
		args = append(args, *update.ApprovedBy)
		argIdx++
	}

	if update.ApprovedAt != nil {
		setClauses = append(setClauses, fmt.Sprintf("approved_at = $%d", argIdx))
		args = append(args, *update.ApprovedAt)
		argIdx++
	}

	if len(setClauses) == 0 {
		return nil
	}

	query := fmt.Sprintf(`
		UPDATE leave.leave_request
		SET %s
		WHERE leave_request_id = $%d
	`, strings.Join(setClauses, ", "), argIdx)

	args = append(args, requestID)

	result, err := r.client.Exec(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to update leave request",
			util.String("leave_request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave request not found")
	}

	return nil
}

func (r *leaveRepository) CancelLeaveRequest(ctx context.Context, requestID uuid.UUID) error {
	query := `
		UPDATE leave.leave_request
		SET status = 'cancelled'
		WHERE leave_request_id = $1
		AND status = 'pending'
	`

	result, err := r.client.Exec(ctx, query, requestID)
	if err != nil {
		r.logger.Error("Failed to cancel leave request",
			util.String("leave_request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to cancel leave request: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave request not found or not in pending status")
	}

	return nil
}

func (r *leaveRepository) CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM leave.leave_request
			WHERE user_id = $1
			AND status IN ('pending', 'approved')
			AND (
				(start_date BETWEEN $2 AND $3)
				OR (end_date BETWEEN $2 AND $3)
				OR ($2 BETWEEN start_date AND end_date)
			)
		)
	`

	args := []interface{}{userID, startDate, endDate}
	if excludeRequestID != nil {
		query = `
			SELECT EXISTS (
				SELECT 1 FROM leave.leave_request
				WHERE user_id = $1
				AND leave_request_id != $4
				AND status IN ('pending', 'approved')
				AND (
					(start_date BETWEEN $2 AND $3)
					OR (end_date BETWEEN $2 AND $3)
					OR ($2 BETWEEN start_date AND end_date)
				)
			)
		`
		args = append(args, *excludeRequestID)
	}

	row := r.client.QueryRow(ctx, query, args...)
	var exists bool
	err := row.Scan(&exists)
	if err != nil {
		r.logger.Error("Failed to check leave overlap",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check leave overlap: %w", err)
	}

	return exists, nil
}

// ==============================================
// LEAVE LEDGER OPERATIONS
// ==============================================

func (r *leaveRepository) CreateLeaveLedgerEntry(ctx context.Context, entry *models.LeaveLedger) error {
	if entry.LedgerID == uuid.Nil {
		entry.LedgerID = uuid.New()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_ledger (
			ledger_id, entitlement_id, leave_request_id,
			entry_type, days, entry_date, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.client.Exec(ctx, query,
		entry.LedgerID,
		entry.EntitlementID,
		entry.LeaveRequestID,
		entry.EntryType,
		entry.Days,
		entry.EntryDate,
		entry.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave ledger entry",
			util.String("entitlement_id", entry.EntitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave ledger entry: %w", err)
	}

	return nil
}

func (r *leaveRepository) CreateBulkLeaveLedgerEntries(ctx context.Context, entries []*models.LeaveLedger) error {
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
		INSERT INTO leave.leave_ledger (
			ledger_id, entitlement_id, leave_request_id,
			entry_type, days, entry_date, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
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
			entry.EntitlementID,
			entry.LeaveRequestID,
			entry.EntryType,
			entry.Days,
			entry.EntryDate,
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

func (r *leaveRepository) GetLeaveLedgerEntriesByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveLedger, error) {
	query := `
		SELECT * FROM leave.leave_ledger
		WHERE entitlement_id = $1
		ORDER BY entry_date, created_at
	`

	rows, err := r.client.Query(ctx, query, entitlementID)
	if err != nil {
		r.logger.Error("Failed to get leave ledger entries by entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave ledger entries: %w", err)
	}
	defer rows.Close()

	var entries []*models.LeaveLedger
	for rows.Next() {
		var entry models.LeaveLedger
		err := rows.Scan(
			&entry.LedgerID,
			&entry.EntitlementID,
			&entry.LeaveRequestID,
			&entry.EntryType,
			&entry.Days,
			&entry.EntryDate,
			&entry.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave ledger entry: %w", err)
		}

		entries = append(entries, &entry)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return entries, nil
}

func (r *leaveRepository) GetLeaveLedgerEntriesByRequest(ctx context.Context, requestID uuid.UUID) ([]*models.LeaveLedger, error) {
	query := `
		SELECT * FROM leave.leave_ledger
		WHERE leave_request_id = $1
		ORDER BY entry_date, created_at
	`

	rows, err := r.client.Query(ctx, query, requestID)
	if err != nil {
		r.logger.Error("Failed to get leave ledger entries by request",
			util.String("leave_request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave ledger entries: %w", err)
	}
	defer rows.Close()

	var entries []*models.LeaveLedger
	for rows.Next() {
		var entry models.LeaveLedger
		err := rows.Scan(
			&entry.LedgerID,
			&entry.EntitlementID,
			&entry.LeaveRequestID,
			&entry.EntryType,
			&entry.Days,
			&entry.EntryDate,
			&entry.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave ledger entry: %w", err)
		}

		entries = append(entries, &entry)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return entries, nil
}

func (r *leaveRepository) GetLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID) (*models.LeaveBalance, error) {
	query := `
		WITH current_entitlement AS (
			SELECT entitlement_id, total_days
			FROM leave.leave_entitlement
			WHERE user_id = $1
			AND leave_type_id = $2
			AND effective_from <= CURRENT_DATE
			AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
			ORDER BY effective_from DESC
			LIMIT 1
		),
		accrual_sum AS (
			SELECT COALESCE(SUM(days_accrued), 0) as accrued
			FROM leave.leave_accrual la
			JOIN current_entitlement ce ON la.entitlement_id = ce.entitlement_id
		),
		consumption_sum AS (
			SELECT COALESCE(SUM(days), 0) as consumed
			FROM leave.leave_ledger ll
			JOIN current_entitlement ce ON ll.entitlement_id = ce.entitlement_id
			WHERE entry_type = 'consumption'
		),
		leave_type_info AS (
			SELECT code, name, carry_forward_limit
			FROM leave.leave_type
			WHERE leave_type_id = $2
		)
		SELECT 
			$1 as user_id,
			$2 as leave_type_id,
			lti.code,
			lti.name,
			COALESCE(ce.total_days, 0) as total_entitled,
			COALESCE(acc.accrued, 0) as accrued,
			COALESCE(con.consumed, 0) as consumed,
			COALESCE(acc.accrued, 0) - COALESCE(con.consumed, 0) as balance,
			lti.carry_forward_limit
		FROM leave_type_info lti
		CROSS JOIN current_entitlement ce
		CROSS JOIN accrual_sum acc
		CROSS JOIN consumption_sum con
	`

	row := r.client.QueryRow(ctx, query, userID, leaveTypeID)
	var balance models.LeaveBalance
	var carryForwardLimit sql.NullInt32

	err := row.Scan(
		&balance.UserID,
		&balance.LeaveTypeID,
		&balance.LeaveTypeCode,
		&balance.LeaveTypeName,
		&balance.TotalEntitled,
		&balance.Accrued,
		&balance.Consumed,
		&balance.Balance,
		&carryForwardLimit,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Return zero balance if no data found
			return &models.LeaveBalance{
				UserID:        userID,
				LeaveTypeID:   leaveTypeID,
				TotalEntitled: 0,
				Accrued:       0,
				Consumed:      0,
				Balance:       0,
			}, nil
		}
		r.logger.Error("Failed to get leave balance",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave balance: %w", err)
	}

	if carryForwardLimit.Valid {
		limit := int(carryForwardLimit.Int32)
		balance.CarryForward = &limit
	}

	return &balance, nil
}

func (r *leaveRepository) GetLeaveBalancesByUser(ctx context.Context, userID uuid.UUID) ([]*models.LeaveBalance, error) {
	query := `
		WITH user_leave_types AS (
			SELECT DISTINCT lt.leave_type_id, lt.code, lt.name, lt.carry_forward_limit
			FROM leave.leave_entitlement le
			JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
			WHERE le.user_id = $1
			AND le.effective_from <= CURRENT_DATE
			AND (le.effective_to IS NULL OR le.effective_to >= CURRENT_DATE)
		),
		current_entitlement AS (
			SELECT le.leave_type_id, le.entitlement_id, le.total_days
			FROM leave.leave_entitlement le
			WHERE le.user_id = $1
			AND le.effective_from <= CURRENT_DATE
			AND (le.effective_to IS NULL OR le.effective_to >= CURRENT_DATE)
		),
		accrual_sum AS (
			SELECT ce.leave_type_id, COALESCE(SUM(days_accrued), 0) as accrued
			FROM leave.leave_accrual la
			JOIN current_entitlement ce ON la.entitlement_id = ce.entitlement_id
			GROUP BY ce.leave_type_id
		),
		consumption_sum AS (
			SELECT ce.leave_type_id, COALESCE(SUM(days), 0) as consumed
			FROM leave.leave_ledger ll
			JOIN current_entitlement ce ON ll.entitlement_id = ce.entitlement_id
			WHERE entry_type = 'consumption'
			GROUP BY ce.leave_type_id
		)
		SELECT 
			$1 as user_id,
			ult.leave_type_id,
			ult.code,
			ult.name,
			COALESCE(ce.total_days, 0) as total_entitled,
			COALESCE(acc.accrued, 0) as accrued,
			COALESCE(con.consumed, 0) as consumed,
			COALESCE(acc.accrued, 0) - COALESCE(con.consumed, 0) as balance,
			ult.carry_forward_limit
		FROM user_leave_types ult
		LEFT JOIN current_entitlement ce ON ult.leave_type_id = ce.leave_type_id
		LEFT JOIN accrual_sum acc ON ult.leave_type_id = acc.leave_type_id
		LEFT JOIN consumption_sum con ON ult.leave_type_id = con.leave_type_id
		ORDER BY ult.code
	`

	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to get leave balances by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave balances: %w", err)
	}
	defer rows.Close()

	var balances []*models.LeaveBalance
	for rows.Next() {
		var balance models.LeaveBalance
		var carryForwardLimit sql.NullInt32

		err := rows.Scan(
			&balance.UserID,
			&balance.LeaveTypeID,
			&balance.LeaveTypeCode,
			&balance.LeaveTypeName,
			&balance.TotalEntitled,
			&balance.Accrued,
			&balance.Consumed,
			&balance.Balance,
			&carryForwardLimit,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave balance: %w", err)
		}

		if carryForwardLimit.Valid {
			limit := int(carryForwardLimit.Int32)
			balance.CarryForward = &limit
		}

		balances = append(balances, &balance)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return balances, nil
}

func (r *leaveRepository) GetLeaveTransactionHistory(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveTransaction, error) {
	query := `
		SELECT 
			ll.ledger_id as transaction_id,
			le.user_id,
			le.leave_type_id,
			ll.entry_type,
			ll.days,
			ll.entry_date,
			ll.leave_request_id as reference_id,
			CASE 
				WHEN ll.leave_request_id IS NOT NULL THEN 'leave_request'
				ELSE NULL
			END as reference_type,
			CASE 
				WHEN ll.entry_type = 'accrual' THEN 'Leave Accrual'
				WHEN ll.entry_type = 'consumption' AND lr.leave_request_id IS NOT NULL THEN 'Leave Taken (' || lt.code || ')'
				WHEN ll.entry_type = 'reversal' AND lr.leave_request_id IS NOT NULL THEN 'Leave Reversal (' || lt.code || ')'
				ELSE ll.entry_type
			END as description
		FROM leave.leave_ledger ll
		JOIN leave.leave_entitlement le ON ll.entitlement_id = le.entitlement_id
		LEFT JOIN leave.leave_request lr ON ll.leave_request_id = lr.leave_request_id
		LEFT JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
		WHERE le.user_id = $1
		AND ll.entry_date BETWEEN $2 AND $3
		ORDER BY ll.entry_date DESC, ll.created_at DESC
	`

	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get leave transaction history",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave transaction history: %w", err)
	}
	defer rows.Close()

	var transactions []*models.LeaveTransaction
	for rows.Next() {
		var transaction models.LeaveTransaction
		var referenceID sql.NullString
		var referenceType sql.NullString

		err := rows.Scan(
			&transaction.TransactionID,
			&transaction.UserID,
			&transaction.LeaveTypeID,
			&transaction.EntryType,
			&transaction.Days,
			&transaction.EntryDate,
			&referenceID,
			&referenceType,
			&transaction.Description,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave transaction: %w", err)
		}

		if referenceID.Valid {
			id, _ := uuid.Parse(referenceID.String)
			transaction.ReferenceID = &id
		}

		if referenceType.Valid {
			transaction.ReferenceType = &referenceType.String
		}

		transactions = append(transactions, &transaction)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return transactions, nil
}

// ==============================================
// BUSINESS LOGIC OPERATIONS
// ==============================================

func (r *leaveRepository) ProcessLeaveRequest(ctx context.Context, requestID uuid.UUID, approved bool, approvedBy uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// 1. Get the leave request
	query := `
		SELECT lr.*, le.entitlement_id
		FROM leave.leave_request lr
		JOIN leave.leave_entitlement le ON lr.user_id = le.user_id 
			AND lr.leave_type_id = le.leave_type_id
			AND le.effective_from <= lr.start_date
			AND (le.effective_to IS NULL OR le.effective_to >= lr.end_date)
		WHERE lr.leave_request_id = $1
		AND lr.status = 'pending'
	`

	row := tx.QueryRowContext(ctx, query, requestID)
	var request models.LeaveRequest
	var entitlementID uuid.UUID

	err = row.Scan(
		&request.LeaveRequestID,
		&request.CompanyID,
		&request.UserID,
		&request.LeaveTypeID,
		&request.StartDate,
		&request.EndDate,
		&request.TotalDays,
		&request.Status,
		&request.RequestedBy,
		&request.ApprovedBy,
		&request.RequestedAt,
		&request.ApprovedAt,
		&entitlementID,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("leave request not found or not in pending status")
		}
		return fmt.Errorf("failed to get leave request: %w", err)
	}

	// 2. Update the request status
	status := "rejected"
	if approved {
		status = "approved"
	}

	updateQuery := `
		UPDATE leave.leave_request
		SET status = $1, approved_by = $2, approved_at = NOW()
		WHERE leave_request_id = $3
	`

	_, err = tx.ExecContext(ctx, updateQuery, status, approvedBy, requestID)
	if err != nil {
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	// 3. If approved, create ledger entries for consumption
	if approved {
		ledgerEntry := &models.LeaveLedger{
			EntitlementID:  entitlementID,
			LeaveRequestID: &requestID,
			EntryType:      "consumption",
			Days:           request.TotalDays,
			EntryDate:      time.Now().UTC(),
			CreatedAt:      time.Now().UTC(),
		}

		ledgerQuery := `
			INSERT INTO leave.leave_ledger (
				ledger_id, entitlement_id, leave_request_id,
				entry_type, days, entry_date, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7)
		`

		ledgerEntry.LedgerID = uuid.New()
		_, err = tx.ExecContext(ctx, ledgerQuery,
			ledgerEntry.LedgerID,
			ledgerEntry.EntitlementID,
			ledgerEntry.LeaveRequestID,
			ledgerEntry.EntryType,
			ledgerEntry.Days,
			ledgerEntry.EntryDate,
			ledgerEntry.CreatedAt,
		)

		if err != nil {
			return fmt.Errorf("failed to create ledger entry: %w", err)
		}
	}

	// 4. Commit transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *leaveRepository) ProcessLeaveAccruals(ctx context.Context, companyID uuid.UUID, accrualDate time.Time) (int, error) {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// 1. Get all active entitlements for accrual
	query := `
		SELECT le.entitlement_id, lt.accrual_method, le.total_days
		FROM leave.leave_entitlement le
		JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
		WHERE le.company_id = $1
		AND le.effective_from <= $2
		AND (le.effective_to IS NULL OR le.effective_to >= $2)
		AND lt.accrual_method != 'none'
	`

	rows, err := tx.QueryContext(ctx, query, companyID, accrualDate)
	if err != nil {
		return 0, fmt.Errorf("failed to get entitlements for accrual: %w", err)
	}
	defer rows.Close()

	var accruals []*models.LeaveAccrual
	processedCount := 0

	for rows.Next() {
		var entitlementID uuid.UUID
		var accrualMethod string
		var totalDays int

		err := rows.Scan(&entitlementID, &accrualMethod, &totalDays)
		if err != nil {
			return 0, fmt.Errorf("failed to scan entitlement: %w", err)
		}

		// Calculate days to accrue based on method
		daysToAccrue := 0
		switch accrualMethod {
		case "monthly":
			daysToAccrue = totalDays / 12
		case "yearly":
			// Check if it's the anniversary month
			daysToAccrue = totalDays
		case "quarterly":
			daysToAccrue = totalDays / 4
		}

		if daysToAccrue > 0 {
			accrual := &models.LeaveAccrual{
				AccrualID:     uuid.New(),
				EntitlementID: entitlementID,
				AccrualDate:   accrualDate,
				DaysAccrued:   daysToAccrue,
				CreatedAt:     time.Now().UTC(),
			}
			accruals = append(accruals, accrual)
			processedCount++
		}
	}

	// 2. Create accrual entries
	if len(accruals) > 0 {
		accrualQuery := `
			INSERT INTO leave.leave_accrual (
				accrual_id, entitlement_id, accrual_date,
				days_accrued, created_at
			) VALUES ($1, $2, $3, $4, $5)
		`

		stmt, err := tx.Prepare(accrualQuery)
		if err != nil {
			return 0, fmt.Errorf("failed to prepare accrual statement: %w", err)
		}
		defer stmt.Close()

		for _, accrual := range accruals {
			_, err = stmt.ExecContext(ctx,
				accrual.AccrualID,
				accrual.EntitlementID,
				accrual.AccrualDate,
				accrual.DaysAccrued,
				accrual.CreatedAt,
			)
			if err != nil {
				return 0, fmt.Errorf("failed to insert accrual: %w", err)
			}

			// Also create ledger entry for accrual
			ledgerEntry := &models.LeaveLedger{
				LedgerID:      uuid.New(),
				EntitlementID: accrual.EntitlementID,
				EntryType:     "accrual",
				Days:          accrual.DaysAccrued,
				EntryDate:     accrual.AccrualDate,
				CreatedAt:     time.Now().UTC(),
			}

			ledgerQuery := `
				INSERT INTO leave.leave_ledger (
					ledger_id, entitlement_id, leave_request_id,
					entry_type, days, entry_date, created_at
				) VALUES ($1, $2, NULL, $3, $4, $5, $6)
			`

			_, err = tx.ExecContext(ctx, ledgerQuery,
				ledgerEntry.LedgerID,
				ledgerEntry.EntitlementID,
				ledgerEntry.EntryType,
				ledgerEntry.Days,
				ledgerEntry.EntryDate,
				ledgerEntry.CreatedAt,
			)
			if err != nil {
				return 0, fmt.Errorf("failed to create ledger entry for accrual: %w", err)
			}
		}
	}

	// 3. Commit transaction
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return processedCount, nil
}

func (r *leaveRepository) CalculateLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID, asOfDate time.Time) (*models.LeaveBalance, error) {
	query := `
		WITH current_entitlement AS (
			SELECT entitlement_id, total_days
			FROM leave.leave_entitlement
			WHERE user_id = $1
			AND leave_type_id = $2
			AND effective_from <= $3
			AND (effective_to IS NULL OR effective_to >= $3)
			ORDER BY effective_from DESC
			LIMIT 1
		),
		accrual_sum AS (
			SELECT COALESCE(SUM(days_accrued), 0) as accrued
			FROM leave.leave_accrual la
			JOIN current_entitlement ce ON la.entitlement_id = ce.entitlement_id
			WHERE la.accrual_date <= $3
		),
		consumption_sum AS (
			SELECT COALESCE(SUM(days), 0) as consumed
			FROM leave.leave_ledger ll
			JOIN current_entitlement ce ON ll.entitlement_id = ce.entitlement_id
			WHERE ll.entry_type = 'consumption'
			AND ll.entry_date <= $3
		),
		leave_type_info AS (
			SELECT code, name, carry_forward_limit
			FROM leave.leave_type
			WHERE leave_type_id = $2
		)
		SELECT 
			$1 as user_id,
			$2 as leave_type_id,
			lti.code,
			lti.name,
			COALESCE(ce.total_days, 0) as total_entitled,
			COALESCE(acc.accrued, 0) as accrued,
			COALESCE(con.consumed, 0) as consumed,
			COALESCE(acc.accrued, 0) - COALESCE(con.consumed, 0) as balance,
			lti.carry_forward_limit
		FROM leave_type_info lti
		CROSS JOIN current_entitlement ce
		CROSS JOIN accrual_sum acc
		CROSS JOIN consumption_sum con
	`

	row := r.client.QueryRow(ctx, query, userID, leaveTypeID, asOfDate)
	var balance models.LeaveBalance
	var carryForwardLimit sql.NullInt32

	err := row.Scan(
		&balance.UserID,
		&balance.LeaveTypeID,
		&balance.LeaveTypeCode,
		&balance.LeaveTypeName,
		&balance.TotalEntitled,
		&balance.Accrued,
		&balance.Consumed,
		&balance.Balance,
		&carryForwardLimit,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &models.LeaveBalance{
				UserID:        userID,
				LeaveTypeID:   leaveTypeID,
				TotalEntitled: 0,
				Accrued:       0,
				Consumed:      0,
				Balance:       0,
			}, nil
		}
		r.logger.Error("Failed to calculate leave balance",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.Time("as_of_date", asOfDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to calculate leave balance: %w", err)
	}

	if carryForwardLimit.Valid {
		limit := int(carryForwardLimit.Int32)
		balance.CarryForward = &limit
	}

	return &balance, nil
}

func (r *leaveRepository) GetLeaveUtilizationReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveBalance, error) {
	query := `
		WITH user_leave_data AS (
			SELECT 
				le.user_id,
				le.leave_type_id,
				lt.code as leave_type_code,
				lt.name as leave_type_name,
				le.total_days,
				COALESCE(SUM(CASE 
					WHEN la.accrual_date BETWEEN $2 AND $3 
					THEN la.days_accrued ELSE 0 
				END), 0) as accrued_days,
				COALESCE(SUM(CASE 
					WHEN ll.entry_type = 'consumption' 
					AND ll.entry_date BETWEEN $2 AND $3 
					THEN ll.days ELSE 0 
				END), 0) as consumed_days
			FROM leave.leave_entitlement le
			JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
			LEFT JOIN leave.leave_accrual la ON le.entitlement_id = la.entitlement_id
			LEFT JOIN leave.leave_ledger ll ON le.entitlement_id = ll.entitlement_id
			WHERE le.company_id = $1
			AND le.effective_from <= $3
			AND (le.effective_to IS NULL OR le.effective_to >= $2)
			GROUP BY le.user_id, le.leave_type_id, lt.code, lt.name, le.total_days
		)
		SELECT 
			user_id,
			leave_type_id,
			leave_type_code,
			leave_type_name,
			total_days as total_entitled,
			accrued_days as accrued,
			consumed_days as consumed,
			accrued_days - consumed_days as balance
		FROM user_leave_data
		WHERE accrued_days > 0 OR consumed_days > 0
		ORDER BY user_id, leave_type_code
	`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get leave utilization report",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave utilization report: %w", err)
	}
	defer rows.Close()

	var balances []*models.LeaveBalance
	for rows.Next() {
		var balance models.LeaveBalance

		err := rows.Scan(
			&balance.UserID,
			&balance.LeaveTypeID,
			&balance.LeaveTypeCode,
			&balance.LeaveTypeName,
			&balance.TotalEntitled,
			&balance.Accrued,
			&balance.Consumed,
			&balance.Balance,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave balance: %w", err)
		}

		balances = append(balances, &balance)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return balances, nil
}

func (r *leaveRepository) GetLeaveForecast(ctx context.Context, userID uuid.UUID, months int) ([]*models.LeaveBalance, error) {
	forecastDate := time.Now().AddDate(0, months, 0)

	query := `
		WITH leave_types AS (
			SELECT DISTINCT lt.leave_type_id, lt.code, lt.name, lt.accrual_method
			FROM leave.leave_entitlement le
			JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
			WHERE le.user_id = $1
			AND le.effective_from <= $2
			AND (le.effective_to IS NULL OR le.effective_to >= $2)
		),
		current_balances AS (
			SELECT 
				le.leave_type_id,
				COALESCE(SUM(la.days_accrued), 0) as accrued,
				COALESCE(SUM(CASE 
					WHEN ll.entry_type = 'consumption' 
					THEN ll.days ELSE 0 
				END), 0) as consumed
			FROM leave.leave_entitlement le
			LEFT JOIN leave.leave_accrual la ON le.entitlement_id = la.entitlement_id
			LEFT JOIN leave.leave_ledger ll ON le.entitlement_id = ll.entitlement_id
			WHERE le.user_id = $1
			GROUP BY le.leave_type_id
		),
		future_accruals AS (
			SELECT 
				lt.leave_type_id,
				CASE 
					WHEN lt.accrual_method = 'monthly' THEN $3 * (le.total_days / 12)
					WHEN lt.accrual_method = 'quarterly' THEN CEIL($3 / 3.0) * (le.total_days / 4)
					WHEN lt.accrual_method = 'yearly' THEN CEIL($3 / 12.0) * le.total_days
					ELSE 0
				END as forecast_accrual
			FROM leave.leave_entitlement le
			JOIN leave_types lt ON le.leave_type_id = lt.leave_type_id
			WHERE le.user_id = $1
		)
		SELECT 
			$1 as user_id,
			lt.leave_type_id,
			lt.code,
			lt.name,
			COALESCE(cb.accrued, 0) as accrued,
			COALESCE(cb.consumed, 0) as consumed,
			COALESCE(cb.accrued, 0) - COALESCE(cb.consumed, 0) as current_balance,
			COALESCE(fa.forecast_accrual, 0) as forecast_accrual,
			(COALESCE(cb.accrued, 0) - COALESCE(cb.consumed, 0)) + COALESCE(fa.forecast_accrual, 0) as forecast_balance
		FROM leave_types lt
		LEFT JOIN current_balances cb ON lt.leave_type_id = cb.leave_type_id
		LEFT JOIN future_accruals fa ON lt.leave_type_id = fa.leave_type_id
		ORDER BY lt.code
	`

	rows, err := r.client.Query(ctx, query, userID, forecastDate, months)
	if err != nil {
		r.logger.Error("Failed to get leave forecast",
			util.String("user_id", userID.String()),
			util.Int("months", months),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave forecast: %w", err)
	}
	defer rows.Close()

	var forecasts []*models.LeaveBalance
	for rows.Next() {
		var forecast models.LeaveBalance
		var currentBalance, forecastAccrual, forecastBalance int

		err := rows.Scan(
			&forecast.UserID,
			&forecast.LeaveTypeID,
			&forecast.LeaveTypeCode,
			&forecast.LeaveTypeName,
			&forecast.Accrued,
			&forecast.Consumed,
			&currentBalance,
			&forecastAccrual,
			&forecastBalance,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan leave forecast: %w", err)
		}

		forecast.Balance = forecastBalance
		forecasts = append(forecasts, &forecast)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return forecasts, nil
}

// ==============================================
// VALIDATION OPERATIONS
// ==============================================

func (r *leaveRepository) ValidateLeaveRequest(ctx context.Context, request *models.LeaveRequestCreate) (bool, string, error) {
	// Check for overlapping leave requests
	overlap, err := r.CheckLeaveOverlap(ctx, request.UserID, request.StartDate, request.EndDate, nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to check leave overlap: %w", err)
	}

	if overlap {
		return false, "Leave request overlaps with existing approved or pending leave", nil
	}

	// Check leave availability
	available, availableDays, err := r.CheckLeaveAvailability(ctx, request.UserID, request.LeaveTypeID, request.TotalDays, request.StartDate)
	if err != nil {
		return false, "", fmt.Errorf("failed to check leave availability: %w", err)
	}

	if !available {
		return false, fmt.Sprintf("Insufficient leave balance. Available: %d days, Requested: %d days", availableDays, request.TotalDays), nil
	}

	return true, "", nil
}

func (r *leaveRepository) CheckLeaveAvailability(ctx context.Context, userID, leaveTypeID uuid.UUID, days int, startDate time.Time) (bool, int, error) {
	balance, err := r.CalculateLeaveBalance(ctx, userID, leaveTypeID, startDate)
	if err != nil {
		return false, 0, fmt.Errorf("failed to calculate leave balance: %w", err)
	}

	available := balance.Balance >= days
	return available, balance.Balance, nil
}

func (r *leaveRepository) GetLeaveQuota(ctx context.Context, userID, leaveTypeID uuid.UUID) (int, int, error) {
	query := `
		SELECT 
			COALESCE(le.total_days, 0) as total_days,
			COALESCE(SUM(la.days_accrued), 0) - COALESCE(SUM(CASE 
				WHEN ll.entry_type = 'consumption' THEN ll.days ELSE 0 
			END), 0) as available_days
		FROM leave.leave_entitlement le
		LEFT JOIN leave.leave_accrual la ON le.entitlement_id = la.entitlement_id
		LEFT JOIN leave.leave_ledger ll ON le.entitlement_id = ll.entitlement_id
		WHERE le.user_id = $1
		AND le.leave_type_id = $2
		AND le.effective_from <= CURRENT_DATE
		AND (le.effective_to IS NULL OR le.effective_to >= CURRENT_DATE)
		GROUP BY le.entitlement_id, le.total_days
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, userID, leaveTypeID)
	var totalDays, availableDays int

	err := row.Scan(&totalDays, &availableDays)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, nil
		}
		r.logger.Error("Failed to get leave quota",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return 0, 0, fmt.Errorf("failed to get leave quota: %w", err)
	}

	return availableDays, totalDays, nil
}

// ==============================================
// HEALTH CHECK
// ==============================================

func (r *leaveRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM leave.leave_type LIMIT 1`
	var result int
	row := r.client.QueryRow(ctx, query)
	err := row.Scan(&result)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		r.logger.Error("Leave repository health check failed",
			util.ErrorField(err))
		return fmt.Errorf("leave repository health check failed: %w", err)
	}
	return nil
}
func (r *leaveRepository) CreateLeaveBalanceSnapshot(
	ctx context.Context,
	snapshot *models.LeaveBalanceSnapshot,
) error {

	if snapshot.SnapshotID == uuid.Nil {
		snapshot.SnapshotID = uuid.New()
	}
	if snapshot.CalculatedAt.IsZero() {
		snapshot.CalculatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_balance_snapshot (
			snapshot_id,
			entitlement_id,
			balance_days,
			calculated_at
		) VALUES ($1, $2, $3, $4)
	`

	_, err := r.client.Exec(ctx, query,
		snapshot.SnapshotID,
		snapshot.EntitlementID,
		snapshot.BalanceDays,
		snapshot.CalculatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create leave balance snapshot: %w", err)
	}

	return nil
}
func (r *leaveRepository) GetLatestLeaveBalanceSnapshot(
	ctx context.Context,
	entitlementID uuid.UUID,
) (*models.LeaveBalanceSnapshot, error) {

	query := `
		SELECT snapshot_id, entitlement_id, balance_days, calculated_at
		FROM leave.leave_balance_snapshot
		WHERE entitlement_id = $1
		ORDER BY calculated_at DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, entitlementID)

	var snapshot models.LeaveBalanceSnapshot
	err := row.Scan(
		&snapshot.SnapshotID,
		&snapshot.EntitlementID,
		&snapshot.BalanceDays,
		&snapshot.CalculatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get leave balance snapshot: %w", err)
	}

	return &snapshot, nil
}
