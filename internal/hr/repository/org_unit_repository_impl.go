package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/orgunit"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

type OrgUnitRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

func NewOrgUnitRepository(postgresClient *client.PostgresClient, logger *zap.Logger) OrgUnitRepository {
	repo := &OrgUnitRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt),
	}
	go repo.initializePreparedStatements(context.Background())
	return repo
}

func (r *OrgUnitRepositoryImpl) CreateOrgUnit(ctx context.Context, orgUnit *orgunit.OrgUnit) error {
	query := `
		INSERT INTO org_units (
			org_unit_id, company_id, org_unit_type, name, description,
			department_id, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.client.Exec(ctx, query,
		orgUnit.OrgUnitID,
		orgUnit.CompanyID,
		orgUnit.OrgUnitType,
		orgUnit.Name,
		orgUnit.Description,
		orgUnit.DepartmentID,
		orgUnit.IsActive,
		orgUnit.CreatedAt,
		orgUnit.UpdatedAt,
	)

	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return fmt.Errorf("org unit with this name already exists")
		}
		return fmt.Errorf("failed to create org unit: %w", err)
	}

	return nil
}

func (r *OrgUnitRepositoryImpl) GetOrgUnitByID(ctx context.Context, companyID, orgUnitID uuid.UUID) (*orgunit.OrgUnit, error) {
	stmt, ok := r.getStmt("get_org_unit_by_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found")
	}

	rows, err := stmt.QueryContext(ctx, companyID, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get org unit: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanOrgUnit(rows)
	}

	return nil, fmt.Errorf("org unit not found: %s", orgUnitID)
}

func (r *OrgUnitRepositoryImpl) GetOrgUnitWithDetails(ctx context.Context, companyID, orgUnitID uuid.UUID) (*orgunit.OrgUnitWithDetails, error) {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get org unit
	ouQuery := `
		SELECT ou.*, d.department_name, wc.name as work_center_name
		FROM org_units ou
		LEFT JOIN departments d ON ou.department_id = d.department_id
		LEFT JOIN work_centers wc ON ou.work_center_id = wc.work_center_code AND ou.company_id = wc.company_id
		WHERE ou.company_id = $1 AND ou.org_unit_id = $2`

	var ou orgunit.OrgUnit
	var deptName, workCenterName sql.NullString

	err = tx.QueryRow(ouQuery, companyID, orgUnitID).Scan(
		&ou.OrgUnitID,
		&ou.CompanyID,
		&ou.OrgUnitType,
		&ou.Name,
		&ou.Description,
		&ou.DepartmentID,
		&ou.IsActive,
		&ou.CreatedAt,
		&ou.UpdatedAt,
		&deptName,
		&workCenterName,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get org unit: %w", err)
	}

	// Get member count
	countQuery := `SELECT COUNT(*) FROM org_unit_members WHERE org_unit_id = $1 AND effective_to IS NULL`
	var memberCount int
	err = tx.QueryRow(countQuery, orgUnitID).Scan(&memberCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count members: %w", err)
	}

	// Get active members
	membersQuery := `
		SELECT user_id, effective_from, effective_to
		FROM org_unit_members
		WHERE org_unit_id = $1 AND effective_to IS NULL
		ORDER BY effective_from`

	memberRows, err := tx.Query(membersQuery, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get members: %w", err)
	}
	defer memberRows.Close()

	var activeMembers []orgunit.OrgUnitMember
	for memberRows.Next() {
		var member orgunit.OrgUnitMember
		var effTo sql.NullTime
		err = memberRows.Scan(&member.UserID, &member.EffectiveFrom, &effTo)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		if effTo.Valid {
			member.EffectiveTo = &effTo.Time
		}
		member.OrgUnitID = orgUnitID
		activeMembers = append(activeMembers, member)
	}

	// Get roles
	rolesQuery := `
		SELECT user_id, role, position_id, effective_from, effective_to
		FROM org_unit_roles
		WHERE org_unit_id = $1 AND effective_to IS NULL
		ORDER BY role, user_id`

	roleRows, err := tx.Query(rolesQuery, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	defer roleRows.Close()

	var roles []orgunit.OrgUnitRole
	for roleRows.Next() {
		var role orgunit.OrgUnitRole
		var positionID sql.NullString
		var effTo sql.NullTime
		err = roleRows.Scan(&role.UserID, &role.Role, &positionID, &role.EffectiveFrom, &effTo)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		if effTo.Valid {
			role.EffectiveTo = &effTo.Time
		}
		if positionID.Valid {
			pid, _ := uuid.Parse(positionID.String)
			role.PositionID = &pid
		}
		role.OrgUnitID = orgUnitID
		roles = append(roles, role)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	result := &orgunit.OrgUnitWithDetails{
		OrgUnit:       ou,
		MemberCount:   memberCount,
		ActiveMembers: activeMembers,
		Roles:         roles,
	}

	if deptName.Valid {
		result.Department = &deptName.String
	}
	if workCenterName.Valid {
		result.WorkCenter = &workCenterName.String
	}

	return result, nil
}

func (r *OrgUnitRepositoryImpl) UpdateOrgUnit(ctx context.Context, orgUnit *orgunit.OrgUnit) error {
	query := `
		UPDATE org_units SET
			name = $1, description = $2, department_id = $3,
			is_active = $4, updated_at = $5
		WHERE company_id = $6 AND org_unit_id = $7`

	result, err := r.client.Exec(ctx, query,
		orgUnit.Name,
		orgUnit.Description,
		orgUnit.DepartmentID,
		orgUnit.IsActive,
		orgUnit.UpdatedAt,
		orgUnit.CompanyID,
		orgUnit.OrgUnitID,
	)

	if err != nil {
		return fmt.Errorf("failed to update org unit: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("org unit not found")
	}

	return nil
}

func (r *OrgUnitRepositoryImpl) DeleteOrgUnit(ctx context.Context, companyID, orgUnitID uuid.UUID) error {
	// First, end all memberships
	endMembersQuery := `
		UPDATE org_unit_members
		SET effective_to = CURRENT_DATE
		WHERE org_unit_id = $1 AND effective_to IS NULL`

	_, err := r.client.Exec(ctx, endMembersQuery, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to end memberships: %w", err)
	}

	// End all roles
	endRolesQuery := `
		UPDATE org_unit_roles
		SET effective_to = CURRENT_DATE
		WHERE org_unit_id = $1 AND effective_to IS NULL`

	_, err = r.client.Exec(ctx, endRolesQuery, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to end roles: %w", err)
	}

	// Soft delete org unit
	query := `UPDATE org_units SET is_active = false WHERE company_id = $1 AND org_unit_id = $2`
	result, err := r.client.Exec(ctx, query, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to delete org unit: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("org unit not found")
	}

	return nil
}

func (r *OrgUnitRepositoryImpl) SoftDeleteOrgUnit(ctx context.Context, companyID, orgUnitID uuid.UUID) error {
	return r.DeleteOrgUnit(ctx, companyID, orgUnitID)
}

func (r *OrgUnitRepositoryImpl) ListOrgUnits(ctx context.Context, companyID uuid.UUID, orgUnitType *string, isActive *bool, limit, offset int) ([]*orgunit.OrgUnit, int, error) {
	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	paramIdx := 2

	if orgUnitType != nil {
		conditions = append(conditions, fmt.Sprintf("org_unit_type = $%d", paramIdx))
		params = append(params, *orgUnitType)
		paramIdx++
	}

	if isActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", paramIdx))
		params = append(params, *isActive)
		paramIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM org_units %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count org units: %w", err)
	}

	// List
	listQuery := fmt.Sprintf(`
		SELECT org_unit_id, company_id, org_unit_type, name, description,
			   department_id, is_active, created_at, updated_at
		FROM org_units %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, paramIdx, paramIdx+1)

	params = append(params, limit, offset)
	rows, err := r.client.Query(ctx, listQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list org units: %w", err)
	}
	defer rows.Close()

	orgUnits := make([]*orgunit.OrgUnit, 0, limit)
	for rows.Next() {
		ou, err := r.scanOrgUnit(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan org unit: %w", err)
		}
		orgUnits = append(orgUnits, ou)
	}

	return orgUnits, totalCount, nil
}

func (r *OrgUnitRepositoryImpl) SearchOrgUnits(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*orgunit.OrgUnit, int, error) {
	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	paramIdx := 2

	for field, value := range filters {
		switch field {
		case "name":
			conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", paramIdx))
			params = append(params, "%"+value.(string)+"%")
			paramIdx++
		case "org_unit_type":
			conditions = append(conditions, fmt.Sprintf("org_unit_type = $%d", paramIdx))
			params = append(params, value)
			paramIdx++
		case "is_active":
			conditions = append(conditions, fmt.Sprintf("is_active = $%d", paramIdx))
			params = append(params, value)
			paramIdx++
		case "department_id":
			conditions = append(conditions, fmt.Sprintf("department_id = $%d", paramIdx))
			params = append(params, value)
			paramIdx++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM org_units %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	searchQuery := fmt.Sprintf(`
		SELECT org_unit_id, company_id, org_unit_type, name, description,
			   department_id, is_active, created_at, updated_at
		FROM org_units %s
		ORDER BY name
		LIMIT $%d OFFSET $%d`, whereClause, paramIdx, paramIdx+1)

	params = append(params, limit, offset)
	rows, err := r.client.Query(ctx, searchQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search org units: %w", err)
	}
	defer rows.Close()

	orgUnits := make([]*orgunit.OrgUnit, 0, limit)
	for rows.Next() {
		ou, err := r.scanOrgUnit(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan org unit: %w", err)
		}
		orgUnits = append(orgUnits, ou)
	}

	return orgUnits, totalCount, nil
}

func (r *OrgUnitRepositoryImpl) GetActiveOrgUnits(ctx context.Context, companyID uuid.UUID) ([]*orgunit.OrgUnit, error) {
	query := `
		SELECT org_unit_id, company_id, org_unit_type, name, description,
			   department_id, is_active, created_at, updated_at
		FROM org_units
		WHERE company_id = $1 AND is_active = true
		ORDER BY name`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active org units: %w", err)
	}
	defer rows.Close()

	var orgUnits []*orgunit.OrgUnit
	for rows.Next() {
		ou, err := r.scanOrgUnit(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan org unit: %w", err)
		}
		orgUnits = append(orgUnits, ou)
	}

	return orgUnits, nil
}

func (r *OrgUnitRepositoryImpl) CheckOrgUnitExists(ctx context.Context, companyID uuid.UUID, name string, orgUnitType string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM org_units WHERE company_id = $1 AND name = $2 AND org_unit_type = $3)`
	err := r.client.QueryRow(ctx, query, companyID, name, orgUnitType).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check org unit existence: %w", err)
	}
	return exists, nil
}

func (r *OrgUnitRepositoryImpl) AddMember(ctx context.Context, member *orgunit.OrgUnitMember) error {
	// End any existing active membership first
	endQuery := `
		UPDATE org_unit_members
		SET effective_to = $1
		WHERE org_unit_id = $2 AND user_id = $3 AND effective_to IS NULL`

	_, err := r.client.Exec(ctx, endQuery, member.EffectiveFrom.Add(-24*time.Hour), member.OrgUnitID, member.UserID)
	if err != nil {
		return fmt.Errorf("failed to end existing membership: %w", err)
	}

	// Add new membership
	query := `
		INSERT INTO org_unit_members (org_unit_id, user_id, effective_from, effective_to)
		VALUES ($1, $2, $3, $4)`

	_, err = r.client.Exec(ctx, query,
		member.OrgUnitID,
		member.UserID,
		member.EffectiveFrom,
		member.EffectiveTo,
	)

	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	return nil
}

func (r *OrgUnitRepositoryImpl) RemoveMember(ctx context.Context, orgUnitID, userID uuid.UUID, effectiveTo time.Time) error {
	query := `
		UPDATE org_unit_members
		SET effective_to = $1
		WHERE org_unit_id = $2 AND user_id = $3 AND effective_to IS NULL`

	result, err := r.client.Exec(ctx, query, effectiveTo, orgUnitID, userID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("active membership not found")
	}

	return nil
}

func (r *OrgUnitRepositoryImpl) GetMember(ctx context.Context, orgUnitID, userID uuid.UUID) (*orgunit.OrgUnitMember, error) {
	query := `
		SELECT org_unit_id, user_id, effective_from, effective_to
		FROM org_unit_members
		WHERE org_unit_id = $1 AND user_id = $2
		ORDER BY effective_from DESC
		LIMIT 1`

	var member orgunit.OrgUnitMember
	var effTo sql.NullTime
	err := r.client.QueryRow(ctx, query, orgUnitID, userID).Scan(
		&member.OrgUnitID,
		&member.UserID,
		&member.EffectiveFrom,
		&effTo,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	if effTo.Valid {
		member.EffectiveTo = &effTo.Time
	}

	return &member, nil
}

func (r *OrgUnitRepositoryImpl) GetActiveMembers(ctx context.Context, orgUnitID uuid.UUID) ([]*orgunit.OrgUnitMember, error) {
	query := `
		SELECT org_unit_id, user_id, effective_from, effective_to
		FROM org_unit_members
		WHERE org_unit_id = $1 AND effective_to IS NULL
		ORDER BY effective_from`

	rows, err := r.client.Query(ctx, query, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active members: %w", err)
	}
	defer rows.Close()

	var members []*orgunit.OrgUnitMember
	for rows.Next() {
		var member orgunit.OrgUnitMember
		var effTo sql.NullTime
		err = rows.Scan(&member.OrgUnitID, &member.UserID, &member.EffectiveFrom, &effTo)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		if effTo.Valid {
			member.EffectiveTo = &effTo.Time
		}
		members = append(members, &member)
	}

	return members, nil
}

func (r *OrgUnitRepositoryImpl) GetUserMemberships(ctx context.Context, userID uuid.UUID, onlyActive bool) ([]*orgunit.UserOrgUnitMembership, error) {
	conditions := []string{"oum.user_id = $1"}
	params := []interface{}{userID}

	if onlyActive {
		conditions = append(conditions, "oum.effective_to IS NULL")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT oum.org_unit_id, oum.user_id, ou.name as org_unit_name,
			   ou.org_unit_type, our.role, our.position_id
		FROM org_unit_members oum
		JOIN org_units ou ON oum.org_unit_id = ou.org_unit_id
		LEFT JOIN org_unit_roles our ON oum.org_unit_id = our.org_unit_id 
			AND oum.user_id = our.user_id AND our.effective_to IS NULL
		%s
		ORDER BY ou.org_unit_type, ou.name`, whereClause)

	rows, err := r.client.Query(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}
	defer rows.Close()

	var memberships []*orgunit.UserOrgUnitMembership
	for rows.Next() {
		var membership orgunit.UserOrgUnitMembership
		var role, positionID sql.NullString
		err = rows.Scan(
			&membership.OrgUnitID,
			&membership.UserID,
			&membership.OrgUnitName,
			&membership.OrgUnitType,
			&role,
			&positionID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}
		if role.Valid {
			membership.Role = &role.String
		}
		if positionID.Valid {
			pid, _ := uuid.Parse(positionID.String)
			membership.PositionID = &pid
		}
		memberships = append(memberships, &membership)
	}

	return memberships, nil
}

func (r *OrgUnitRepositoryImpl) GetOrgUnitMembers(ctx context.Context, orgUnitID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitMember, error) {
	conditions := []string{"org_unit_id = $1"}
	params := []interface{}{orgUnitID}

	if onlyActive {
		conditions = append(conditions, "effective_to IS NULL")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT org_unit_id, user_id, effective_from, effective_to
		FROM org_unit_members
		%s
		ORDER BY effective_from`, whereClause)

	rows, err := r.client.Query(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get org unit members: %w", err)
	}
	defer rows.Close()

	var members []*orgunit.OrgUnitMember
	for rows.Next() {
		var member orgunit.OrgUnitMember
		var effTo sql.NullTime
		err = rows.Scan(&member.OrgUnitID, &member.UserID, &member.EffectiveFrom, &effTo)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		if effTo.Valid {
			member.EffectiveTo = &effTo.Time
		}
		members = append(members, &member)
	}

	return members, nil
}

func (r *OrgUnitRepositoryImpl) AssignRole(ctx context.Context, role *orgunit.OrgUnitRole) error {
	// End any existing active role first
	endQuery := `
		UPDATE org_unit_roles
		SET effective_to = $1
		WHERE org_unit_id = $2 AND user_id = $3 AND role = $4 AND effective_to IS NULL`

	_, err := r.client.Exec(ctx, endQuery, role.EffectiveFrom.Add(-24*time.Hour),
		role.OrgUnitID, role.UserID, role.Role)
	if err != nil {
		return fmt.Errorf("failed to end existing role: %w", err)
	}

	// Assign new role
	query := `
		INSERT INTO org_unit_roles (org_unit_id, user_id, role, position_id, effective_from, effective_to)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err = r.client.Exec(ctx, query,
		role.OrgUnitID,
		role.UserID,
		role.Role,
		role.PositionID,
		role.EffectiveFrom,
		role.EffectiveTo,
	)

	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

func (r *OrgUnitRepositoryImpl) RemoveRole(ctx context.Context, orgUnitID, userID uuid.UUID, role string, effectiveTo time.Time) error {
	query := `
		UPDATE org_unit_roles
		SET effective_to = $1
		WHERE org_unit_id = $2 AND user_id = $3 AND role = $4 AND effective_to IS NULL`

	result, err := r.client.Exec(ctx, query, effectiveTo, orgUnitID, userID, role)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("active role not found")
	}

	return nil
}

func (r *OrgUnitRepositoryImpl) GetRole(ctx context.Context, orgUnitID, userID uuid.UUID, role string) (*orgunit.OrgUnitRole, error) {
	query := `
		SELECT org_unit_id, user_id, role, position_id, effective_from, effective_to
		FROM org_unit_roles
		WHERE org_unit_id = $1 AND user_id = $2 AND role = $3
		ORDER BY effective_from DESC
		LIMIT 1`

	var ouRole orgunit.OrgUnitRole
	var positionID sql.NullString
	var effTo sql.NullTime
	err := r.client.QueryRow(ctx, query, orgUnitID, userID, role).Scan(
		&ouRole.OrgUnitID,
		&ouRole.UserID,
		&ouRole.Role,
		&positionID,
		&ouRole.EffectiveFrom,
		&effTo,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if positionID.Valid {
		pid, _ := uuid.Parse(positionID.String)
		ouRole.PositionID = &pid
	}
	if effTo.Valid {
		ouRole.EffectiveTo = &effTo.Time
	}

	return &ouRole, nil
}

func (r *OrgUnitRepositoryImpl) GetUserRoles(ctx context.Context, userID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitRole, error) {
	conditions := []string{"user_id = $1"}
	params := []interface{}{userID}

	if onlyActive {
		conditions = append(conditions, "effective_to IS NULL")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT org_unit_id, user_id, role, position_id, effective_from, effective_to
		FROM org_unit_roles
		%s
		ORDER BY effective_from DESC`, whereClause)

	rows, err := r.client.Query(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	var roles []*orgunit.OrgUnitRole
	for rows.Next() {
		var role orgunit.OrgUnitRole
		var positionID sql.NullString
		var effTo sql.NullTime
		err = rows.Scan(
			&role.OrgUnitID,
			&role.UserID,
			&role.Role,
			&positionID,
			&role.EffectiveFrom,
			&effTo,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		if positionID.Valid {
			pid, _ := uuid.Parse(positionID.String)
			role.PositionID = &pid
		}
		if effTo.Valid {
			role.EffectiveTo = &effTo.Time
		}
		roles = append(roles, &role)
	}

	return roles, nil
}

func (r *OrgUnitRepositoryImpl) GetOrgUnitRoles(ctx context.Context, orgUnitID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitRole, error) {
	conditions := []string{"org_unit_id = $1"}
	params := []interface{}{orgUnitID}

	if onlyActive {
		conditions = append(conditions, "effective_to IS NULL")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT org_unit_id, user_id, role, position_id, effective_from, effective_to
		FROM org_unit_roles
		%s
		ORDER BY role, user_id`, whereClause)

	rows, err := r.client.Query(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get org unit roles: %w", err)
	}
	defer rows.Close()

	var roles []*orgunit.OrgUnitRole
	for rows.Next() {
		var role orgunit.OrgUnitRole
		var positionID sql.NullString
		var effTo sql.NullTime
		err = rows.Scan(
			&role.OrgUnitID,
			&role.UserID,
			&role.Role,
			&positionID,
			&role.EffectiveFrom,
			&effTo,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		if positionID.Valid {
			pid, _ := uuid.Parse(positionID.String)
			role.PositionID = &pid
		}
		if effTo.Valid {
			role.EffectiveTo = &effTo.Time
		}
		roles = append(roles, &role)
	}

	return roles, nil
}

func (r *OrgUnitRepositoryImpl) scanOrgUnit(rows *sql.Rows) (*orgunit.OrgUnit, error) {
	var ou orgunit.OrgUnit
	var description, departmentID sql.NullString

	err := rows.Scan(
		&ou.OrgUnitID,
		&ou.CompanyID,
		&ou.OrgUnitType,
		&ou.Name,
		&description,
		&departmentID,
		&ou.IsActive,
		&ou.CreatedAt,
		&ou.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	if description.Valid {
		ou.Description = &description.String
	}
	if departmentID.Valid {
		did, _ := uuid.Parse(departmentID.String)
		ou.DepartmentID = &did
	}

	return &ou, nil
}

func (r *OrgUnitRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_org_unit_by_id": `
			SELECT org_unit_id, company_id, org_unit_type, name, description,
				   department_id, is_active, created_at, updated_at
			FROM org_units WHERE company_id = $1 AND org_unit_id = $2`,
	}

	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare statement",
				util.String("statement", name),
				util.ErrorField(err))
			continue
		}
		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}

	r.logger.Info("Org unit prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

func (r *OrgUnitRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

func (r *OrgUnitRepositoryImpl) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM org_units LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("org unit repository health check failed: %w", err)
	}
	return nil
}
