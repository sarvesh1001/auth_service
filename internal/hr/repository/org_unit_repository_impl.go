package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"auth-service/internal/client"
	hrErrors "auth-service/internal/hr/errors"
	"auth-service/internal/hr/models/orgunit"
)

type OrgUnitRepositoryImpl struct {
	client *client.PostgresClient
}

func NewOrgUnitRepository(pgClient *client.PostgresClient) OrgUnitRepository {
	return &OrgUnitRepositoryImpl{client: pgClient}
}

// ============================================================
// TRANSACTION HELPERS
// ============================================================

func (r *OrgUnitRepositoryImpl) WithTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := r.client.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ensureTx returns a *sql.Tx. If db is already a *sql.Tx, it's returned
// as-is (owned=false). Otherwise a new tx is opened (owned=true).
func (r *OrgUnitRepositoryImpl) ensureTx(ctx context.Context, db client.DBTX) (tx *sql.Tx, owned bool, err error) {
	if existing, ok := db.(*sql.Tx); ok {
		return existing, false, nil
	}
	tx, err = r.client.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin tx: %w", err)
	}
	return tx, true, nil
}

// ============================================================
// ORG UNITS — WRITE
// ============================================================

// CreateOrgUnit inserts the org unit row only. Locations are managed
// separately via SetOrgUnitLocations (the service wraps both in a tx).
func (r *OrgUnitRepositoryImpl) CreateOrgUnit(ctx context.Context, db client.DBTX, ou *orgunit.OrgUnit) error {
	const query = `
		INSERT INTO org_units (
			org_unit_id, company_id, org_unit_type, name, description,
			department_id, is_active,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := db.ExecContext(ctx, query,
		ou.OrgUnitID, ou.CompanyID, ou.OrgUnitType, ou.Name, ou.Description,
		ou.DepartmentID, ou.IsActive,
		ou.CreatedBy, ou.UpdatedBy, ou.CreatedAt, ou.UpdatedAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return hrErrors.ErrOrgUnitAlreadyExists
		}
		return fmt.Errorf("failed to create org unit: %w", err)
	}
	return nil
}

// UpdateOrgUnit updates the base row only. Locations are handled by
// SetOrgUnitLocations (the service wraps both in a tx).
func (r *OrgUnitRepositoryImpl) UpdateOrgUnit(ctx context.Context, db client.DBTX, ou *orgunit.OrgUnit) error {
	const query = `
		UPDATE org_units SET
			name          = $1,
			description   = $2,
			department_id = $3,
			is_active     = $4,
			updated_by    = $5,
			updated_at    = $6
		WHERE company_id = $7 AND org_unit_id = $8
	`
	result, err := db.ExecContext(ctx, query,
		ou.Name, ou.Description, ou.DepartmentID,
		ou.IsActive, ou.UpdatedBy, ou.UpdatedAt,
		ou.CompanyID, ou.OrgUnitID,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return hrErrors.ErrOrgUnitAlreadyExists
		}
		return fmt.Errorf("failed to update org unit: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return hrErrors.ErrOrgUnitNotFound
	}
	return nil
}

func (r *OrgUnitRepositoryImpl) DeleteOrgUnit(ctx context.Context, db client.DBTX, companyID, orgUnitID, actorID uuid.UUID) error {
	tx, owned, err := r.ensureTx(ctx, db)
	if err != nil {
		return err
	}
	if owned {
		defer tx.Rollback()
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE org_unit_members
		SET effective_to = CURRENT_DATE,
		    updated_at   = NOW(),
		    updated_by   = $1
		WHERE org_unit_id = $2 AND effective_to IS NULL
	`, actorID, orgUnitID); err != nil {
		return fmt.Errorf("failed to end memberships: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE org_unit_roles
		SET effective_to = CURRENT_DATE,
		    is_primary   = false,
		    updated_at   = NOW(),
		    updated_by   = $1
		WHERE org_unit_id = $2 AND effective_to IS NULL
	`, actorID, orgUnitID); err != nil {
		return fmt.Errorf("failed to end roles: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE org_units
		SET is_active  = false,
		    updated_by = $1,
		    updated_at = NOW()
		WHERE company_id = $2 AND org_unit_id = $3 AND is_active = true
	`, actorID, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to delete org unit: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return hrErrors.ErrOrgUnitNotFound
	}

	if owned {
		return tx.Commit()
	}
	return nil
}

// ============================================================
// ORG UNITS ↔ LOCATIONS
// ============================================================

// SetOrgUnitLocations replaces the org's location set atomically.
// Passing an empty slice makes the org universal.
func (r *OrgUnitRepositoryImpl) SetOrgUnitLocations(
	ctx context.Context,
	db client.DBTX,
	orgUnitID uuid.UUID,
	locationIDs []uuid.UUID,
	actorID uuid.UUID,
) error {
	tx, owned, err := r.ensureTx(ctx, db)
	if err != nil {
		return err
	}
	if owned {
		defer tx.Rollback()
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM org_unit_locations WHERE org_unit_id = $1`, orgUnitID,
	); err != nil {
		return fmt.Errorf("clear org unit locations: %w", err)
	}

	if len(locationIDs) > 0 {
		// Bulk insert with unnest — one round-trip.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO org_unit_locations (org_unit_id, location_id, created_by)
			SELECT $1, unnest($2::uuid[]), $3
		`, orgUnitID, pq.Array(locationIDs), actorID); err != nil {
			if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23503" {
				return fmt.Errorf("location does not exist: %w", err)
			}
			return fmt.Errorf("insert org unit locations: %w", err)
		}
	}

	if owned {
		return tx.Commit()
	}
	return nil
}

// GetOrgUnitLocations returns the org's bound location IDs.
func (r *OrgUnitRepositoryImpl) GetOrgUnitLocations(
	ctx context.Context,
	db client.DBTX,
	orgUnitID uuid.UUID,
) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT location_id
		FROM org_unit_locations
		WHERE org_unit_id = $1
		ORDER BY created_at
	`, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("get org unit locations: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetOrgUnitLocationsDetailed returns the org's bound locations with
// code + name. Used by the details view.
func (r *OrgUnitRepositoryImpl) GetOrgUnitLocationsDetailed(
	ctx context.Context,
	db client.DBTX,
	orgUnitID uuid.UUID,
) ([]orgunit.LocationBrief, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT l.location_id, l.location_code, l.location_name
		FROM org_unit_locations oul
		JOIN locations l ON l.location_id = oul.location_id
		WHERE oul.org_unit_id = $1
		ORDER BY oul.created_at
	`, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("get org unit locations detailed: %w", err)
	}
	defer rows.Close()

	var out []orgunit.LocationBrief
	for rows.Next() {
		var lb orgunit.LocationBrief
		if err := rows.Scan(&lb.LocationID, &lb.LocationCode, &lb.LocationName); err != nil {
			return nil, err
		}
		out = append(out, lb)
	}
	return out, rows.Err()
}

// hydrateLocations loads HomeLocationIDs for a batch of org units.
func (r *OrgUnitRepositoryImpl) hydrateLocations(
	ctx context.Context,
	db client.DBTX,
	orgUnits []*orgunit.OrgUnit,
) error {
	if len(orgUnits) == 0 {
		return nil
	}

	ids := make([]uuid.UUID, 0, len(orgUnits))
	byID := make(map[uuid.UUID]*orgunit.OrgUnit, len(orgUnits))
	for _, ou := range orgUnits {
		ids = append(ids, ou.OrgUnitID)
		byID[ou.OrgUnitID] = ou
	}

	rows, err := db.QueryContext(ctx, `
		SELECT org_unit_id, location_id
		FROM org_unit_locations
		WHERE org_unit_id = ANY($1)
		ORDER BY created_at
	`, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("hydrate org unit locations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ouID, locID uuid.UUID
		if err := rows.Scan(&ouID, &locID); err != nil {
			return err
		}
		if ou, ok := byID[ouID]; ok {
			ou.HomeLocationIDs = append(ou.HomeLocationIDs, locID)
		}
	}
	return rows.Err()
}

// ============================================================
// ORG UNITS — READ
// ============================================================

func (r *OrgUnitRepositoryImpl) GetOrgUnitByID(ctx context.Context, db client.DBTX, companyID, orgUnitID uuid.UUID) (*orgunit.OrgUnit, error) {
	const query = `
		SELECT
			ou.org_unit_id, ou.company_id, ou.org_unit_type, ou.name, ou.description,
			ou.department_id, ou.is_active,
			ou.created_by, ou.updated_by, ou.created_at, ou.updated_at,
			org_unit_location_count(ou.org_unit_id) AS location_count,
			org_unit_member_count(ou.org_unit_id)   AS member_count
		FROM org_units ou
		WHERE ou.company_id = $1 AND ou.org_unit_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, orgUnitID)
	ou, err := scanOrgUnitRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, hrErrors.ErrOrgUnitNotFound
		}
		return nil, fmt.Errorf("failed to get org unit: %w", err)
	}

	if err := r.hydrateLocations(ctx, db, []*orgunit.OrgUnit{ou}); err != nil {
		return nil, err
	}
	return ou, nil
}

func (r *OrgUnitRepositoryImpl) GetOrgUnitWithDetails(ctx context.Context, db client.DBTX, companyID, orgUnitID uuid.UUID) (*orgunit.OrgUnitWithDetails, error) {
	// 1. Org unit + department name
	const ouQuery = `
		SELECT
			ou.org_unit_id, ou.company_id, ou.org_unit_type, ou.name, ou.description,
			ou.department_id, ou.is_active,
			ou.created_by, ou.updated_by, ou.created_at, ou.updated_at,
			d.department_name
		FROM org_units ou
		LEFT JOIN departments d ON ou.department_id = d.department_id
		WHERE ou.company_id = $1 AND ou.org_unit_id = $2
	`
	var ou orgunit.OrgUnit
	var deptName sql.NullString
	var createdBy, updatedBy uuid.NullUUID

	err := db.QueryRowContext(ctx, ouQuery, companyID, orgUnitID).Scan(
		&ou.OrgUnitID, &ou.CompanyID, &ou.OrgUnitType, &ou.Name, &ou.Description,
		&ou.DepartmentID, &ou.IsActive,
		&createdBy, &updatedBy, &ou.CreatedAt, &ou.UpdatedAt,
		&deptName,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, hrErrors.ErrOrgUnitNotFound
		}
		return nil, fmt.Errorf("failed to get org unit: %w", err)
	}
	if createdBy.Valid {
		ou.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ou.UpdatedBy = &updatedBy.UUID
	}

	// 2. Configured locations (the org's binding).
	configuredLocs, err := r.GetOrgUnitLocationsDetailed(ctx, db, orgUnitID)
	if err != nil {
		return nil, err
	}
	for _, l := range configuredLocs {
		ou.HomeLocationIDs = append(ou.HomeLocationIDs, l.LocationID)
	}

	// 3. Active members.
	memberRows, err := db.QueryContext(ctx, `
		SELECT org_unit_id, user_id, location_id,
		       effective_from, effective_to,
		       created_by, updated_by, created_at, updated_at
		FROM org_unit_members
		WHERE org_unit_id = $1 AND effective_to IS NULL
		ORDER BY effective_from
	`, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get members: %w", err)
	}
	defer memberRows.Close()

	var activeMembers []orgunit.OrgUnitMember
	for memberRows.Next() {
		m, err := scanOrgUnitMember(memberRows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		activeMembers = append(activeMembers, *m)
	}

	// 4. Active roles.
	roleRows, err := db.QueryContext(ctx, `
		SELECT org_unit_id, user_id, role, position_id, location_id,
		       is_primary, effective_from, effective_to,
		       created_by, updated_by, created_at, updated_at
		FROM org_unit_roles
		WHERE org_unit_id = $1 AND effective_to IS NULL
		ORDER BY role, user_id
	`, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	defer roleRows.Close()

	var roles []orgunit.OrgUnitRole
	for roleRows.Next() {
		rle, err := scanOrgUnitRole(roleRows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, *rle)
	}

	// 5. Member footprint (which locations active members are actually at).
	locRows, err := db.QueryContext(ctx, `
		SELECT l.location_id, l.location_code, l.location_name, COUNT(*) AS member_count
		FROM org_unit_members m
		JOIN locations l ON l.location_id = m.location_id
		WHERE m.org_unit_id = $1 AND m.effective_to IS NULL
		GROUP BY l.location_id, l.location_code, l.location_name
		ORDER BY member_count DESC, l.location_name
	`, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get location footprint: %w", err)
	}
	defer locRows.Close()

	var footprint []orgunit.LocationBrief
	for locRows.Next() {
		var lb orgunit.LocationBrief
		if err := locRows.Scan(&lb.LocationID, &lb.LocationCode, &lb.LocationName, &lb.MemberCount); err != nil {
			return nil, fmt.Errorf("failed to scan location: %w", err)
		}
		footprint = append(footprint, lb)
	}

	ou.LocationCount = len(footprint)
	ou.MemberCount = len(activeMembers)

	result := &orgunit.OrgUnitWithDetails{
		OrgUnit:       ou,
		ActiveMembers: activeMembers,
		Roles:         roles,
		HomeLocations: configuredLocs,
		Locations:     footprint,
	}
	if deptName.Valid {
		result.Department = &deptName.String
	}
	return result, nil
}

func (r *OrgUnitRepositoryImpl) ListOrgUnits(ctx context.Context, db client.DBTX, companyID uuid.UUID, orgUnitType *string, isActive *bool, limit, offset int) ([]*orgunit.OrgUnit, int, error) {
	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	idx := 2

	if orgUnitType != nil {
		conditions = append(conditions, fmt.Sprintf("org_unit_type = $%d", idx))
		params = append(params, *orgUnitType)
		idx++
	}
	if isActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		params = append(params, *isActive)
		idx++
	}
	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM org_units %s", where),
		params...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count org units: %w", err)
	}

	params = append(params, limit, offset)
	listQuery := fmt.Sprintf(`
		SELECT
			ou.org_unit_id, ou.company_id, ou.org_unit_type, ou.name, ou.description,
			ou.department_id, ou.is_active,
			ou.created_by, ou.updated_by, ou.created_at, ou.updated_at,
			org_unit_location_count(ou.org_unit_id) AS location_count,
			org_unit_member_count(ou.org_unit_id)   AS member_count
		FROM org_units ou
		%s
		ORDER BY ou.created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)

	rows, err := db.QueryContext(ctx, listQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list org units: %w", err)
	}
	defer rows.Close()

	orgUnits := make([]*orgunit.OrgUnit, 0, limit)
	for rows.Next() {
		ou, err := scanOrgUnitRows(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan org unit: %w", err)
		}
		orgUnits = append(orgUnits, ou)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := r.hydrateLocations(ctx, db, orgUnits); err != nil {
		return nil, 0, err
	}
	return orgUnits, total, nil
}

func (r *OrgUnitRepositoryImpl) SearchOrgUnits(ctx context.Context, db client.DBTX, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*orgunit.OrgUnit, int, error) {
	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	idx := 2

	for field, value := range filters {
		switch field {
		case "name":
			conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", idx))
			params = append(params, "%"+value.(string)+"%")
			idx++
		case "org_unit_type":
			conditions = append(conditions, fmt.Sprintf("org_unit_type = $%d", idx))
			params = append(params, value)
			idx++
		case "is_active":
			conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
			params = append(params, value)
			idx++
		case "department_id":
			conditions = append(conditions, fmt.Sprintf("department_id = $%d", idx))
			params = append(params, value)
			idx++

		// Single-location filter — orgs bound to exactly this location.
		// Accepts the legacy key `home_location_id` for compatibility.
		case "location_id", "home_location_id":
			conditions = append(conditions, fmt.Sprintf(
				"EXISTS (SELECT 1 FROM org_unit_locations oul WHERE oul.org_unit_id = org_units.org_unit_id AND oul.location_id = $%d)",
				idx))
			params = append(params, value)
			idx++

		// Multi-location filter — orgs bound to any of these.
		case "location_ids", "home_location_ids":
			conditions = append(conditions, fmt.Sprintf(
				"EXISTS (SELECT 1 FROM org_unit_locations oul WHERE oul.org_unit_id = org_units.org_unit_id AND oul.location_id = ANY($%d))",
				idx))
			params = append(params, pq.Array(value))
			idx++

		// Universal-only / bound-only flag.
		case "is_universal":
			if v, ok := value.(bool); ok && v {
				conditions = append(conditions,
					"NOT EXISTS (SELECT 1 FROM org_unit_locations oul WHERE oul.org_unit_id = org_units.org_unit_id)")
			} else if ok {
				conditions = append(conditions,
					"EXISTS (SELECT 1 FROM org_unit_locations oul WHERE oul.org_unit_id = org_units.org_unit_id)")
			}
		}
	}
	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM org_units %s", where), params...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	params = append(params, limit, offset)
	searchQuery := fmt.Sprintf(`
		SELECT
			ou.org_unit_id, ou.company_id, ou.org_unit_type, ou.name, ou.description,
			ou.department_id, ou.is_active,
			ou.created_by, ou.updated_by, ou.created_at, ou.updated_at,
			org_unit_location_count(ou.org_unit_id) AS location_count,
			org_unit_member_count(ou.org_unit_id)   AS member_count
		FROM org_units ou
		%s
		ORDER BY ou.name
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)

	rows, err := db.QueryContext(ctx, searchQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search org units: %w", err)
	}
	defer rows.Close()

	orgUnits := make([]*orgunit.OrgUnit, 0, limit)
	for rows.Next() {
		ou, err := scanOrgUnitRows(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan org unit: %w", err)
		}
		orgUnits = append(orgUnits, ou)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := r.hydrateLocations(ctx, db, orgUnits); err != nil {
		return nil, 0, err
	}
	return orgUnits, total, nil
}

func (r *OrgUnitRepositoryImpl) GetActiveOrgUnits(ctx context.Context, db client.DBTX, companyID uuid.UUID) ([]*orgunit.OrgUnit, error) {
	const query = `
		SELECT
			ou.org_unit_id, ou.company_id, ou.org_unit_type, ou.name, ou.description,
			ou.department_id, ou.is_active,
			ou.created_by, ou.updated_by, ou.created_at, ou.updated_at,
			org_unit_location_count(ou.org_unit_id) AS location_count,
			org_unit_member_count(ou.org_unit_id)   AS member_count
		FROM org_units ou
		WHERE ou.company_id = $1 AND ou.is_active = true
		ORDER BY ou.name
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active org units: %w", err)
	}
	defer rows.Close()

	var orgUnits []*orgunit.OrgUnit
	for rows.Next() {
		ou, err := scanOrgUnitRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan org unit: %w", err)
		}
		orgUnits = append(orgUnits, ou)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := r.hydrateLocations(ctx, db, orgUnits); err != nil {
		return nil, err
	}
	return orgUnits, nil
}

func (r *OrgUnitRepositoryImpl) CheckOrgUnitExists(ctx context.Context, db client.DBTX, companyID uuid.UUID, name string, orgUnitType string) (bool, error) {
	var exists bool
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM org_units
			WHERE company_id = $1
			  AND org_unit_type = $2
			  AND lower(name) = lower($3)
			  AND is_active = true
		)
	`
	if err := db.QueryRowContext(ctx, query, companyID, orgUnitType, name).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check org unit existence: %w", err)
	}
	return exists, nil
}

// ============================================================
// MEMBERS
// ============================================================

func (r *OrgUnitRepositoryImpl) AddMember(ctx context.Context, db client.DBTX, member *orgunit.OrgUnitMember) error {
	tx, owned, err := r.ensureTx(ctx, db)
	if err != nil {
		return err
	}
	if owned {
		defer tx.Rollback()
	}

	if !member.EffectiveFrom.IsZero() {
		prevEnd := member.EffectiveFrom.AddDate(0, 0, -1)
		if _, err := tx.ExecContext(ctx, `
			UPDATE org_unit_members
			SET effective_to = $1,
			    updated_at   = NOW(),
			    updated_by   = $2
			WHERE org_unit_id = $3
			  AND user_id     = $4
			  AND effective_to IS NULL
			  AND effective_from <> $5
		`, prevEnd, member.UpdatedBy, member.OrgUnitID, member.UserID, member.EffectiveFrom); err != nil {
			return fmt.Errorf("failed to end previous membership: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO org_unit_members (
			org_unit_id, user_id, location_id,
			effective_from, effective_to,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3,
			$4, $5,
			NOW(), NOW(), $6, $6
		)
		ON CONFLICT (org_unit_id, user_id, effective_from)
		DO UPDATE SET
			location_id  = EXCLUDED.location_id,
			effective_to = EXCLUDED.effective_to,
			updated_at   = NOW(),
			updated_by   = EXCLUDED.updated_by
	`, member.OrgUnitID, member.UserID, member.LocationID,
		member.EffectiveFrom, member.EffectiveTo,
		member.CreatedBy); err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	if owned {
		return tx.Commit()
	}
	return nil
}

func (r *OrgUnitRepositoryImpl) RemoveMember(
	ctx context.Context, db client.DBTX,
	orgUnitID, userID uuid.UUID,
	effectiveTo time.Time, actorID uuid.UUID,
) error {
	result, err := db.ExecContext(ctx, `
		UPDATE org_unit_members
		SET effective_to = $1,
		    updated_at   = NOW(),
		    updated_by   = $2
		WHERE org_unit_id = $3 AND user_id = $4 AND effective_to IS NULL
	`, effectiveTo, actorID, orgUnitID, userID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return hrErrors.ErrOrgUnitMemberNotFound
	}
	return nil
}

func (r *OrgUnitRepositoryImpl) GetMember(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID) (*orgunit.OrgUnitMember, error) {
	const query = `
		SELECT org_unit_id, user_id, location_id,
		       effective_from, effective_to,
		       created_by, updated_by, created_at, updated_at
		FROM org_unit_members
		WHERE org_unit_id = $1 AND user_id = $2
		ORDER BY effective_from DESC
		LIMIT 1
	`
	rows, err := db.QueryContext(ctx, query, orgUnitID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, hrErrors.ErrOrgUnitMemberNotFound
	}
	m, err := scanOrgUnitMember(rows)
	if err != nil {
		return nil, fmt.Errorf("failed to scan member: %w", err)
	}
	return m, nil
}

func (r *OrgUnitRepositoryImpl) GetActiveMembers(ctx context.Context, db client.DBTX, orgUnitID uuid.UUID) ([]*orgunit.OrgUnitMember, error) {
	const query = `
		SELECT org_unit_id, user_id, location_id,
		       effective_from, effective_to,
		       created_by, updated_by, created_at, updated_at
		FROM org_unit_members
		WHERE org_unit_id = $1 AND effective_to IS NULL
		ORDER BY effective_from
	`
	rows, err := db.QueryContext(ctx, query, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active members: %w", err)
	}
	defer rows.Close()

	var members []*orgunit.OrgUnitMember
	for rows.Next() {
		m, err := scanOrgUnitMember(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (r *OrgUnitRepositoryImpl) GetUserMemberships(ctx context.Context, db client.DBTX, userID uuid.UUID, onlyActive bool) ([]*orgunit.UserOrgUnitMembership, error) {
	conditions := []string{"oum.user_id = $1"}
	params := []interface{}{userID}
	if onlyActive {
		conditions = append(conditions, "oum.effective_to IS NULL")
	}
	where := "WHERE " + strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT oum.org_unit_id, oum.user_id, oum.location_id,
		       ou.name AS org_unit_name, ou.org_unit_type,
		       our.role, our.position_id
		FROM org_unit_members oum
		JOIN org_units ou ON oum.org_unit_id = ou.org_unit_id
		LEFT JOIN org_unit_roles our
			ON oum.org_unit_id = our.org_unit_id
			AND oum.user_id = our.user_id
			AND our.effective_to IS NULL
		%s
		ORDER BY ou.org_unit_type, ou.name
	`, where)

	rows, err := db.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}
	defer rows.Close()

	var memberships []*orgunit.UserOrgUnitMembership
	for rows.Next() {
		var m orgunit.UserOrgUnitMembership
		var locID, posID uuid.NullUUID
		var role sql.NullString
		if err := rows.Scan(
			&m.OrgUnitID, &m.UserID, &locID,
			&m.OrgUnitName, &m.OrgUnitType,
			&role, &posID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}
		if locID.Valid {
			m.LocationID = &locID.UUID
		}
		if posID.Valid {
			m.PositionID = &posID.UUID
		}
		if role.Valid {
			m.Role = &role.String
		}
		memberships = append(memberships, &m)
	}
	return memberships, rows.Err()
}

func (r *OrgUnitRepositoryImpl) GetOrgUnitMembers(ctx context.Context, db client.DBTX, orgUnitID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitMember, error) {
	conditions := []string{"org_unit_id = $1"}
	params := []interface{}{orgUnitID}
	if onlyActive {
		conditions = append(conditions, "effective_to IS NULL")
	}
	where := "WHERE " + strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT org_unit_id, user_id, location_id,
		       effective_from, effective_to,
		       created_by, updated_by, created_at, updated_at
		FROM org_unit_members
		%s
		ORDER BY effective_from
	`, where)

	rows, err := db.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get org unit members: %w", err)
	}
	defer rows.Close()

	var members []*orgunit.OrgUnitMember
	for rows.Next() {
		m, err := scanOrgUnitMember(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (r *OrgUnitRepositoryImpl) MemberExists(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID, effectiveFrom time.Time) (bool, error) {
	var exists bool
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM org_unit_members
			WHERE org_unit_id = $1 AND user_id = $2 AND effective_from = $3
		)
	`
	if err := db.QueryRowContext(ctx, query, orgUnitID, userID, effectiveFrom).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check member existence: %w", err)
	}
	return exists, nil
}

func (r *OrgUnitRepositoryImpl) EndActiveMembership(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID, effectiveTo time.Time) error {
	_, err := db.ExecContext(ctx, `
		UPDATE org_unit_members
		SET effective_to = $1, updated_at = NOW()
		WHERE org_unit_id = $2 AND user_id = $3 AND effective_to IS NULL
	`, effectiveTo, orgUnitID, userID)
	return err
}

func (r *OrgUnitRepositoryImpl) GetActiveUsersByOrgUnit(ctx context.Context, db client.DBTX, orgUnitID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT user_id FROM org_unit_members
		WHERE org_unit_id = $1 AND effective_to IS NULL
	`, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch org unit users: %w", err)
	}
	defer rows.Close()

	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var uid uuid.UUID
		if err := rows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("failed to scan user_id: %w", err)
		}
		ids = append(ids, uid)
	}
	return ids, rows.Err()
}

// ============================================================
// ROLES
// ============================================================

func (r *OrgUnitRepositoryImpl) AssignRole(ctx context.Context, db client.DBTX, role *orgunit.OrgUnitRole) error {
	tx, owned, err := r.ensureTx(ctx, db)
	if err != nil {
		return err
	}
	if owned {
		defer tx.Rollback()
	}

	if !role.EffectiveFrom.IsZero() {
		prevEnd := role.EffectiveFrom.AddDate(0, 0, -1)
		if _, err := tx.ExecContext(ctx, `
			UPDATE org_unit_roles
			SET effective_to = $1,
			    updated_at   = NOW(),
			    updated_by   = $2
			WHERE org_unit_id = $3
			  AND user_id     = $4
			  AND role        = $5
			  AND effective_to IS NULL
			  AND effective_from <> $6
		`, prevEnd, role.UpdatedBy, role.OrgUnitID, role.UserID, role.Role, role.EffectiveFrom); err != nil {
			return fmt.Errorf("failed to end previous role: %w", err)
		}
	}

	if role.IsPrimary {
		if _, err := tx.ExecContext(ctx, `
			UPDATE org_unit_roles
			SET is_primary = false,
			    updated_at = NOW(),
			    updated_by = $1
			WHERE org_unit_id  = $2
			  AND user_id      = $3
			  AND is_primary   = true
			  AND effective_to IS NULL
			  AND NOT (role = $4 AND effective_from = $5)
		`, role.UpdatedBy, role.OrgUnitID, role.UserID,
			role.Role, role.EffectiveFrom); err != nil {
			return fmt.Errorf("failed to clear previous primary role: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO org_unit_roles (
			org_unit_id, user_id, role,
			position_id, location_id, is_primary,
			effective_from, effective_to,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3,
			$4, $5, $6,
			$7, $8,
			NOW(), NOW(), $9, $9
		)
		ON CONFLICT (org_unit_id, user_id, role, effective_from)
		DO UPDATE SET
			position_id  = EXCLUDED.position_id,
			location_id  = EXCLUDED.location_id,
			is_primary   = EXCLUDED.is_primary,
			effective_to = EXCLUDED.effective_to,
			updated_at   = NOW(),
			updated_by   = EXCLUDED.updated_by
	`, role.OrgUnitID, role.UserID, role.Role,
		role.PositionID, role.LocationID, role.IsPrimary,
		role.EffectiveFrom, role.EffectiveTo,
		role.CreatedBy); err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			switch pgErr.Constraint {
			case "uq_our_primary_per_user_org_unit":
				return hrErrors.ErrOrgUnitPrimaryAlreadyExists
			default:
				return hrErrors.ErrOrgUnitRoleAlreadyExists
			}
		}
		return fmt.Errorf("failed to assign role: %w", err)
	}

	if owned {
		return tx.Commit()
	}
	return nil
}

func (r *OrgUnitRepositoryImpl) RemoveRole(
	ctx context.Context, db client.DBTX,
	orgUnitID, userID uuid.UUID,
	role string, effectiveTo time.Time, actorID uuid.UUID,
) error {
	result, err := db.ExecContext(ctx, `
		UPDATE org_unit_roles
		SET effective_to = $1,
		    is_primary   = false,
		    updated_at   = NOW(),
		    updated_by   = $2
		WHERE org_unit_id  = $3
		  AND user_id      = $4
		  AND role         = $5
		  AND effective_to IS NULL
	`, effectiveTo, actorID, orgUnitID, userID, role)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return hrErrors.ErrOrgUnitRoleNotFound
	}
	return nil
}

func (r *OrgUnitRepositoryImpl) GetRole(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID, role string) (*orgunit.OrgUnitRole, error) {
	const query = `
		SELECT org_unit_id, user_id, role, position_id, location_id,
		       is_primary, effective_from, effective_to,
		       created_by, updated_by, created_at, updated_at
		FROM org_unit_roles
		WHERE org_unit_id = $1 AND user_id = $2 AND role = $3
		ORDER BY effective_from DESC
		LIMIT 1
	`
	rows, err := db.QueryContext(ctx, query, orgUnitID, userID, role)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, hrErrors.ErrOrgUnitRoleNotFound
	}
	rle, err := scanOrgUnitRole(rows)
	if err != nil {
		return nil, fmt.Errorf("failed to scan role: %w", err)
	}
	return rle, nil
}

func (r *OrgUnitRepositoryImpl) GetUserRoles(ctx context.Context, db client.DBTX, userID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitRole, error) {
	conditions := []string{"user_id = $1"}
	params := []interface{}{userID}
	if onlyActive {
		conditions = append(conditions, "effective_to IS NULL")
	}
	where := "WHERE " + strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT org_unit_id, user_id, role, position_id, location_id,
		       is_primary, effective_from, effective_to,
		       created_by, updated_by, created_at, updated_at
		FROM org_unit_roles %s
		ORDER BY effective_from DESC
	`, where)

	rows, err := db.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	var roles []*orgunit.OrgUnitRole
	for rows.Next() {
		rle, err := scanOrgUnitRole(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, rle)
	}
	return roles, rows.Err()
}

func (r *OrgUnitRepositoryImpl) GetOrgUnitRoles(ctx context.Context, db client.DBTX, orgUnitID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitRole, error) {
	conditions := []string{"org_unit_id = $1"}
	params := []interface{}{orgUnitID}
	if onlyActive {
		conditions = append(conditions, "effective_to IS NULL")
	}
	where := "WHERE " + strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT org_unit_id, user_id, role, position_id, location_id,
		       is_primary, effective_from, effective_to,
		       created_by, updated_by, created_at, updated_at
		FROM org_unit_roles %s
		ORDER BY role, user_id
	`, where)

	rows, err := db.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get org unit roles: %w", err)
	}
	defer rows.Close()

	var roles []*orgunit.OrgUnitRole
	for rows.Next() {
		rle, err := scanOrgUnitRole(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, rle)
	}
	return roles, rows.Err()
}

// ============================================================
// SCAN HELPERS
// ============================================================

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanOrgUnitRow(row rowScanner) (*orgunit.OrgUnit, error) {
	var ou orgunit.OrgUnit
	var deptID, createdBy, updatedBy uuid.NullUUID
	var description sql.NullString

	err := row.Scan(
		&ou.OrgUnitID, &ou.CompanyID, &ou.OrgUnitType, &ou.Name, &description,
		&deptID, &ou.IsActive,
		&createdBy, &updatedBy, &ou.CreatedAt, &ou.UpdatedAt,
		&ou.LocationCount,
		&ou.MemberCount,
	)
	if err != nil {
		return nil, err
	}
	if description.Valid {
		ou.Description = &description.String
	}
	if deptID.Valid {
		ou.DepartmentID = &deptID.UUID
	}
	if createdBy.Valid {
		ou.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ou.UpdatedBy = &updatedBy.UUID
	}
	return &ou, nil
}

func scanOrgUnitRows(rows *sql.Rows) (*orgunit.OrgUnit, error) {
	return scanOrgUnitRow(rows)
}

// scanOrgUnitMember reads a row matching:
//
//	org_unit_id, user_id, location_id,
//	effective_from, effective_to,
//	created_by, updated_by, created_at, updated_at
func scanOrgUnitMember(rows *sql.Rows) (*orgunit.OrgUnitMember, error) {
	var m orgunit.OrgUnitMember
	var locID, createdBy, updatedBy uuid.NullUUID
	var effTo sql.NullTime

	if err := rows.Scan(
		&m.OrgUnitID, &m.UserID, &locID,
		&m.EffectiveFrom, &effTo,
		&createdBy, &updatedBy, &m.CreatedAt, &m.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if locID.Valid {
		m.LocationID = &locID.UUID
	}
	if effTo.Valid {
		m.EffectiveTo = &effTo.Time
	}
	if createdBy.Valid {
		m.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		m.UpdatedBy = &updatedBy.UUID
	}
	return &m, nil
}

// scanOrgUnitRole reads a row matching:
//
//	org_unit_id, user_id, role, position_id, location_id,
//	is_primary, effective_from, effective_to,
//	created_by, updated_by, created_at, updated_at
func scanOrgUnitRole(rows *sql.Rows) (*orgunit.OrgUnitRole, error) {
	var rle orgunit.OrgUnitRole
	var posID, locID, createdBy, updatedBy uuid.NullUUID
	var effTo sql.NullTime

	if err := rows.Scan(
		&rle.OrgUnitID, &rle.UserID, &rle.Role,
		&posID, &locID, &rle.IsPrimary,
		&rle.EffectiveFrom, &effTo,
		&createdBy, &updatedBy, &rle.CreatedAt, &rle.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if posID.Valid {
		rle.PositionID = &posID.UUID
	}
	if locID.Valid {
		rle.LocationID = &locID.UUID
	}
	if effTo.Valid {
		rle.EffectiveTo = &effTo.Time
	}
	if createdBy.Valid {
		rle.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		rle.UpdatedBy = &updatedBy.UUID
	}
	return &rle, nil
}

// ============================================================
// HEALTH
// ============================================================

func (r *OrgUnitRepositoryImpl) HealthCheck(ctx context.Context, db client.DBTX) error {
	if err := db.QueryRowContext(ctx, `SELECT 1`).Scan(new(int)); err != nil {
		return fmt.Errorf("org unit repository health check failed: %w", err)
	}
	return nil
}
