package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type deviceRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewDeviceRepository creates a new device repository
func NewDeviceRepository(pg *client.PostgresClient, logger *zap.Logger) repository.DeviceRepository {
	return &deviceRepository{
		client: pg,
		logger: logger.Named("device_repo"),
	}
}

func (r *deviceRepository) GetDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.AttendanceDevice, error) {
	query := `
		SELECT
			device_id, company_id, source_type, device_code,
			device_name, manufacturer, model,
			work_center_code, location_id,
			ip_address, mac_address,
			is_active, is_trusted,
			last_seen_at, installed_at,
			metadata, created_at
		FROM attendance.attendance_devices
		WHERE device_id = $1 AND company_id = $2
	`
	row := r.client.QueryRow(ctx, query, deviceID, companyID)
	return r.scanDevice(row)
}

func (r *deviceRepository) GetActiveDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.AttendanceDevice, error) {
	query := `
		SELECT
			device_id, company_id, source_type, device_code,
			device_name, manufacturer, model,
			work_center_code, location_id,
			ip_address, mac_address,
			is_active, is_trusted,
			last_seen_at, installed_at,
			metadata, created_at
		FROM attendance.attendance_devices
		WHERE device_id = $1 AND company_id = $2 AND is_active = true
	`
	row := r.client.QueryRow(ctx, query, deviceID, companyID)
	return r.scanDevice(row)
}

func (r *deviceRepository) GetDeviceByCode(ctx context.Context, companyID uuid.UUID, deviceCode string) (*models.AttendanceDevice, error) {
	query := `
		SELECT
			device_id, company_id, source_type, device_code,
			device_name, manufacturer, model,
			work_center_code, location_id,
			ip_address, mac_address,
			is_active, is_trusted,
			last_seen_at, installed_at,
			metadata, created_at
		FROM attendance.attendance_devices
		WHERE company_id = $1 AND device_code = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, deviceCode)
	return r.scanDevice(row)
}

func (r *deviceRepository) GetDevicesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendanceDevice, error) {
	query := `
		SELECT
			device_id, company_id, source_type, device_code,
			device_name, manufacturer, model,
			work_center_code, location_id,
			ip_address, mac_address,
			is_active, is_trusted,
			last_seen_at, installed_at,
			metadata, created_at
		FROM attendance.attendance_devices
		WHERE company_id = $1
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY created_at DESC"

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("query devices: %w", err)
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

func (r *deviceRepository) GetDevicesByWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string, activeOnly bool) ([]*models.AttendanceDevice, error) {
	query := `
		SELECT
			device_id, company_id, source_type, device_code,
			device_name, manufacturer, model,
			work_center_code, location_id,
			ip_address, mac_address,
			is_active, is_trusted,
			last_seen_at, installed_at,
			metadata, created_at
		FROM attendance.attendance_devices
		WHERE company_id = $1 AND work_center_code = $2
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY device_name"

	rows, err := r.client.Query(ctx, query, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("query devices by work center: %w", err)
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

func (r *deviceRepository) GetDevicesBySourceType(ctx context.Context, companyID uuid.UUID, sourceType string, activeOnly bool) ([]*models.AttendanceDevice, error) {
	query := `
		SELECT
			device_id, company_id, source_type, device_code,
			device_name, manufacturer, model,
			work_center_code, location_id,
			ip_address, mac_address,
			is_active, is_trusted,
			last_seen_at, installed_at,
			metadata, created_at
		FROM attendance.attendance_devices
		WHERE company_id = $1 AND source_type = $2
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY device_name"

	rows, err := r.client.Query(ctx, query, companyID, sourceType)
	if err != nil {
		return nil, fmt.Errorf("query devices by source type: %w", err)
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

func (r *deviceRepository) CreateDevice(ctx context.Context, device *models.AttendanceDevice) error {
	if device.DeviceID == "" {
		return errors.New("device_id is required")
	}
	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now().UTC()
	}
	metadataJSON, _ := json.Marshal(device.Metadata)

	query := `
		INSERT INTO attendance.attendance_devices (
			device_id, company_id, source_type, device_code,
			device_name, manufacturer, model,
			work_center_code, location_id,
			ip_address, mac_address,
			is_active, is_trusted,
			last_seen_at, installed_at,
			metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := r.client.Exec(ctx, query,
		device.DeviceID,
		device.CompanyID,
		device.SourceType,
		device.DeviceCode,
		device.DeviceName,
		device.Manufacturer,
		device.Model,
		device.WorkCenterCode,
		device.LocationID,
		device.IPAddress,
		device.MacAddress,
		device.IsActive,
		device.IsTrusted,
		device.LastSeenAt,
		device.InstalledAt,
		metadataJSON,
		device.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create device: %w", err)
	}
	return nil
}

func (r *deviceRepository) UpdateDevice(ctx context.Context, device *models.AttendanceDevice) error {
	metadataJSON, _ := json.Marshal(device.Metadata)

	query := `
		UPDATE attendance.attendance_devices
		SET
			source_type = $1,
			device_code = $2,
			device_name = $3,
			manufacturer = $4,
			model = $5,
			work_center_code = $6,
			location_id = $7,
			ip_address = $8,
			mac_address = $9,
			is_active = $10,
			is_trusted = $11,
			last_seen_at = $12,
			installed_at = $13,
			metadata = $14
		WHERE device_id = $15 AND company_id = $16
	`
	result, err := r.client.Exec(ctx, query,
		device.SourceType,
		device.DeviceCode,
		device.DeviceName,
		device.Manufacturer,
		device.Model,
		device.WorkCenterCode,
		device.LocationID,
		device.IPAddress,
		device.MacAddress,
		device.IsActive,
		device.IsTrusted,
		device.LastSeenAt,
		device.InstalledAt,
		metadataJSON,
		device.DeviceID,
		device.CompanyID,
	)
	if err != nil {
		return fmt.Errorf("update device: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("device not found")
	}
	return nil
}

func (r *deviceRepository) UpdateLastSeen(ctx context.Context, deviceID string) error {
	query := `
		UPDATE attendance.attendance_devices
		SET last_seen_at = $1
		WHERE device_id = $2
	`
	result, err := r.client.Exec(ctx, query, time.Now().UTC(), deviceID)
	if err != nil {
		return fmt.Errorf("update last seen: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("device not found")
	}
	return nil
}

func (r *deviceRepository) DeactivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	query := `
		UPDATE attendance.attendance_devices
		SET is_active = false
		WHERE device_id = $1 AND company_id = $2
	`
	result, err := r.client.Exec(ctx, query, deviceID, companyID)
	if err != nil {
		return fmt.Errorf("deactivate device: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("device not found")
	}
	return nil
}

func (r *deviceRepository) ActivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	query := `
		UPDATE attendance.attendance_devices
		SET is_active = true
		WHERE device_id = $1 AND company_id = $2
	`
	result, err := r.client.Exec(ctx, query, deviceID, companyID)
	if err != nil {
		return fmt.Errorf("activate device: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("device not found")
	}
	return nil
}

func (r *deviceRepository) MarkAsTrusted(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	query := `
		UPDATE attendance.attendance_devices
		SET is_trusted = true
		WHERE device_id = $1 AND company_id = $2
	`
	result, err := r.client.Exec(ctx, query, deviceID, companyID)
	if err != nil {
		return fmt.Errorf("mark trusted: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("device not found")
	}
	return nil
}

func (r *deviceRepository) RevokeTrust(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	query := `
		UPDATE attendance.attendance_devices
		SET is_trusted = false
		WHERE device_id = $1 AND company_id = $2
	`
	result, err := r.client.Exec(ctx, query, deviceID, companyID)
	if err != nil {
		return fmt.Errorf("revoke trust: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("device not found")
	}
	return nil
}

func (r *deviceRepository) UpdateDeviceMetadata(ctx context.Context, deviceID string, metadata map[string]interface{}) error {
	metadataJSON, _ := json.Marshal(metadata)
	query := `
		UPDATE attendance.attendance_devices
		SET metadata = $1
		WHERE device_id = $2
	`
	result, err := r.client.Exec(ctx, query, metadataJSON, deviceID)
	if err != nil {
		return fmt.Errorf("update metadata: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("device not found")
	}
	return nil
}

func (r *deviceRepository) CountDevicesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM attendance.attendance_devices
		WHERE company_id = $1
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	var count int
	err := r.client.QueryRow(ctx, query, companyID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count devices: %w", err)
	}
	return count, nil
}

func (r *deviceRepository) GetDeviceStatistics(ctx context.Context, companyID uuid.UUID) (*repository.DeviceStatistics, error) {
	stats := &repository.DeviceStatistics{
		BySourceType: make(map[string]int),
		ByWorkCenter: make(map[string]int),
	}

	// Total, active, trusted
	query1 := `
		SELECT
			COUNT(*) AS total,
			COUNT(CASE WHEN is_active THEN 1 END) AS active,
			COUNT(CASE WHEN is_trusted THEN 1 END) AS trusted
		FROM attendance.attendance_devices
		WHERE company_id = $1
	`
	err := r.client.QueryRow(ctx, query1, companyID).Scan(
		&stats.TotalDevices,
		&stats.ActiveDevices,
		&stats.TrustedDevices,
	)
	if err != nil {
		return nil, fmt.Errorf("fetch device stats: %w", err)
	}

	// By source type
	query2 := `
		SELECT source_type, COUNT(*)
		FROM attendance.attendance_devices
		WHERE company_id = $1
		GROUP BY source_type
	`
	rows, err := r.client.Query(ctx, query2, companyID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var st string
			var cnt int
			if err := rows.Scan(&st, &cnt); err == nil {
				stats.BySourceType[st] = cnt
			}
		}
	}

	// By work center (only active)
	query3 := `
		SELECT work_center_code, COUNT(*)
		FROM attendance.attendance_devices
		WHERE company_id = $1 AND is_active = true AND work_center_code IS NOT NULL
		GROUP BY work_center_code
	`
	rows2, err := r.client.Query(ctx, query3, companyID)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var wc string
			var cnt int
			if err := rows2.Scan(&wc, &cnt); err == nil {
				stats.ByWorkCenter[wc] = cnt
			}
		}
	}

	// Average uptime in days
	query4 := `
		SELECT AVG(EXTRACT(EPOCH FROM (COALESCE(last_seen_at, NOW()) - COALESCE(installed_at, created_at))) / 86400.0)
		FROM attendance.attendance_devices
		WHERE company_id = $1 AND is_active = true
	`
	var avg sql.NullFloat64
	err = r.client.QueryRow(ctx, query4, companyID).Scan(&avg)
	if err == nil && avg.Valid {
		stats.AverageUptimeDays = avg.Float64
	}

	return stats, nil
}

func (r *deviceRepository) HealthCheck(ctx context.Context) error {
	var one int
	query := `SELECT 1 FROM attendance.attendance_devices LIMIT 1`
	err := r.client.QueryRow(ctx, query).Scan(&one)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

// ----- helper scan functions -----

func (r *deviceRepository) scanDevice(row *sql.Row) (*models.AttendanceDevice, error) {
	var dev models.AttendanceDevice
	var metadataJSON []byte
	var deviceName, manufacturer, model, workCenterCode, ipAddress, macAddress sql.NullString
	var locationID sql.NullString
	var lastSeenAt, installedAt sql.NullTime

	err := row.Scan(
		&dev.DeviceID,
		&dev.CompanyID,
		&dev.SourceType,
		&dev.DeviceCode,
		&deviceName,
		&manufacturer,
		&model,
		&workCenterCode,
		&locationID,
		&ipAddress,
		&macAddress,
		&dev.IsActive,
		&dev.IsTrusted,
		&lastSeenAt,
		&installedAt,
		&metadataJSON,
		&dev.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan device: %w", err)
	}

	if deviceName.Valid {
		dev.DeviceName = &deviceName.String
	}
	if manufacturer.Valid {
		dev.Manufacturer = &manufacturer.String
	}
	if model.Valid {
		dev.Model = &model.String
	}
	if workCenterCode.Valid {
		dev.WorkCenterCode = &workCenterCode.String
	}
	if locationID.Valid && locationID.String != "" {
		if id, err := uuid.Parse(locationID.String); err == nil {
			dev.LocationID = &id
		}
	}
	if ipAddress.Valid {
		dev.IPAddress = &ipAddress.String
	}
	if macAddress.Valid {
		dev.MacAddress = &macAddress.String
	}
	if lastSeenAt.Valid {
		dev.LastSeenAt = &lastSeenAt.Time
	}
	if installedAt.Valid {
		dev.InstalledAt = &installedAt.Time
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &dev.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &dev, nil
}

func (r *deviceRepository) scanDevices(rows *sql.Rows) ([]*models.AttendanceDevice, error) {
	var devices []*models.AttendanceDevice
	for rows.Next() {
		var dev models.AttendanceDevice
		var metadataJSON []byte
		var deviceName, manufacturer, model, workCenterCode, ipAddress, macAddress sql.NullString
		var locationID sql.NullString
		var lastSeenAt, installedAt sql.NullTime

		err := rows.Scan(
			&dev.DeviceID,
			&dev.CompanyID,
			&dev.SourceType,
			&dev.DeviceCode,
			&deviceName,
			&manufacturer,
			&model,
			&workCenterCode,
			&locationID,
			&ipAddress,
			&macAddress,
			&dev.IsActive,
			&dev.IsTrusted,
			&lastSeenAt,
			&installedAt,
			&metadataJSON,
			&dev.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		// fill nullables as above...
		if deviceName.Valid {
			dev.DeviceName = &deviceName.String
		}
		if manufacturer.Valid {
			dev.Manufacturer = &manufacturer.String
		}
		if model.Valid {
			dev.Model = &model.String
		}
		if workCenterCode.Valid {
			dev.WorkCenterCode = &workCenterCode.String
		}
		if locationID.Valid && locationID.String != "" {
			if id, err := uuid.Parse(locationID.String); err == nil {
				dev.LocationID = &id
			}
		}
		if ipAddress.Valid {
			dev.IPAddress = &ipAddress.String
		}
		if macAddress.Valid {
			dev.MacAddress = &macAddress.String
		}
		if lastSeenAt.Valid {
			dev.LastSeenAt = &lastSeenAt.Time
		}
		if installedAt.Valid {
			dev.InstalledAt = &installedAt.Time
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &dev.Metadata); err != nil {
				return nil, fmt.Errorf("unmarshal metadata: %w", err)
			}
		}
		devices = append(devices, &dev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return devices, nil
}
