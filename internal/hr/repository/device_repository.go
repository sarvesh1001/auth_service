package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Repository errors
var (
	ErrDeviceNotFound = errors.New("device not found")
)

type AttendanceDeviceRepository interface {
	// Device Retrieval
	GetActiveDevice(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
	) (*attendance.AttendanceDevice, error)

	GetDeviceByCode(
		ctx context.Context,
		companyID uuid.UUID,
		deviceCode string,
	) (*attendance.AttendanceDevice, error)

	GetDevicesByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		activeOnly bool,
	) ([]*attendance.AttendanceDevice, error)

	GetDevicesByWorkCenter(
		ctx context.Context,
		companyID uuid.UUID,
		workCenterCode string,
		activeOnly bool,
	) ([]*attendance.AttendanceDevice, error)

	GetDevicesBySourceType(
		ctx context.Context,
		companyID uuid.UUID,
		sourceType string,
		activeOnly bool,
	) ([]*attendance.AttendanceDevice, error)

	// Device Management
	CreateDevice(
		ctx context.Context,
		device *attendance.AttendanceDevice,
	) error

	UpdateDevice(
		ctx context.Context,
		device *attendance.AttendanceDevice,
	) error

	UpdateLastSeen(
		ctx context.Context,
		deviceID string,
	) error

	DeactivateDevice(
		ctx context.Context,
		deviceID string,
	) error

	ActivateDevice(
		ctx context.Context,
		deviceID string,
	) error

	UpdateDeviceMetadata(
		ctx context.Context,
		deviceID string,
		metadata map[string]interface{},
	) error

	// Device Counts and Stats
	CountDevicesByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		activeOnly bool,
	) (int, error)

	GetDeviceStatistics(
		ctx context.Context,
		companyID uuid.UUID,
	) (*DeviceStatistics, error)

	HealthCheck(ctx context.Context) error
}

type DeviceStatistics struct {
	TotalDevices      int            `json:"total_devices"`
	ActiveDevices     int            `json:"active_devices"`
	TrustedDevices    int            `json:"trusted_devices"`
	BySourceType      map[string]int `json:"by_source_type"`
	ByWorkCenter      map[string]int `json:"by_work_center"`
	AverageUptimeDays float64        `json:"average_uptime_days"`
}

type attendanceDeviceRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewAttendanceDeviceRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) AttendanceDeviceRepository {
	return &attendanceDeviceRepository{
		client: postgresClient,
		logger: logger,
	}
}

// GetActiveDevice retrieves an active device by ID and company
func (r *attendanceDeviceRepository) GetActiveDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) (*attendance.AttendanceDevice, error) {
	query := `
		SELECT
			device_id,
			company_id,
			source_type,
			device_code,
			device_name,
			manufacturer,
			model,
			work_center_code,
			location_id,
			ip_address,
			mac_address,
			is_active,
			is_trusted,
			last_seen_at,
			installed_at,
			metadata,
			created_at
		FROM attendance_devices
		WHERE device_id = $1
		  AND company_id = $2
		  AND is_active = true
	`

	row := r.client.QueryRow(ctx, query, deviceID, companyID)
	return r.scanDevice(row)
}

// GetDeviceByCode retrieves a device by company and device code
func (r *attendanceDeviceRepository) GetDeviceByCode(
	ctx context.Context,
	companyID uuid.UUID,
	deviceCode string,
) (*attendance.AttendanceDevice, error) {
	query := `
		SELECT
			device_id,
			company_id,
			source_type,
			device_code,
			device_name,
			manufacturer,
			model,
			work_center_code,
			location_id,
			ip_address,
			mac_address,
			is_active,
			is_trusted,
			last_seen_at,
			installed_at,
			metadata,
			created_at
		FROM attendance_devices
		WHERE company_id = $1
		  AND device_code = $2
	`

	row := r.client.QueryRow(ctx, query, companyID, deviceCode)
	return r.scanDevice(row)
}

// GetDevicesByCompany retrieves all devices for a company
func (r *attendanceDeviceRepository) GetDevicesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*attendance.AttendanceDevice, error) {
	query := `
		SELECT
			device_id,
			company_id,
			source_type,
			device_code,
			device_name,
			manufacturer,
			model,
			work_center_code,
			location_id,
			ip_address,
			mac_address,
			is_active,
			is_trusted,
			last_seen_at,
			installed_at,
			metadata,
			created_at
		FROM attendance_devices
		WHERE company_id = $1
		ORDER BY created_at DESC
	`

	if activeOnly {
		query = `
			SELECT
				device_id,
				company_id,
				source_type,
				device_code,
				device_name,
				manufacturer,
				model,
				work_center_code,
				location_id,
				ip_address,
				mac_address,
				is_active,
				is_trusted,
				last_seen_at,
				installed_at,
				metadata,
				created_at
			FROM attendance_devices
			WHERE company_id = $1
			  AND is_active = true
			ORDER BY created_at DESC
		`
	}

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to get devices by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

// GetDevicesByWorkCenter retrieves devices by work center
func (r *attendanceDeviceRepository) GetDevicesByWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	activeOnly bool,
) ([]*attendance.AttendanceDevice, error) {
	query := `
		SELECT
			device_id,
			company_id,
			source_type,
			device_code,
			device_name,
			manufacturer,
			model,
			work_center_code,
			location_id,
			ip_address,
			mac_address,
			is_active,
			is_trusted,
			last_seen_at,
			installed_at,
			metadata,
			created_at
		FROM attendance_devices
		WHERE company_id = $1
		  AND work_center_code = $2
		ORDER BY device_name
	`

	if activeOnly {
		query = `
			SELECT
				device_id,
				company_id,
				source_type,
				device_code,
				device_name,
				manufacturer,
				model,
				work_center_code,
				location_id,
				ip_address,
				mac_address,
				is_active,
				is_trusted,
				last_seen_at,
				installed_at,
				metadata,
				created_at
			FROM attendance_devices
			WHERE company_id = $1
			  AND work_center_code = $2
			  AND is_active = true
			ORDER BY device_name
		`
	}

	rows, err := r.client.Query(ctx, query, companyID, workCenterCode)
	if err != nil {
		r.logger.Error("Failed to get devices by work center",
			util.String("company_id", companyID.String()),
			util.String("work_center_code", workCenterCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

// GetDevicesBySourceType retrieves devices by source type
func (r *attendanceDeviceRepository) GetDevicesBySourceType(
	ctx context.Context,
	companyID uuid.UUID,
	sourceType string,
	activeOnly bool,
) ([]*attendance.AttendanceDevice, error) {
	query := `
		SELECT
			device_id,
			company_id,
			source_type,
			device_code,
			device_name,
			manufacturer,
			model,
			work_center_code,
			location_id,
			ip_address,
			mac_address,
			is_active,
			is_trusted,
			last_seen_at,
			installed_at,
			metadata,
			created_at
		FROM attendance_devices
		WHERE company_id = $1
		  AND source_type = $2
		ORDER BY device_name
	`

	if activeOnly {
		query = `
			SELECT
				device_id,
				company_id,
				source_type,
				device_code,
				device_name,
				manufacturer,
				model,
				work_center_code,
				location_id,
				ip_address,
				mac_address,
				is_active,
				is_trusted,
				last_seen_at,
				installed_at,
				metadata,
				created_at
			FROM attendance_devices
			WHERE company_id = $1
			  AND source_type = $2
			  AND is_active = true
			ORDER BY device_name
		`
	}

	rows, err := r.client.Query(ctx, query, companyID, sourceType)
	if err != nil {
		r.logger.Error("Failed to get devices by source type",
			util.String("company_id", companyID.String()),
			util.String("source_type", sourceType),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

// CreateDevice creates a new attendance device
func (r *attendanceDeviceRepository) CreateDevice(
	ctx context.Context,
	device *attendance.AttendanceDevice,
) error {
	query := `
		INSERT INTO attendance_devices (
			device_id,
			company_id,
			source_type,
			device_code,
			device_name,
			manufacturer,
			model,
			work_center_code,
			location_id,
			ip_address,
			mac_address,
			is_active,
			is_trusted,
			last_seen_at,
			installed_at,
			metadata,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`

	if device.DeviceID == "" {
		return fmt.Errorf("device ID is required")
	}

	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now().UTC()
	}

	metadataJSON, _ := json.Marshal(device.Metadata)

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
		r.logger.Error("Failed to create attendance device",
			util.String("device_id", device.DeviceID),
			util.String("company_id", device.CompanyID.String()),
			util.String("device_code", device.DeviceCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance device: %w", err)
	}

	return nil
}

// UpdateDevice updates an existing device
func (r *attendanceDeviceRepository) UpdateDevice(
	ctx context.Context,
	device *attendance.AttendanceDevice,
) error {
	query := `
		UPDATE attendance_devices SET
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
		WHERE device_id = $15
		  AND company_id = $16
	`

	metadataJSON, _ := json.Marshal(device.Metadata)

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
		r.logger.Error("Failed to update attendance device",
			util.String("device_id", device.DeviceID),
			util.String("company_id", device.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update attendance device: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance device not found")
	}

	return nil
}

// UpdateLastSeen updates the last seen timestamp for a device
func (r *attendanceDeviceRepository) UpdateLastSeen(
	ctx context.Context,
	deviceID string,
) error {
	query := `
		UPDATE attendance_devices
		SET last_seen_at = $1
		WHERE device_id = $2
	`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), deviceID)
	if err != nil {
		r.logger.Error("Failed to update device last seen",
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to update device last seen: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance device not found")
	}

	return nil
}

// DeactivateDevice marks a device as inactive
func (r *attendanceDeviceRepository) DeactivateDevice(
	ctx context.Context,
	deviceID string,
) error {
	query := `
		UPDATE attendance_devices
		SET is_active = false
		WHERE device_id = $1
	`

	result, err := r.client.Exec(ctx, query, deviceID)
	if err != nil {
		r.logger.Error("Failed to deactivate device",
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to deactivate device: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance device not found")
	}

	return nil
}

// ActivateDevice marks a device as active
func (r *attendanceDeviceRepository) ActivateDevice(
	ctx context.Context,
	deviceID string,
) error {
	query := `
		UPDATE attendance_devices
		SET is_active = true
		WHERE device_id = $1
	`

	result, err := r.client.Exec(ctx, query, deviceID)
	if err != nil {
		r.logger.Error("Failed to activate device",
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to activate device: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance device not found")
	}

	return nil
}

// UpdateDeviceMetadata updates only the metadata of a device
func (r *attendanceDeviceRepository) UpdateDeviceMetadata(
	ctx context.Context,
	deviceID string,
	metadata map[string]interface{},
) error {
	query := `
		UPDATE attendance_devices
		SET metadata = $1
		WHERE device_id = $2
	`

	metadataJSON, _ := json.Marshal(metadata)

	result, err := r.client.Exec(ctx, query, metadataJSON, deviceID)
	if err != nil {
		r.logger.Error("Failed to update device metadata",
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to update device metadata: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance device not found")
	}

	return nil
}

// CountDevicesByCompany counts devices for a company
func (r *attendanceDeviceRepository) CountDevicesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM attendance_devices
		WHERE company_id = $1
	`

	if activeOnly {
		query = `
			SELECT COUNT(*)
			FROM attendance_devices
			WHERE company_id = $1
			  AND is_active = true
		`
	}

	row := r.client.QueryRow(ctx, query, companyID)
	var count int
	err := row.Scan(&count)

	if err != nil {
		r.logger.Error("Failed to count devices by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("failed to count devices: %w", err)
	}

	return count, nil
}

// GetDeviceStatistics gets statistics about devices
func (r *attendanceDeviceRepository) GetDeviceStatistics(
	ctx context.Context,
	companyID uuid.UUID,
) (*DeviceStatistics, error) {
	// Get basic counts
	totalQuery := `
		SELECT
			COUNT(*) as total,
			COUNT(CASE WHEN is_active = true THEN 1 END) as active,
			COUNT(CASE WHEN is_trusted = true THEN 1 END) as trusted,
			source_type,
			COUNT(*) as count
		FROM attendance_devices
		WHERE company_id = $1
		GROUP BY source_type
	`

	rows, err := r.client.Query(ctx, totalQuery, companyID)
	if err != nil {
		r.logger.Error("Failed to get device statistics",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get device statistics: %w", err)
	}
	defer rows.Close()

	stats := &DeviceStatistics{
		BySourceType: make(map[string]int),
		ByWorkCenter: make(map[string]int),
	}

	for rows.Next() {
		var sourceType string
		var sourceCount int
		err := rows.Scan(
			&stats.TotalDevices,
			&stats.ActiveDevices,
			&stats.TrustedDevices,
			&sourceType,
			&sourceCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan device stats: %w", err)
		}
		stats.BySourceType[sourceType] = sourceCount
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	// Get work center distribution
	workCenterQuery := `
		SELECT work_center_code, COUNT(*)
		FROM attendance_devices
		WHERE company_id = $1
		  AND work_center_code IS NOT NULL
		  AND is_active = true
		GROUP BY work_center_code
	`

	workCenterRows, err := r.client.Query(ctx, workCenterQuery, companyID)
	if err == nil {
		defer workCenterRows.Close()
		for workCenterRows.Next() {
			var workCenterCode string
			var count int
			err := workCenterRows.Scan(&workCenterCode, &count)
			if err == nil {
				stats.ByWorkCenter[workCenterCode] = count
			}
		}
	}

	// Calculate average uptime
	uptimeQuery := `
		SELECT AVG(EXTRACT(EPOCH FROM (NOW() - installed_at)) / 86400.0)
		FROM attendance_devices
		WHERE company_id = $1
		  AND installed_at IS NOT NULL
		  AND is_active = true
	`

	row := r.client.QueryRow(ctx, uptimeQuery, companyID)
	var avgUptime sql.NullFloat64
	err = row.Scan(&avgUptime)
	if err == nil && avgUptime.Valid {
		stats.AverageUptimeDays = avgUptime.Float64
	}

	return stats, nil
}

// HealthCheck performs a health check on the repository
func (r *attendanceDeviceRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance_devices LIMIT 1`
	var result int
	row := r.client.QueryRow(ctx, query)
	err := row.Scan(&result)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		r.logger.Error("Device repository health check failed",
			util.ErrorField(err))
		return fmt.Errorf("device repository health check failed: %w", err)
	}
	return nil
}

// Helper method to scan a single device row
func (r *attendanceDeviceRepository) scanDevice(row *sql.Row) (*attendance.AttendanceDevice, error) {
	var device attendance.AttendanceDevice
	var metadataJSON []byte

	err := row.Scan(
		&device.DeviceID,
		&device.CompanyID,
		&device.SourceType,
		&device.DeviceCode,
		&device.DeviceName,
		&device.Manufacturer,
		&device.Model,
		&device.WorkCenterCode,
		&device.LocationID,
		&device.IPAddress,
		&device.MacAddress,
		&device.IsActive,
		&device.IsTrusted,
		&device.LastSeenAt,
		&device.InstalledAt,
		&metadataJSON,
		&device.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan device: %w", err)
	}

	if len(metadataJSON) > 0 {
		err = json.Unmarshal(metadataJSON, &device.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &device, nil
}

// Helper method to scan multiple device rows
func (r *attendanceDeviceRepository) scanDevices(rows *sql.Rows) ([]*attendance.AttendanceDevice, error) {
	var devices []*attendance.AttendanceDevice

	for rows.Next() {
		var device attendance.AttendanceDevice
		var metadataJSON []byte

		err := rows.Scan(
			&device.DeviceID,
			&device.CompanyID,
			&device.SourceType,
			&device.DeviceCode,
			&device.DeviceName,
			&device.Manufacturer,
			&device.Model,
			&device.WorkCenterCode,
			&device.LocationID,
			&device.IPAddress,
			&device.MacAddress,
			&device.IsActive,
			&device.IsTrusted,
			&device.LastSeenAt,
			&device.InstalledAt,
			&metadataJSON,
			&device.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}

		if len(metadataJSON) > 0 {
			err = json.Unmarshal(metadataJSON, &device.Metadata)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		devices = append(devices, &device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return devices, nil
}
