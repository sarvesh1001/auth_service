package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type heartbeatRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewDeviceHeartbeatRepository creates a new heartbeat repository
func NewDeviceHeartbeatRepository(pg *client.PostgresClient, logger *zap.Logger) repository.DeviceHeartbeatRepository {
	return &heartbeatRepository{
		client: pg,
		logger: logger.Named("heartbeat_repo"),
	}
}

func (r *heartbeatRepository) Insert(ctx context.Context, hb *models.DeviceHeartbeat) error {
	query := `
		INSERT INTO attendance.attendance_device_heartbeats (
			heartbeat_id,
			company_id,
			device_id,
			source_type,
			device_time,
			server_time,
			firmware_version,
			ip_address,
			status,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := r.client.Exec(ctx, query,
		hb.HeartbeatID,
		hb.CompanyID,
		hb.DeviceID,
		hb.SourceType,
		hb.DeviceTime,
		hb.ServerTime,
		hb.FirmwareVersion,
		hb.IPAddress,
		hb.Status,
		hb.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to insert device heartbeat",
			zap.String("heartbeat_id", hb.HeartbeatID.String()),
			zap.String("company_id", hb.CompanyID.String()),
			zap.String("device_id", hb.DeviceID),
			zap.Error(err),
		)
		return fmt.Errorf("insert heartbeat: %w", err)
	}
	return nil
}

func (r *heartbeatRepository) GetLatestByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.DeviceHeartbeat, error) {
	query := `
		SELECT
			heartbeat_id,
			company_id,
			device_id,
			source_type,
			device_time,
			server_time,
			firmware_version,
			ip_address,
			status,
			created_at
		FROM attendance.attendance_device_heartbeats
		WHERE company_id = $1
		  AND device_id = $2
		ORDER BY created_at DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, deviceID)

	var hb models.DeviceHeartbeat
	err := row.Scan(
		&hb.HeartbeatID,
		&hb.CompanyID,
		&hb.DeviceID,
		&hb.SourceType,
		&hb.DeviceTime,
		&hb.ServerTime,
		&hb.FirmwareVersion,
		&hb.IPAddress,
		&hb.Status,
		&hb.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get latest heartbeat",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("get latest heartbeat: %w", err)
	}
	return &hb, nil
}
