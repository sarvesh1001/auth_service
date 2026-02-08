package repository

import (
	"context"
	"database/sql"
	"fmt"

	"auth-service/internal/client"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type deviceHeartbeatRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewDeviceHeartbeatRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) DeviceHeartbeatRepository {
	return &deviceHeartbeatRepository{
		client: postgresClient,
		logger: logger,
	}
}

func (r *deviceHeartbeatRepository) Insert(
	ctx context.Context,
	hb *DeviceHeartbeat,
) error {
	query := `
		INSERT INTO attendance_device_heartbeats (
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
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
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
		r.logger.Error("Failed to insert device heartbeat",
			util.String("heartbeat_id", hb.HeartbeatID.String()),
			util.String("company_id", hb.CompanyID.String()),
			util.String("device_id", hb.DeviceID),
			util.String("source_type", hb.SourceType),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to insert device heartbeat: %w", err)
	}

	return nil
}

func (r *deviceHeartbeatRepository) GetLatestByDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) (*DeviceHeartbeat, error) {
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
		FROM attendance_device_heartbeats
		WHERE company_id = $1
		  AND device_id = $2
		ORDER BY created_at DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, deviceID)

	var hb DeviceHeartbeat
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

		r.logger.Error("Failed to get latest device heartbeat",
			util.String("company_id", companyID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get latest device heartbeat: %w", err)
	}

	return &hb, nil
}
