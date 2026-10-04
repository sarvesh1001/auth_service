package resolver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
)

type timezoneProvider struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewTimezoneProvider(pg *client.PostgresClient, logger *zap.Logger) TimezoneProvider {
	return &timezoneProvider{
		client: pg,
		logger: logger.Named("tz_provider"),
	}
}

func (p *timezoneProvider) ResolveTimezone(
	ctx context.Context,
	companyID uuid.UUID,
	positionID *uuid.UUID,
	workCenterCode *string,
	locationID *uuid.UUID,
) (string, error) {
	// Path 1: position walks everything
	if positionID != nil && *positionID != uuid.Nil {
		return p.fromPosition(ctx, companyID, *positionID, workCenterCode)
	}

	// Path 2: no position, walk from work center
	if workCenterCode != nil && *workCenterCode != "" {
		return p.fromWorkCenter(ctx, companyID, *workCenterCode, locationID)
	}

	// Path 3: no position, no WC, but a location
	if locationID != nil && *locationID != uuid.Nil {
		tz, err := p.fromLocation(ctx, companyID, *locationID)
		if err == nil && tz != "" {
			return tz, nil
		}
	}

	// Path 4: company default
	return p.fromCompany(ctx, companyID)
}

func (p *timezoneProvider) ResolveForPosition(
	ctx context.Context,
	companyID uuid.UUID,
	positionID uuid.UUID,
) (string, error) {
	return p.fromPosition(ctx, companyID, positionID, nil)
}

// fromPosition walks: position.location → position.work_center → company
func (p *timezoneProvider) fromPosition(
	ctx context.Context,
	companyID uuid.UUID,
	positionID uuid.UUID,
	fallbackWorkCenter *string,
) (string, error) {
	var locID sql.NullString
	var wcCode sql.NullString

	err := p.client.QueryRow(ctx, `
		SELECT location_id, work_center_code
		FROM positions
		WHERE company_id = $1 AND position_id = $2
	`, companyID, positionID).Scan(&locID, &wcCode)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Position row missing — treat as config bug, fall through
			p.logger.Warn("position not found for tz resolution",
				zap.String("company_id", companyID.String()),
				zap.String("position_id", positionID.String()),
			)
			if fallbackWorkCenter != nil && *fallbackWorkCenter != "" {
				return p.fromWorkCenter(ctx, companyID, *fallbackWorkCenter, nil)
			}
			return p.fromCompany(ctx, companyID)
		}
		return "", fmt.Errorf("fetch position for tz: %w", err)
	}

	// Priority 1: position's own location
	if locID.Valid && locID.String != "" {
		if lid, err := uuid.Parse(locID.String); err == nil {
			if tz, err := p.fromLocation(ctx, companyID, lid); err == nil && tz != "" {
				p.logger.Debug("tz resolved via position.location",
					zap.String("position_id", positionID.String()),
					zap.String("tz", tz),
				)
				return tz, nil
			}
		}
	}

	// Priority 2: position's work center (or caller-supplied override)
	wc := ""
	if wcCode.Valid {
		wc = wcCode.String
	}
	if wc == "" && fallbackWorkCenter != nil {
		wc = *fallbackWorkCenter
	}
	if wc != "" {
		return p.fromWorkCenter(ctx, companyID, wc, nil)
	}

	// Priority 3: company default
	return p.fromCompany(ctx, companyID)
}

// fromWorkCenter walks: work_center.timezone → work_center.location → company
func (p *timezoneProvider) fromWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	wcCode string,
	fallbackLocationID *uuid.UUID,
) (string, error) {
	var tz sql.NullString
	var locID sql.NullString

	err := p.client.QueryRow(ctx, `
		SELECT timezone, location_id
		FROM attendance.work_centers
		WHERE company_id = $1 AND work_center_code = $2
	`, companyID, wcCode).Scan(&tz, &locID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			p.logger.Warn("work center not found for tz resolution",
				zap.String("company_id", companyID.String()),
				zap.String("work_center_code", wcCode),
			)
			if fallbackLocationID != nil {
				if ltz, lerr := p.fromLocation(ctx, companyID, *fallbackLocationID); lerr == nil && ltz != "" {
					return ltz, nil
				}
			}
			return p.fromCompany(ctx, companyID)
		}
		return "", fmt.Errorf("fetch work center for tz: %w", err)
	}

	// Priority 1: work center's own tz
	if tz.Valid && tz.String != "" {
		p.logger.Debug("tz resolved via work_center.timezone",
			zap.String("work_center_code", wcCode),
			zap.String("tz", tz.String),
		)
		return tz.String, nil
	}

	// Priority 2: work center's location
	if locID.Valid && locID.String != "" {
		if lid, err := uuid.Parse(locID.String); err == nil {
			if ltz, err := p.fromLocation(ctx, companyID, lid); err == nil && ltz != "" {
				return ltz, nil
			}
		}
	}

	// Priority 3: fallback location
	if fallbackLocationID != nil && *fallbackLocationID != uuid.Nil {
		if ltz, err := p.fromLocation(ctx, companyID, *fallbackLocationID); err == nil && ltz != "" {
			return ltz, nil
		}
	}

	return p.fromCompany(ctx, companyID)
}

// fromLocation fetches locations.timezone. Returns ("", nil) when NULL.
func (p *timezoneProvider) fromLocation(
	ctx context.Context,
	companyID uuid.UUID,
	locationID uuid.UUID,
) (string, error) {
	var tz sql.NullString

	err := p.client.QueryRow(ctx, `
		SELECT timezone
		FROM locations
		WHERE company_id = $1 AND location_id = $2
	`, companyID, locationID).Scan(&tz)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("fetch location tz: %w", err)
	}

	if tz.Valid && tz.String != "" {
		p.logger.Debug("tz resolved via location.timezone",
			zap.String("location_id", locationID.String()),
			zap.String("tz", tz.String),
		)
		return tz.String, nil
	}
	return "", nil
}

// fromCompany fetches companies.default_timezone. Never returns empty.
func (p *timezoneProvider) fromCompany(ctx context.Context, companyID uuid.UUID) (string, error) {
	var tz sql.NullString

	err := p.client.QueryRow(ctx, `
		SELECT default_timezone
		FROM companies
		WHERE company_id = $1
	`, companyID).Scan(&tz)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			p.logger.Warn("company not found, defaulting tz to UTC",
				zap.String("company_id", companyID.String()),
			)
			return "UTC", nil
		}
		return "", fmt.Errorf("fetch company tz: %w", err)
	}

	if tz.Valid && tz.String != "" {
		p.logger.Debug("tz resolved via company.default_timezone",
			zap.String("company_id", companyID.String()),
			zap.String("tz", tz.String),
		)
		return tz.String, nil
	}

	p.logger.Warn("company has no default_timezone, using UTC",
		zap.String("company_id", companyID.String()),
	)
	return "UTC", nil
}
