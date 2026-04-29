package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
)

type PeriodLockService interface {
	LockPeriod(ctx context.Context, companyID uuid.UUID, fiscalYear, period int, lockedBy *uuid.UUID, reason string) error
	UnlockPeriod(ctx context.Context, companyID uuid.UUID, fiscalYear, period int, unlockedBy *uuid.UUID, reason string) error
	IsPeriodLocked(ctx context.Context, companyID uuid.UUID, fiscalYear, period int) (bool, error)
	GetPeriodLock(ctx context.Context, companyID uuid.UUID, fiscalYear, period int) (*models.PeriodLock, error)
	ListPeriodLocks(ctx context.Context, filter repository.PeriodLockFilter, pagination Pagination, sort repository.Sort) ([]*models.PeriodLock, int64, error)
	ListLockedPeriods(ctx context.Context, companyID uuid.UUID) (map[[2]int]string, error)
}

type periodLockService struct {
	repo         repository.PeriodLockRepository
	pgClient     *client.PostgresClient
	auditService *audit.AuditService
	logger       *zap.Logger
}

func NewPeriodLockService(
	repo repository.PeriodLockRepository,
	pgClient *client.PostgresClient,
	auditService *audit.AuditService,
	logger *zap.Logger,
) PeriodLockService {
	return &periodLockService{
		repo:         repo,
		pgClient:     pgClient,
		auditService: auditService,
		logger:       logger.Named("period_lock_service"),
	}
}

// LockPeriod – uses pgClient.DB (write operation)
func (s *periodLockService) LockPeriod(ctx context.Context, companyID uuid.UUID, fiscalYear, period int, lockedBy *uuid.UUID, reason string) error {
	// ✅ FIX: pass pgClient.DB instead of nil
	if err := s.repo.LockPeriod(ctx, s.pgClient.DB, companyID, fiscalYear, period, lockedBy, reason); err != nil {
		return fmt.Errorf("lock period: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "accounting", "lock", "period_lock",
			nil, "user", lockedBy, nil, nil, map[string]interface{}{
				"fiscal_year": fiscalYear,
				"period":      period,
				"reason":      reason,
			})
	}
	s.logger.Info("period locked", zap.String("company", companyID.String()), zap.Int("fy", fiscalYear), zap.Int("period", period))
	return nil
}

// UnlockPeriod – uses pgClient.DB
func (s *periodLockService) UnlockPeriod(ctx context.Context, companyID uuid.UUID, fiscalYear, period int, unlockedBy *uuid.UUID, reason string) error {
	// ✅ FIX: pass pgClient.DB instead of nil
	if err := s.repo.UnlockPeriod(ctx, s.pgClient.DB, companyID, fiscalYear, period, unlockedBy, reason); err != nil {
		return fmt.Errorf("unlock period: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "accounting", "unlock", "period_lock",
			nil, "user", unlockedBy, nil, nil, map[string]interface{}{
				"fiscal_year": fiscalYear,
				"period":      period,
				"reason":      reason,
			})
	}
	s.logger.Info("period unlocked", zap.String("company", companyID.String()), zap.Int("fy", fiscalYear), zap.Int("period", period))
	return nil
}

// IsPeriodLocked – read‑only, use pgClient.DB
func (s *periodLockService) IsPeriodLocked(ctx context.Context, companyID uuid.UUID, fiscalYear, period int) (bool, error) {
	return s.repo.IsLocked(ctx, s.pgClient.DB, companyID, fiscalYear, period)
}

// GetPeriodLock – read‑only
func (s *periodLockService) GetPeriodLock(ctx context.Context, companyID uuid.UUID, fiscalYear, period int) (*models.PeriodLock, error) {
	return s.repo.GetLock(ctx, s.pgClient.DB, companyID, fiscalYear, period)
}

// ListPeriodLocks – read‑only, pass pgClient.DB
func (s *periodLockService) ListPeriodLocks(ctx context.Context, filter repository.PeriodLockFilter, pagination Pagination, sort repository.Sort) ([]*models.PeriodLock, int64, error) {
	items, err := s.repo.ListLocks(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	return items, int64(len(items)), nil
}

// ListLockedPeriods – read‑only
func (s *periodLockService) ListLockedPeriods(ctx context.Context, companyID uuid.UUID) (map[[2]int]string, error) {
	return s.repo.ListLockedPeriods(ctx, s.pgClient.DB, companyID)
}
