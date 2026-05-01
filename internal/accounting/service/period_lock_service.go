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
	"auth-service/internal/infrastructure/idempotency"
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
	repo             repository.PeriodLockRepository
	pgClient         *client.PostgresClient
	auditService     *audit.AuditService
	logger           *zap.Logger
	idempotencyStore idempotency.Store
}

func NewPeriodLockService(
	repo repository.PeriodLockRepository,
	pgClient *client.PostgresClient,
	auditService *audit.AuditService,
	logger *zap.Logger,
	idempotencyStore idempotency.Store,
) PeriodLockService {
	return &periodLockService{
		repo:             repo,
		pgClient:         pgClient,
		auditService:     auditService,
		logger:           logger.Named("period_lock_service"),
		idempotencyStore: idempotencyStore,
	}
}

// --------------------------------------------------------------------------
// LockPeriod – with idempotency (uses its own *sql.Tx from BeginTx)
// --------------------------------------------------------------------------
func (s *periodLockService) LockPeriod(ctx context.Context, companyID uuid.UUID, fiscalYear, period int, lockedBy *uuid.UUID, reason string) error {
	logger := s.logger.With(
		zap.String("method", "LockPeriod"),
		zap.String("company", companyID.String()),
		zap.Int("fy", fiscalYear),
		zap.Int("period", period),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var done bool
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &done)
		if err == nil && done {
			logger.Info("idempotent request, period already locked")
			return nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	if err := s.repo.LockPeriod(ctx, tx, companyID, fiscalYear, period, lockedBy, reason); err != nil {
		return fmt.Errorf("lock period: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "accounting", "lock", "period_lock",
			nil, "user", lockedBy, nil, nil, map[string]interface{}{
				"fiscal_year": fiscalYear,
				"period":      period,
				"reason":      reason,
			})
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("period locked")
	return nil
}

// --------------------------------------------------------------------------
// UnlockPeriod – with idempotency
// --------------------------------------------------------------------------
func (s *periodLockService) UnlockPeriod(ctx context.Context, companyID uuid.UUID, fiscalYear, period int, unlockedBy *uuid.UUID, reason string) error {
	logger := s.logger.With(
		zap.String("method", "UnlockPeriod"),
		zap.String("company", companyID.String()),
		zap.Int("fy", fiscalYear),
		zap.Int("period", period),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var done bool
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &done)
		if err == nil && done {
			logger.Info("idempotent request, period already unlocked")
			return nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	if err := s.repo.UnlockPeriod(ctx, tx, companyID, fiscalYear, period, unlockedBy, reason); err != nil {
		return fmt.Errorf("unlock period: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "accounting", "unlock", "period_lock",
			nil, "user", unlockedBy, nil, nil, map[string]interface{}{
				"fiscal_year": fiscalYear,
				"period":      period,
				"reason":      reason,
			})
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("period unlocked")
	return nil
}

// --------------------------------------------------------------------------
// Read‑only methods – no idempotency
// --------------------------------------------------------------------------
func (s *periodLockService) IsPeriodLocked(ctx context.Context, companyID uuid.UUID, fiscalYear, period int) (bool, error) {
	return s.repo.IsLocked(ctx, s.pgClient.DB, companyID, fiscalYear, period)
}

func (s *periodLockService) GetPeriodLock(ctx context.Context, companyID uuid.UUID, fiscalYear, period int) (*models.PeriodLock, error) {
	return s.repo.GetLock(ctx, s.pgClient.DB, companyID, fiscalYear, period)
}

func (s *periodLockService) ListPeriodLocks(ctx context.Context, filter repository.PeriodLockFilter, pagination Pagination, sort repository.Sort) ([]*models.PeriodLock, int64, error) {
	items, err := s.repo.ListLocks(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	return items, int64(len(items)), nil
}

func (s *periodLockService) ListLockedPeriods(ctx context.Context, companyID uuid.UUID) (map[[2]int]string, error) {
	return s.repo.ListLockedPeriods(ctx, s.pgClient.DB, companyID)
}
