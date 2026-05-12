package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
)

// AnalyticsQueryService defines the query methods for inventory analytics.
type AnalyticsQueryService interface {
	GetSnapshotRange(ctx context.Context, filter repository.SnapshotFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.DailyInventorySnapshot, error)
	GetTurnoverMetrics(ctx context.Context, filter repository.TurnoverFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.InventoryTurnoverMetrics, error)
	GetABCClassification(ctx context.Context, filter repository.ABCFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.ABCClassification, error)
	GetInventoryAging(ctx context.Context, filter repository.AgingFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.InventoryAging, error)
	GetDemandHistory(ctx context.Context, filter repository.DemandFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.DemandHistory, error)
	GetMovementSummary(ctx context.Context, companyID uuid.UUID, from, to time.Time, warehouseID, itemID *uuid.UUID) ([]*models.MovementDailySummary, error)
}

type analyticsQueryService struct {
	analysisRepo repository.InventoryAnalysisRepository
	db           repository.DBTX // typically *sql.DB or *sql.Tx
	logger       *zap.Logger
}

// NewAnalyticsQueryService creates a new AnalyticsQueryService.
func NewAnalyticsQueryService(
	analysisRepo repository.InventoryAnalysisRepository,
	db repository.DBTX,
	logger *zap.Logger,
) AnalyticsQueryService {
	return &analyticsQueryService{
		analysisRepo: analysisRepo,
		db:           db,
		logger:       logger.Named("analytics_query_service"),
	}
}

func (s *analyticsQueryService) GetSnapshotRange(ctx context.Context, filter repository.SnapshotFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.DailyInventorySnapshot, error) {
	return s.analysisRepo.GetSnapshotRange(ctx, s.db, filter, pagination, sort)
}

func (s *analyticsQueryService) GetTurnoverMetrics(ctx context.Context, filter repository.TurnoverFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.InventoryTurnoverMetrics, error) {
	return s.analysisRepo.GetTurnoverMetrics(ctx, s.db, filter, pagination, sort)
}

func (s *analyticsQueryService) GetABCClassification(ctx context.Context, filter repository.ABCFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.ABCClassification, error) {
	return s.analysisRepo.GetABCClassification(ctx, s.db, filter, pagination, sort)
}

func (s *analyticsQueryService) GetInventoryAging(ctx context.Context, filter repository.AgingFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.InventoryAging, error) {
	return s.analysisRepo.GetInventoryAging(ctx, s.db, filter, pagination, sort)
}

func (s *analyticsQueryService) GetDemandHistory(ctx context.Context, filter repository.DemandFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.DemandHistory, error) {
	return s.analysisRepo.GetDemandHistory(ctx, s.db, filter, pagination, sort)
}

func (s *analyticsQueryService) GetMovementSummary(ctx context.Context, companyID uuid.UUID, from, to time.Time, warehouseID, itemID *uuid.UUID) ([]*models.MovementDailySummary, error) {
	return s.analysisRepo.GetMovementSummary(ctx, s.db, companyID, from, to, warehouseID, itemID)
}
