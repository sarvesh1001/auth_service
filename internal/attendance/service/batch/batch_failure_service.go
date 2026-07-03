package batch

import (
	"context"
	"errors"

	"auth-service/internal/attendance/repository"

	"go.uber.org/zap"
)

// BatchFailureService handles retrieval of batch processing failures.
type BatchFailureService interface {
	// GetFailures returns all failures for a batch reference.
	GetFailures(ctx context.Context, batchRef string) ([]*repository.AttendancePunchFailureView, error)
}

type batchFailureService struct {
	batchRepo repository.AttendanceBatchRepository
	logger    *zap.Logger
}

// NewBatchFailureService creates a new batch failure service.
func NewBatchFailureService(batchRepo repository.AttendanceBatchRepository, logger *zap.Logger) BatchFailureService {
	return &batchFailureService{
		batchRepo: batchRepo,
		logger:    logger,
	}
}

func (s *batchFailureService) GetFailures(ctx context.Context, batchRef string) ([]*repository.AttendancePunchFailureView, error) {
	if batchRef == "" {
		return nil, errors.New("batch_ref is required")
	}
	failures, err := s.batchRepo.ListFailuresByBatchRef(ctx, batchRef)
	if err != nil {
		s.logger.Error("Failed to list failures", zap.String("batch_ref", batchRef), zap.Error(err))
		return nil, err
	}
	s.logger.Info("GetFailures completed", zap.String("batch_ref", batchRef), zap.Int("count", len(failures)))
	return failures, nil
}
