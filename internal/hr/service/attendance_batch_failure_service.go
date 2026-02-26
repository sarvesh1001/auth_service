package service

import (
	"context"
	"errors"

	"auth-service/internal/hr/repository"

	"go.uber.org/zap"
)

type AttendanceBatchFailureService interface {
	GetFailures(
		ctx context.Context,
		batchRef string,
	) ([]*repository.AttendanceBatchOutbox, error)
}

type attendanceBatchFailureService struct {
	repo   repository.AttendanceBatchOutboxRepository
	logger *zap.Logger
}

func NewAttendanceBatchFailureService(
	repo repository.AttendanceBatchOutboxRepository,
	logger *zap.Logger,
) AttendanceBatchFailureService {
	return &attendanceBatchFailureService{
		repo:   repo,
		logger: logger,
	}
}

func (s *attendanceBatchFailureService) GetFailures(
	ctx context.Context,
	batchRef string,
) ([]*repository.AttendanceBatchOutbox, error) {

	// 🔥 ENTRY LOG
	s.logger.Info("GetFailures called",
		zap.String("batch_ref", batchRef),
	)

	if batchRef == "" {
		s.logger.Error("GetFailures failed: batch_ref is empty")
		return nil, errors.New("batch_ref is required")
	}

	failures, err := s.repo.ListFailuresByBatchRef(ctx, batchRef)
	if err != nil {
		s.logger.Error("Failed to list failures by batch ref",
			zap.String("batch_ref", batchRef),
			zap.Error(err),
		)
		return nil, err
	}

	// 🔥 EXIT LOG
	s.logger.Info("GetFailures completed",
		zap.String("batch_ref", batchRef),
		zap.Int("count", len(failures)),
	)

	return failures, nil
}
