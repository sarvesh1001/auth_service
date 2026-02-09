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

	if batchRef == "" {
		return nil, errors.New("batch_ref is required")
	}

	return s.repo.ListFailuresByBatchRef(ctx, batchRef)
}
