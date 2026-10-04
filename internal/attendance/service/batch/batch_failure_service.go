package batch

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
)

type BatchFailureService interface {
	GetFailures(
		ctx context.Context,
		companyID uuid.UUID,
		batchRef string,
	) ([]*repository.AttendancePunchFailureView, error)
}

type batchFailureService struct {
	batchRepo repository.AttendanceBatchRepository
	logger    *zap.Logger
}

func NewBatchFailureService(
	batchRepo repository.AttendanceBatchRepository,
	logger *zap.Logger,
) BatchFailureService {
	return &batchFailureService{
		batchRepo: batchRepo,
		logger:    logger,
	}
}

// GetFailures returns the recorded failures for a batch, scoped to the
// caller's company.
//
// FIX: previous version attempted to post-filter using f.CompanyID, but
// AttendancePunchFailureView does not expose that field. The company
// filter is now applied inside the repository (ListFailuresByBatchRef
// takes companyID and constrains the JOIN on attendance_device_punch_batches
// by company_id). Cross-tenant rows never leave the database.
func (s *batchFailureService) GetFailures(
	ctx context.Context,
	companyID uuid.UUID,
	batchRef string,
) ([]*repository.AttendancePunchFailureView, error) {
	if batchRef == "" {
		return nil, errors.New("batch_ref is required")
	}
	if companyID == uuid.Nil {
		return nil, errors.New("company_id is required")
	}

	failures, err := s.batchRepo.ListFailuresByBatchRef(ctx, companyID, batchRef)
	if err != nil {
		s.logger.Error("Failed to list failures",
			zap.String("batch_ref", batchRef),
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		return nil, err
	}

	s.logger.Info("GetFailures completed",
		zap.String("batch_ref", batchRef),
		zap.String("company_id", companyID.String()),
		zap.Int("count", len(failures)),
	)
	return failures, nil
}
