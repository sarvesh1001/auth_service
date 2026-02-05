package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type BulkAttendanceRequest struct {
	CompanyID     uuid.UUID
	ActorID       uuid.UUID
	ActorType     string
	OrgUnitID     uuid.UUID
	EventType     string
	EventTime     time.Time
	TargetUserIDs []uuid.UUID
	Reason        *string
}

type AttendanceBulkService interface {
	MarkBulkAttendance(
		ctx context.Context,
		req *BulkAttendanceRequest,
	) (*BulkAttendanceResult, error)
}

type BulkAttendanceResult struct {
	SuccessUserIDs []uuid.UUID
	FailedUsers    map[uuid.UUID]string
}

type attendanceBulkService struct {
	batchService AttendanceBatchService
	logger       *zap.Logger
}

func NewAttendanceBulkService(
	batchService AttendanceBatchService,
	logger *zap.Logger,
) AttendanceBulkService {
	return &attendanceBulkService{
		batchService: batchService,
		logger:       logger,
	}
}

func (s *attendanceBulkService) MarkBulkAttendance(
	ctx context.Context,
	req *BulkAttendanceRequest,
) (*BulkAttendanceResult, error) {

	if req.CompanyID == uuid.Nil || req.ActorID == uuid.Nil {
		return nil, fmt.Errorf("invalid company or actor")
	}
	if len(req.TargetUserIDs) == 0 {
		return nil, fmt.Errorf("no users provided")
	}

	reason := ""
	if req.Reason != nil {
		reason = *req.Reason
	}

	// 🔁 Delegate to batch service (single source of truth)
	batchResult, err := s.batchService.Apply(ctx,
		&AttendanceBatchRequest{
			CompanyID:     req.CompanyID,
			ActorID:       req.ActorID,
			ActorType:     req.ActorType,
			BusinessDate:  req.EventTime,
			Status:        req.EventType,
			Reason:        reason,
			TargetUserIDs: req.TargetUserIDs,
			Source:        "bulk",
			OrgUnitID:     &req.OrgUnitID,
		},
	)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Bulk attendance marked",
		zap.String("company_id", req.CompanyID.String()),
		zap.Int("total_users", len(req.TargetUserIDs)),
		zap.Int("success_count", len(batchResult.SuccessUserIDs)),
		zap.Int("failure_count", len(batchResult.FailedUsers)),
	)

	return &BulkAttendanceResult{
		SuccessUserIDs: batchResult.SuccessUserIDs,
		FailedUsers:    batchResult.FailedUsers,
	}, nil
}
