package service

import (
	"auth-service/internal/hr/repository"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type ClassAttendanceRequest struct {
	CompanyID uuid.UUID
	ActorID   uuid.UUID
	ActorType string
	OrgUnitID uuid.UUID
	Date      time.Time
	Status    string // present / absent / late / etc
	Reason    string
}

type ClassAttendanceResult struct {
	SuccessUserIDs []uuid.UUID
	FailedUsers    map[uuid.UUID]string
}

type ClassAttendanceService interface {
	MarkClassAttendance(
		ctx context.Context,
		req *ClassAttendanceRequest,
	) (*ClassAttendanceResult, error)
}

type classAttendanceService struct {
	orgUnitRepo  repository.OrgUnitRepository
	batchService AttendanceBatchService
	logger       *zap.Logger
}

func NewClassAttendanceService(
	orgUnitRepo repository.OrgUnitRepository,
	batchService AttendanceBatchService,
	logger *zap.Logger,
) ClassAttendanceService {
	return &classAttendanceService{
		orgUnitRepo:  orgUnitRepo,
		batchService: batchService,
		logger:       logger,
	}
}

func (s *classAttendanceService) MarkClassAttendance(
	ctx context.Context,
	req *ClassAttendanceRequest,
) (*ClassAttendanceResult, error) {

	if req.OrgUnitID == uuid.Nil {
		return nil, fmt.Errorf("org_unit_id is required")
	}

	// 1️⃣ Expand class → users
	userIDs, err := s.orgUnitRepo.GetActiveUsersByOrgUnit(ctx, req.OrgUnitID)
	if err != nil {
		return nil, err
	}

	if len(userIDs) == 0 {
		return nil, fmt.Errorf("no active users in class")
	}

	// 2️⃣ Delegate to batch service (single source of truth)
	batchResult, err := s.batchService.Apply(ctx,
		&AttendanceBatchRequest{
			CompanyID:     req.CompanyID,
			ActorID:       req.ActorID,
			ActorType:     req.ActorType,
			BusinessDate:  req.Date,
			Status:        req.Status,
			Reason:        req.Reason,
			TargetUserIDs: userIDs,
			Source:        "class",
			OrgUnitID:     &req.OrgUnitID,
		},
	)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Class attendance marked",
		zap.String("company_id", req.CompanyID.String()),
		zap.String("org_unit_id", req.OrgUnitID.String()),
		zap.Int("total_users", len(userIDs)),
		zap.Int("success_count", len(batchResult.SuccessUserIDs)),
		zap.Int("failure_count", len(batchResult.FailedUsers)),
	)

	return &ClassAttendanceResult{
		SuccessUserIDs: batchResult.SuccessUserIDs,
		FailedUsers:    batchResult.FailedUsers,
	}, nil
}
