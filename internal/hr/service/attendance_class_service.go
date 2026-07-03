package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/repository"
)

// ClassAttendanceRequest defines the request for marking class attendance.
type ClassAttendanceRequest struct {
	CompanyID uuid.UUID
	ActorID   uuid.UUID
	ActorType string
	OrgUnitID uuid.UUID
	Date      time.Time
	Status    string // present / absent / late / etc
	Reason    string
}

// ClassAttendanceResult contains the result.
type ClassAttendanceResult struct {
	SuccessUserIDs []uuid.UUID
	FailedUsers    map[uuid.UUID]string
}

// ClassAttendanceService defines the class attendance marking service.
type ClassAttendanceService interface {
	MarkClassAttendance(
		ctx context.Context,
		req *ClassAttendanceRequest,
	) (*ClassAttendanceResult, error)
}

type classAttendanceService struct {
	orgUnitRepo repository.OrgUnitRepository
	bulkService AttendanceBulkService // refactored bulk service
	logger      *zap.Logger
}

// NewClassAttendanceService creates a new class attendance service.
func NewClassAttendanceService(
	orgUnitRepo repository.OrgUnitRepository,
	bulkService AttendanceBulkService,
	logger *zap.Logger,
) ClassAttendanceService {
	return &classAttendanceService{
		orgUnitRepo: orgUnitRepo,
		bulkService: bulkService,
		logger:      logger,
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

	// 2️⃣ Delegate to bulk service (which uses unified correction + resolution)
	reason := req.Reason
	bulkReq := &BulkAttendanceRequest{
		CompanyID:     req.CompanyID,
		ActorID:       req.ActorID,
		ActorType:     req.ActorType,
		OrgUnitID:     req.OrgUnitID,
		EventType:     req.Status,
		EventTime:     req.Date,
		TargetUserIDs: userIDs,
		Reason:        &reason,
	}
	bulkResult, err := s.bulkService.MarkBulkAttendance(ctx, bulkReq)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Class attendance marked",
		zap.String("company_id", req.CompanyID.String()),
		zap.String("org_unit_id", req.OrgUnitID.String()),
		zap.Int("total_users", len(userIDs)),
		zap.Int("success_count", len(bulkResult.SuccessUserIDs)),
		zap.Int("failure_count", len(bulkResult.FailedUsers)),
	)

	return &ClassAttendanceResult{
		SuccessUserIDs: bulkResult.SuccessUserIDs,
		FailedUsers:    bulkResult.FailedUsers,
	}, nil
}
