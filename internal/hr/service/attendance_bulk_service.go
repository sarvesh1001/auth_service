package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/service/admin"
	"auth-service/internal/attendance/service/resolution"
)

// BulkAttendanceRequest defines the request for marking bulk attendance.
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

// AttendanceBulkService defines the bulk attendance marking service.
type AttendanceBulkService interface {
	MarkBulkAttendance(
		ctx context.Context,
		req *BulkAttendanceRequest,
	) (*BulkAttendanceResult, error)
}

// BulkAttendanceResult contains the result of bulk attendance marking.
type BulkAttendanceResult struct {
	SuccessUserIDs []uuid.UUID
	FailedUsers    map[uuid.UUID]string
}

type attendanceBulkService struct {
	correctionSvc admin.CorrectionService
	resolutionSvc resolution.ResolutionService
	omService     AttendanceOMService
	logger        *zap.Logger
}

// NewAttendanceBulkService creates a new bulk attendance service.
func NewAttendanceBulkService(
	correctionSvc admin.CorrectionService,
	resolutionSvc resolution.ResolutionService,
	omService AttendanceOMService,
	logger *zap.Logger,
) AttendanceBulkService {
	return &attendanceBulkService{
		correctionSvc: correctionSvc,
		resolutionSvc: resolutionSvc,
		omService:     omService,
		logger:        logger,
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

	result := &BulkAttendanceResult{
		FailedUsers: make(map[uuid.UUID]string),
	}

	for _, userID := range req.TargetUserIDs {
		// 1️⃣ Authorization check (HR-specific)
		allowed, authReason := s.omService.CanMarkAttendance(
			ctx,
			req.CompanyID,
			req.ActorID,
			userID,
		)
		if !allowed {
			result.FailedUsers[userID] = authReason
			continue
		}

		// 2️⃣ Create correction event via unified admin service
		corrReq := &admin.CorrectionRequest{
			CompanyID:      req.CompanyID,
			ActorID:        req.ActorID,
			ActorType:      req.ActorType,
			SubjectType:    "employee", // HR users are employees
			SubjectID:      userID,
			BusinessDate:   req.EventTime,
			CorrectionType: "attendance_adjustment",
			OverrideStatus: req.EventType,
			Reason:         reason,
			EventTime:      nil, // not needed for an adjustment
		}
		err := s.correctionSvc.CreateCorrection(ctx, corrReq)
		if err != nil {
			result.FailedUsers[userID] = err.Error()
			continue
		}

		// 3️⃣ Recalculate the day (unified resolution service)
		err = s.resolutionSvc.RecalculateDay(ctx, req.CompanyID, userID, "employee", req.EventTime)
		if err != nil {
			// Log error but don't mark as failed – correction already created.
			s.logger.Warn("Recalculation failed after bulk correction",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}

		result.SuccessUserIDs = append(result.SuccessUserIDs, userID)
	}

	s.logger.Info("Bulk attendance marked",
		zap.String("company_id", req.CompanyID.String()),
		zap.Int("total_users", len(req.TargetUserIDs)),
		zap.Int("success_count", len(result.SuccessUserIDs)),
		zap.Int("failure_count", len(result.FailedUsers)),
	)

	return result, nil
}
