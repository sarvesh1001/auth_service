package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceBatchRequest struct {
	CompanyID uuid.UUID
	ActorID   uuid.UUID
	ActorType string

	BusinessDate time.Time
	Status       string
	Reason       string

	TargetUserIDs []uuid.UUID
	Source        string // "class" | "bulk"
	OrgUnitID     *uuid.UUID
}

type AttendanceBatchResult struct {
	SuccessUserIDs []uuid.UUID
	FailedUsers    map[uuid.UUID]string
}

type AttendanceBatchService interface {
	Apply(
		ctx context.Context,
		req *AttendanceBatchRequest,
	) (*AttendanceBatchResult, error)
}

type attendanceBatchService struct {
	attendanceAdmin AttendanceAdminService
	omService       AttendanceOMService
	resolution      AttendanceResolutionService
	auditService    *AuditService
	logger          *zap.Logger
}

func NewAttendanceBatchService(
	attendanceAdmin AttendanceAdminService,
	omService AttendanceOMService,
	resolution AttendanceResolutionService,
	auditService *AuditService,
	logger *zap.Logger,
) AttendanceBatchService {
	return &attendanceBatchService{
		attendanceAdmin: attendanceAdmin,
		omService:       omService,
		resolution:      resolution,
		auditService:    auditService,
		logger:          logger,
	}
}

func (s *attendanceBatchService) Apply(
	ctx context.Context,
	req *AttendanceBatchRequest,
) (*AttendanceBatchResult, error) {

	result := &AttendanceBatchResult{
		FailedUsers: make(map[uuid.UUID]string),
	}

	for _, userID := range req.TargetUserIDs {

		allowed, reason := s.omService.CanMarkAttendance(
			ctx,
			req.CompanyID,
			req.ActorID,
			userID,
		)
		if !allowed {
			result.FailedUsers[userID] = reason
			continue
		}

		err := s.attendanceAdmin.CreateAttendanceCorrection(ctx,
			&AttendanceCorrectionRequest{
				CompanyID:      req.CompanyID,
				ActorID:        req.ActorID,
				ActorType:      req.ActorType,
				TargetUserID:   userID,
				BusinessDate:   req.BusinessDate,
				CorrectionType: "attendance_adjustment",
				OverrideStatus: req.Status,
				Reason:         req.Reason,
			},
		)
		if err != nil {
			result.FailedUsers[userID] = err.Error()
			continue
		}

		_ = s.resolution.RecalculateDay(
			ctx,
			req.CompanyID,
			userID,
			req.BusinessDate,
		)

		result.SuccessUserIDs = append(result.SuccessUserIDs, userID)
	}

	// 🔍 ONE audit event for whole batch
	if s.auditService != nil {
		meta := map[string]interface{}{
			"source":  req.Source,
			"date":    req.BusinessDate.Format("2006-01-02"),
			"status":  req.Status,
			"total":   len(req.TargetUserIDs),
			"success": len(result.SuccessUserIDs),
			"failed":  len(result.FailedUsers),
		}
		if req.OrgUnitID != nil {
			meta["org_unit_id"] = req.OrgUnitID.String()
		}

		s.auditService.LogAction(
			ctx,
			&req.CompanyID,
			"attendance",
			"batch.apply.completed",
			"attendance_batch",
			nil,
			req.ActorType,
			&req.ActorID,
			nil,
			nil,
			meta,
		)
	}

	return result, nil
}
