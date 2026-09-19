package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/service/admin"
	"auth-service/internal/attendance/service/resolution"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
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

// BulkAttendanceResult contains the result of bulk attendance marking.
type BulkAttendanceResult struct {
	SuccessUserIDs []uuid.UUID          `json:"success_user_ids"`
	FailedUsers    map[uuid.UUID]string `json:"failed_users"`
}

// AttendanceBulkService defines the bulk attendance marking service.
type AttendanceBulkService interface {
	MarkBulkAttendance(
		ctx context.Context,
		req *BulkAttendanceRequest,
	) (*BulkAttendanceResult, error)
}

type attendanceBulkService struct {
	correctionSvc    admin.CorrectionService
	resolutionSvc    resolution.ResolutionService
	omService        AttendanceOMService
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewAttendanceBulkService creates a new bulk attendance service.
func NewAttendanceBulkService(
	correctionSvc admin.CorrectionService,
	resolutionSvc resolution.ResolutionService,
	omService AttendanceOMService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) AttendanceBulkService {
	return &attendanceBulkService{
		correctionSvc:    correctionSvc,
		resolutionSvc:    resolutionSvc,
		omService:        omService,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger,
	}
}

func (s *attendanceBulkService) MarkBulkAttendance(
	ctx context.Context,
	req *BulkAttendanceRequest,
) (*BulkAttendanceResult, error) {
	// 1️⃣ Idempotency: get or generate key
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("bulk_attendance-%s", uuid.New().String())
	}

	// Check if already processed
	var cachedResult BulkAttendanceResult
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedResult); err == nil {
		// Return the cached result (idempotent)
		return &cachedResult, nil
	}

	// 2️⃣ Basic validation
	if req.CompanyID == uuid.Nil || req.ActorID == uuid.Nil {
		return nil, fmt.Errorf("invalid company or actor")
	}
	if len(req.TargetUserIDs) == 0 {
		return nil, fmt.Errorf("no users provided")
	}

	// 3️⃣ Prepare before-state (for audit we can capture the request)
	beforeJSON, _ := json.Marshal(req)

	// 4️⃣ Process each user
	reason := ""
	if req.Reason != nil {
		reason = *req.Reason
	}

	result := &BulkAttendanceResult{
		FailedUsers: make(map[uuid.UUID]string),
	}

	for _, userID := range req.TargetUserIDs {
		// Authorization check (HR-specific)
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

		// Create correction event via unified admin service
		corrReq := &admin.CorrectionRequest{
			CompanyID:      req.CompanyID,
			ActorID:        req.ActorID,
			ActorType:      req.ActorType,
			SubjectType:    "employee",
			SubjectID:      userID,
			BusinessDate:   req.EventTime,
			CorrectionType: "attendance_adjustment",
			OverrideStatus: req.EventType,
			Reason:         reason,
			EventTime:      nil,
		}
		err := s.correctionSvc.CreateCorrection(ctx, corrReq)
		if err != nil {
			result.FailedUsers[userID] = err.Error()
			continue
		}

		// Recalculate the day (unified resolution service)
		err = s.resolutionSvc.RecalculateDay(ctx, req.CompanyID, userID, "employee", req.EventTime)
		if err != nil {
			s.logger.Warn("Recalculation failed after bulk correction",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}

		result.SuccessUserIDs = append(result.SuccessUserIDs, userID)
	}

	// 5️⃣ Log audit with IP
	afterJSON, _ := json.Marshal(result)
	ip, _ := ctx.Value("ip_address").(string) // extract IP from context

	metadata := map[string]interface{}{
		"total_users":   len(req.TargetUserIDs),
		"success_count": len(result.SuccessUserIDs),
		"failure_count": len(result.FailedUsers),
		"event_type":    req.EventType,
		"event_time":    req.EventTime,
		"org_unit_id":   req.OrgUnitID,
		"reason":        reason,
		"ip":            ip, // ✅ include IP in audit
	}

	if s.auditService != nil {
		actorID := req.ActorID
		companyID := req.CompanyID
		_ = s.auditService.LogAction(
			ctx,
			nil, // no transaction needed for audit
			&companyID,
			"attendance",      // module
			"bulk_mark",       // action
			"attendance_bulk", // entity_type
			nil,               // entity_id (not a single entity)
			req.ActorType,
			&actorID,
			beforeJSON,
			afterJSON,
			metadata,
		)
	}

	// 6️⃣ Store idempotency result
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, result)

	return result, nil
}
