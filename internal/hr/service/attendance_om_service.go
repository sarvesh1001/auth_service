package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/repository"
	a "auth-service/internal/infrastructure/audit"
)

//
// ============================================================
// ATTENDANCE OM SERVICE (INTERFACE)
// ============================================================
//

type AttendanceOMService interface {
	CanMarkAttendance(
		ctx context.Context,
		companyID uuid.UUID,
		actorID uuid.UUID,
		targetUserID uuid.UUID,
	) (bool, string)

	CanCorrectAttendance(
		ctx context.Context,
		companyID uuid.UUID,
		actorID uuid.UUID,
		targetUserID uuid.UUID,
	) (bool, string)

	// actorID == nil → device / biometric / terminal
	CanPunchAttendance(
		ctx context.Context,
		companyID uuid.UUID,
		actorID *uuid.UUID,
		targetUserID uuid.UUID,
		sourceType string,
		workCenterCode *string,
	) (bool, string)
}

//
// ============================================================
// IMPLEMENTATION WITH AUDIT LOGS
// ============================================================
//

type attendanceOMService struct {
	orgUnitRepo  repository.OrgUnitRepository
	auditService *a.AuditService
	logger       *zap.Logger
}

//
// ============================================================
// CONSTRUCTOR
// ============================================================
//

func NewAttendanceOMService(
	orgUnitRepo repository.OrgUnitRepository,
	auditService *a.AuditService,
	logger *zap.Logger,
) AttendanceOMService {
	return &attendanceOMService{
		orgUnitRepo:  orgUnitRepo,
		auditService: auditService,
		logger:       logger,
	}
}

//
// ============================================================
// CORE AUTHORIZATION WITH AUDIT LOGS
// ============================================================
//

// CanMarkAttendance — human marking attendance
func (s *attendanceOMService) CanMarkAttendance(
	ctx context.Context,
	companyID uuid.UUID,
	actorID uuid.UUID,
	targetUserID uuid.UUID,
) (bool, string) {
	startTime := time.Now()

	// 🎯 Initialize audit metadata
	auditMetadata := map[string]interface{}{
		"actor_id":           actorID.String(),
		"target_user_id":     targetUserID.String(),
		"authorization_type": "mark_attendance",
	}

	// Self attendance always allowed
	if actorID == targetUserID {
		// 🎯 Log self-attendance authorization
		if s.auditService != nil {
			auditMetadata["result"] = "allowed"
			auditMetadata["reason"] = "self"
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			// ✅ Added tx = nil
			s.auditService.LogAction(ctx,
				nil, // tx
				&companyID,
				"attendance",
				"om.authorization.self",
				"user",
				&actorID,
				"user",
				&actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return true, "self"
	}

	actorMemberships, err := s.orgUnitRepo.GetUserMemberships(ctx, actorID, true)
	if err != nil {
		// 🎯 Log membership fetch failure
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "failed_actor_membership"
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			// ✅ Added tx = nil
			s.auditService.LogAction(ctx,
				nil, // tx
				&companyID,
				"attendance",
				"om.authorization.failed",
				"user",
				&actorID,
				"user",
				&actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return false, "failed_actor_membership"
	}

	targetMemberships, err := s.orgUnitRepo.GetUserMemberships(ctx, targetUserID, true)
	if err != nil {
		// 🎯 Log target membership fetch failure
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "failed_target_membership"
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			// ✅ Added tx = nil
			s.auditService.LogAction(ctx,
				nil, // tx
				&companyID,
				"attendance",
				"om.authorization.failed",
				"user",
				&targetUserID,
				"user",
				&actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return false, "failed_target_membership"
	}

	for _, a := range actorMemberships {
		for _, t := range targetMemberships {
			if a.OrgUnitID == t.OrgUnitID && a.Role != nil {
				switch *a.Role {
				case "teacher", "supervisor", "coordinator":
					// 🎯 Log successful authorization
					if s.auditService != nil {
						auditMetadata["result"] = "allowed"
						auditMetadata["reason"] = *a.Role
						auditMetadata["org_unit_id"] = a.OrgUnitID.String()
						auditMetadata["actor_role"] = *a.Role
						auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
						// ✅ Added tx = nil
						s.auditService.LogAction(ctx,
							nil, // tx
							&companyID,
							"attendance",
							"om.authorization.success",
							"user",
							&actorID,
							"user",
							&actorID,
							nil,
							nil,
							auditMetadata,
						)
					}
					return true, *a.Role
				}
			}
		}
	}

	// 🎯 Log denied authorization
	if s.auditService != nil {
		auditMetadata["result"] = "denied"
		auditMetadata["reason"] = "not_authorized"
		auditMetadata["actor_memberships"] = len(actorMemberships)
		auditMetadata["target_memberships"] = len(targetMemberships)
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		// ✅ Added tx = nil
		s.auditService.LogAction(ctx,
			nil, // tx
			&companyID,
			"attendance",
			"om.authorization.denied",
			"user",
			&actorID,
			"user",
			&actorID,
			nil,
			nil,
			auditMetadata,
		)
	}

	return false, "not_authorized"
}

// CanCorrectAttendance — stricter than mark
func (s *attendanceOMService) CanCorrectAttendance(
	ctx context.Context,
	companyID uuid.UUID,
	actorID uuid.UUID,
	targetUserID uuid.UUID,
) (bool, string) {
	startTime := time.Now()

	// 🎯 Initialize audit metadata
	auditMetadata := map[string]interface{}{
		"actor_id":           actorID.String(),
		"target_user_id":     targetUserID.String(),
		"authorization_type": "correct_attendance",
	}

	if actorID == targetUserID {
		// 🎯 Log self-correction authorization
		if s.auditService != nil {
			auditMetadata["result"] = "allowed"
			auditMetadata["reason"] = "self"
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			// ✅ Added tx = nil
			s.auditService.LogAction(ctx,
				nil, // tx
				&companyID,
				"attendance",
				"om.correction_authorization.self",
				"user",
				&actorID,
				"user",
				&actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return true, "self"
	}

	actorMemberships, err := s.orgUnitRepo.GetUserMemberships(ctx, actorID, true)
	if err != nil {
		// 🎯 Log membership fetch failure
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "failed_actor_membership"
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			// ✅ Added tx = nil
			s.auditService.LogAction(ctx,
				nil, // tx
				&companyID,
				"attendance",
				"om.correction_authorization.failed",
				"user",
				&actorID,
				"user",
				&actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return false, "failed_actor_membership"
	}

	targetMemberships, err := s.orgUnitRepo.GetUserMemberships(ctx, targetUserID, true)
	if err != nil {
		// 🎯 Log target membership fetch failure
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "failed_target_membership"
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			// ✅ Added tx = nil
			s.auditService.LogAction(ctx,
				nil, // tx
				&companyID,
				"attendance",
				"om.correction_authorization.failed",
				"user",
				&targetUserID,
				"user",
				&actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return false, "failed_target_membership"
	}

	for _, a := range actorMemberships {
		for _, t := range targetMemberships {
			if a.OrgUnitID == t.OrgUnitID && a.Role != nil {
				switch *a.Role {
				case "supervisor", "coordinator":
					// 🎯 Log successful correction authorization
					if s.auditService != nil {
						auditMetadata["result"] = "allowed"
						auditMetadata["reason"] = *a.Role
						auditMetadata["org_unit_id"] = a.OrgUnitID.String()
						auditMetadata["actor_role"] = *a.Role
						auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
						// ✅ Added tx = nil
						s.auditService.LogAction(ctx,
							nil, // tx
							&companyID,
							"attendance",
							"om.correction_authorization.success",
							"user",
							&actorID,
							"user",
							&actorID,
							nil,
							nil,
							auditMetadata,
						)
					}
					return true, *a.Role
				}
			}
		}
	}

	// 🎯 Log denied correction authorization
	if s.auditService != nil {
		auditMetadata["result"] = "denied"
		auditMetadata["reason"] = "not_authorized"
		auditMetadata["actor_memberships"] = len(actorMemberships)
		auditMetadata["target_memberships"] = len(targetMemberships)
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		// ✅ Added tx = nil
		s.auditService.LogAction(ctx,
			nil, // tx
			&companyID,
			"attendance",
			"om.correction_authorization.denied",
			"user",
			&actorID,
			"user",
			&actorID,
			nil,
			nil,
			auditMetadata,
		)
	}

	return false, "not_authorized"
}

//
// ============================================================
// 🔥 PUNCH AUTHORIZATION WITH AUDIT LOGS
// ============================================================
//

// actorID == nil → device / biometric / terminal
func (s *attendanceOMService) CanPunchAttendance(
	ctx context.Context,
	companyID uuid.UUID,
	actorID *uuid.UUID,
	targetUserID uuid.UUID,
	sourceType string,
	workCenterCode *string,
) (bool, string) {
	startTime := time.Now()

	// 🎯 Initialize audit metadata
	auditMetadata := map[string]interface{}{
		"target_user_id":     targetUserID.String(),
		"source_type":        sourceType,
		"work_center_code":   workCenterCode,
		"authorization_type": "punch_attendance",
	}

	if actorID != nil {
		auditMetadata["actor_id"] = actorID.String()
		auditMetadata["actor_type"] = "user"
	} else {
		auditMetadata["actor_type"] = "device"
	}

	// ─────────────────────────────
	// 1️⃣ DEVICE / TERMINAL PUNCH
	// ─────────────────────────────
	if actorID == nil {
		// Work center mandatory for devices
		if workCenterCode == nil || *workCenterCode == "" {
			// 🎯 Log work center requirement failure
			if s.auditService != nil {
				auditMetadata["result"] = "denied"
				auditMetadata["reason"] = "work_center_required_for_device"
				auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
				// ✅ Added tx = nil
				s.auditService.LogAction(ctx,
					nil, // tx
					&companyID,
					"attendance",
					"om.device_punch.work_center_required",
					"user",
					&targetUserID,
					"device",
					nil,
					nil,
					nil,
					auditMetadata,
				)
			}
			return false, "work_center_required_for_device"
		}

		// SAP rule:
		// device → work center → org unit → employee
		// 🎯 Log device punch authorization success
		if s.auditService != nil {
			auditMetadata["result"] = "allowed"
			auditMetadata["reason"] = "device_punch_allowed"
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			// ✅ Added tx = nil
			s.auditService.LogAction(ctx,
				nil, // tx
				&companyID,
				"attendance",
				"om.device_punch.allowed",
				"user",
				&targetUserID,
				"device",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return true, "device_punch_allowed"
	}

	// ─────────────────────────────
	// 2️⃣ HUMAN-ACTOR PUNCH
	// ─────────────────────────────

	// Humans cannot pretend to be devices
	switch sourceType {
	case "biometric", "kiosk", "terminal":
		// 🎯 Log invalid source type for human
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "human_cannot_use_device_source"
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			// ✅ Added tx = nil
			s.auditService.LogAction(ctx,
				nil, // tx
				&companyID,
				"attendance",
				"om.human_punch.invalid_source",
				"user",
				&targetUserID,
				"user",
				actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return false, "human_cannot_use_device_source"
	}

	allowed, reason := s.CanMarkAttendance(
		ctx,
		companyID,
		*actorID,
		targetUserID,
	)
	if !allowed {
		// 🎯 Log human punch authorization failure
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = reason
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			// ✅ Added tx = nil
			s.auditService.LogAction(ctx,
				nil, // tx
				&companyID,
				"attendance",
				"om.human_punch.denied",
				"user",
				&targetUserID,
				"user",
				actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return false, reason
	}

	// 🎯 Log human punch authorization success
	if s.auditService != nil {
		auditMetadata["result"] = "allowed"
		auditMetadata["reason"] = "human_punch_allowed"
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		// ✅ Added tx = nil
		s.auditService.LogAction(ctx,
			nil, // tx
			&companyID,
			"attendance",
			"om.human_punch.allowed",
			"user",
			&targetUserID,
			"user",
			actorID,
			nil,
			nil,
			auditMetadata,
		)
	}

	return true, "human_punch_allowed"
}
