package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/locationctx"
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
// IMPLEMENTATION WITH AUDIT LOGS (IP INCLUDED)
// ============================================================
//

type attendanceOMService struct {
	orgUnitRepo  repository.OrgUnitRepository
	employeeRepo repository.EmployeeRepository // 👈 new — for location lookup
	auditService *audit.AuditService
}

//
// ============================================================
// CONSTRUCTOR
// ============================================================
//

func NewAttendanceOMService(
	orgUnitRepo repository.OrgUnitRepository,
	employeeRepo repository.EmployeeRepository, // 👈 new
	auditService *audit.AuditService,
) AttendanceOMService {
	return &attendanceOMService{
		orgUnitRepo:  orgUnitRepo,
		employeeRepo: employeeRepo,
		auditService: auditService,
	}
}

//
// ============================================================
// LOCATION SCOPE HELPER
// ============================================================
//

// targetInLocationScope reports whether the target user is within the
// request's current location scope.
//
// Rules (see docs/location-architecture.md):
//
//   - ScopeAll      → always true (caller has company-wide authority)
//   - ScopeLocation → true iff target.employment_location_id matches scope
//   - missing ctx   → FALSE. User-initiated attendance routes are always
//     wrapped in LocationValidationMiddleware. If the context
//     is missing, that is a wiring bug and must not silently
//     widen access.
//
// Returns (allowed, reason). Reason is "" on success and a short machine
// label on denial, so the caller can log/trace the specific cause.
func (s *attendanceOMService) targetInLocationScope(
	ctx context.Context,
	companyID, targetUserID uuid.UUID,
) (bool, string) {
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		// Missing context on a user-initiated path — treat as denied.
		// The caller will surface "location_context_missing" in the audit.
		return false, "location_context_missing"
	}

	if locCtx.Mode == locationctx.ScopeAll {
		return true, ""
	}

	empLoc, err := s.employeeRepo.GetEmploymentLocationID(ctx, companyID, targetUserID)
	if err != nil {
		// DB error looking up the target's location → deny. Better to
		// over-restrict than to silently allow when we cannot verify.
		return false, "location_lookup_failed"
	}
	if empLoc == nil {
		return false, "target_has_no_location"
	}
	if *empLoc != *locCtx.LocationID {
		return false, "outside_location_scope"
	}
	return true, ""
}

//
// ============================================================
// CORE AUTHORIZATION WITH AUDIT LOGS (IP INCLUDED)
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
	ip, _ := ctx.Value("ip_address").(string)

	auditMetadata := map[string]interface{}{
		"actor_id":           actorID.String(),
		"target_user_id":     targetUserID.String(),
		"authorization_type": "mark_attendance",
		"ip":                 ip,
	}

	// Self attendance always allowed — you can always mark your own.
	if actorID == targetUserID {
		if s.auditService != nil {
			auditMetadata["result"] = "allowed"
			auditMetadata["reason"] = "self"
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
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

	// 👇 Location scope check. Runs BEFORE org-unit membership lookups so
	// we don't leak org-unit structure to out-of-scope callers.
	if allowed, reason := s.targetInLocationScope(ctx, companyID, targetUserID); !allowed {
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = reason
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
				&companyID,
				"attendance",
				"om.authorization.out_of_scope",
				"user",
				&targetUserID,
				"user",
				&actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return false, reason
	}

	actorMemberships, err := s.orgUnitRepo.GetUserMemberships(ctx, actorID, true)
	if err != nil {
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "failed_actor_membership"
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
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
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "failed_target_membership"
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
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
					if s.auditService != nil {
						auditMetadata["result"] = "allowed"
						auditMetadata["reason"] = *a.Role
						auditMetadata["org_unit_id"] = a.OrgUnitID.String()
						auditMetadata["actor_role"] = *a.Role
						auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
						s.auditService.LogAction(ctx,
							nil,
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

	// Denied
	if s.auditService != nil {
		auditMetadata["result"] = "denied"
		auditMetadata["reason"] = "not_authorized"
		auditMetadata["actor_memberships"] = len(actorMemberships)
		auditMetadata["target_memberships"] = len(targetMemberships)
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		s.auditService.LogAction(ctx,
			nil,
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
	ip, _ := ctx.Value("ip_address").(string)

	auditMetadata := map[string]interface{}{
		"actor_id":           actorID.String(),
		"target_user_id":     targetUserID.String(),
		"authorization_type": "correct_attendance",
		"ip":                 ip,
	}

	// Self correction always allowed — you can always fix your own record.
	if actorID == targetUserID {
		if s.auditService != nil {
			auditMetadata["result"] = "allowed"
			auditMetadata["reason"] = "self"
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
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

	// 👇 Location scope check. Runs BEFORE org-unit membership lookups.
	if allowed, reason := s.targetInLocationScope(ctx, companyID, targetUserID); !allowed {
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = reason
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
				&companyID,
				"attendance",
				"om.correction_authorization.out_of_scope",
				"user",
				&targetUserID,
				"user",
				&actorID,
				nil,
				nil,
				auditMetadata,
			)
		}
		return false, reason
	}

	actorMemberships, err := s.orgUnitRepo.GetUserMemberships(ctx, actorID, true)
	if err != nil {
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "failed_actor_membership"
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
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
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "failed_target_membership"
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
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
					if s.auditService != nil {
						auditMetadata["result"] = "allowed"
						auditMetadata["reason"] = *a.Role
						auditMetadata["org_unit_id"] = a.OrgUnitID.String()
						auditMetadata["actor_role"] = *a.Role
						auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
						s.auditService.LogAction(ctx,
							nil,
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

	// Denied
	if s.auditService != nil {
		auditMetadata["result"] = "denied"
		auditMetadata["reason"] = "not_authorized"
		auditMetadata["actor_memberships"] = len(actorMemberships)
		auditMetadata["target_memberships"] = len(targetMemberships)
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		s.auditService.LogAction(ctx,
			nil,
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
// PUNCH AUTHORIZATION WITH IP IN AUDIT
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
	ip, _ := ctx.Value("ip_address").(string)

	auditMetadata := map[string]interface{}{
		"target_user_id":     targetUserID.String(),
		"source_type":        sourceType,
		"work_center_code":   workCenterCode,
		"authorization_type": "punch_attendance",
		"ip":                 ip,
	}

	if actorID != nil {
		auditMetadata["actor_id"] = actorID.String()
		auditMetadata["actor_type"] = "user"
	} else {
		auditMetadata["actor_type"] = "device"
	}

	// ─────────────────────────────
	// 1️⃣ DEVICE / TERMINAL PUNCH
	//
	// Device punches do NOT undergo a location scope check.
	// The device is itself bound to a geofence, and the geofence is
	// bound to an employment location. The middleware that authenticates
	// device tokens enforces that binding. Adding a per-user location
	// check here would break legitimate cross-site device sync.
	// ─────────────────────────────
	if actorID == nil {
		if workCenterCode == nil || *workCenterCode == "" {
			if s.auditService != nil {
				auditMetadata["result"] = "denied"
				auditMetadata["reason"] = "work_center_required_for_device"
				auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
				s.auditService.LogAction(ctx,
					nil,
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

		if s.auditService != nil {
			auditMetadata["result"] = "allowed"
			auditMetadata["reason"] = "device_punch_allowed"
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
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
	//
	// Location check happens inside CanMarkAttendance, which we delegate to.
	// ─────────────────────────────

	switch sourceType {
	case "biometric", "kiosk", "terminal":
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = "human_cannot_use_device_source"
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
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

	allowed, reason := s.CanMarkAttendance(ctx, companyID, *actorID, targetUserID)
	if !allowed {
		if s.auditService != nil {
			auditMetadata["result"] = "denied"
			auditMetadata["reason"] = reason
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				nil,
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

	if s.auditService != nil {
		auditMetadata["result"] = "allowed"
		auditMetadata["reason"] = "human_punch_allowed"
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		s.auditService.LogAction(ctx,
			nil,
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
