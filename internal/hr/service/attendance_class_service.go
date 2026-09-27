package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
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
	SuccessUserIDs []uuid.UUID          `json:"success_user_ids"`
	FailedUsers    map[uuid.UUID]string `json:"failed_users"`
}

// ClassAttendanceService defines the class attendance marking service.
type ClassAttendanceService interface {
	MarkClassAttendance(
		ctx context.Context,
		req *ClassAttendanceRequest,
	) (*ClassAttendanceResult, error)
}

type classAttendanceService struct {
	pgClient         *client.PostgresClient // 👈 NEW
	orgUnitRepo      repository.OrgUnitRepository
	bulkService      AttendanceBulkService
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewClassAttendanceService creates a new class attendance service.
func NewClassAttendanceService(
	pgClient *client.PostgresClient, // 👈 NEW
	orgUnitRepo repository.OrgUnitRepository,
	bulkService AttendanceBulkService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) ClassAttendanceService {
	return &classAttendanceService{
		pgClient:         pgClient, // 👈 NEW
		orgUnitRepo:      orgUnitRepo,
		bulkService:      bulkService,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger,
	}
}

func (s *classAttendanceService) MarkClassAttendance(
	ctx context.Context,
	req *ClassAttendanceRequest,
) (*ClassAttendanceResult, error) {
	// 1️⃣ Idempotency: key based on class + date
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("class_attendance-%s-%s",
			req.OrgUnitID.String(),
			req.Date.Format("2006-01-02"),
		)
	}

	var cachedResult ClassAttendanceResult
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedResult); err == nil {
		return &cachedResult, nil
	}

	// 2️⃣ Validation
	if req.OrgUnitID == uuid.Nil {
		return nil, fmt.Errorf("org_unit_id is required")
	}

	// 3️⃣ Expand class → users
	userIDs, err := s.orgUnitRepo.GetActiveUsersByOrgUnit(ctx, s.pgClient.Pool(), req.OrgUnitID) // 👈 FIX
	if err != nil {
		return nil, err
	}
	if len(userIDs) == 0 {
		return nil, fmt.Errorf("no active users in class")
	}

	// 4️⃣ Before state
	beforeJSON, _ := json.Marshal(req)

	// 5️⃣ Delegate to bulk service
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

	result := &ClassAttendanceResult{
		SuccessUserIDs: bulkResult.SuccessUserIDs,
		FailedUsers:    bulkResult.FailedUsers,
	}

	// 6️⃣ Audit with IP
	afterJSON, _ := json.Marshal(result)
	ip, _ := ctx.Value("ip_address").(string)
	auditMetadata := map[string]interface{}{
		"org_unit_id":   req.OrgUnitID.String(),
		"date":          req.Date.Format("2006-01-02"),
		"status":        req.Status,
		"reason":        req.Reason,
		"total_users":   len(userIDs),
		"success_count": len(result.SuccessUserIDs),
		"failure_count": len(result.FailedUsers),
		"ip":            ip,
	}

	if s.auditService != nil {
		actorID := req.ActorID
		companyID := req.CompanyID
		_ = s.auditService.LogAction(
			ctx,
			nil,
			&companyID,
			"attendance",
			"class_mark",
			"class_attendance",
			nil,
			req.ActorType,
			&actorID,
			beforeJSON,
			afterJSON,
			auditMetadata,
		)
	}

	// 7️⃣ Store idempotency result
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, result)

	return result, nil
}
