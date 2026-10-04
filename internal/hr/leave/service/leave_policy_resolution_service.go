package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

// ErrNoMatchingPolicy is returned by ResolveUserLeaveEntitlements when the
// resolver found zero applicable policy rules for a user. It is not a hard
// failure — it means the user has no policy coverage — but the batch caller
// must distinguish it from "resolved successfully" so counts are honest.
var ErrNoMatchingPolicy = errors.New("no matching policy rules for user")

type LeavePolicyResolutionService interface {
	ResolveUserLeaveEntitlements(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time, reason string, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ResolveBatchLeaveEntitlements(ctx context.Context, companyID uuid.UUID, userIDs []uuid.UUID, asOf time.Time, reason string, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*LeavePolicyResolutionResult, error)

	// ── Enqueue API (used by HTTP handlers, fan-out only) ────────────────
	EnqueueUserResolutionJobs(ctx context.Context, companyID uuid.UUID, userIDs []uuid.UUID, reason string) error
	EnqueueCompanyResolution(ctx context.Context, companyID uuid.UUID, reason string) error

	GetLeaveEntitlements(
		ctx context.Context,
		companyID uuid.UUID,
		userID *uuid.UUID,
		locationID *uuid.UUID,
		page, pageSize int,
	) ([]*models.LeaveEntitlement, int64, error)

	GetUserEffectivePolicies(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) ([]*models.LeavePolicyRuleResolution, error)

	EndActivePolicyEntitlements(ctx context.Context, companyID, userID uuid.UUID, effectiveTo time.Time) error

	ListActiveEmployeeUserIDs(ctx context.Context, companyID uuid.UUID) ([]uuid.UUID, error)

	ListActiveEmployeeUserIDsByPosition(ctx context.Context, companyID, positionID uuid.UUID) ([]uuid.UUID, error)
}

type LeavePolicyResolutionResult struct {
	TotalUsers     int         `json:"TotalUsers"`
	ProcessedUsers int         `json:"ProcessedUsers"`
	SkippedUsers   []uuid.UUID `json:"SkippedUsers"`
	FailedUsers    []uuid.UUID `json:"FailedUsers"`
	Errors         []string    `json:"Errors"`
}

type leavePolicyResolutionService struct {
	repo             repository.LeaveRepository
	resolverJobs     repository.ResolverJobRepository
	pgClient         *client.PostgresClient
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewLeavePolicyResolutionService(
	repo repository.LeaveRepository,
	resolverJobs repository.ResolverJobRepository,
	pgClient *client.PostgresClient,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) LeavePolicyResolutionService {
	return &leavePolicyResolutionService{
		repo:             repo,
		resolverJobs:     resolverJobs,
		pgClient:         pgClient,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// ============================================================
// Enqueue API — used by HTTP handlers, never does the work inline
// ============================================================

// EnqueueUserResolutionJobs enqueues one resolve_user job per user.
// Duplicates (a user already having a pending/processing resolve_user job)
// are silently skipped by the repository's NOT EXISTS check, so this is
// safe to call repeatedly.
func (s *leavePolicyResolutionService) EnqueueUserResolutionJobs(
	ctx context.Context,
	companyID uuid.UUID,
	userIDs []uuid.UUID,
	reason string,
) error {
	if s.pgClient == nil || s.resolverJobs == nil {
		return errors.New("resolver job repository not configured")
	}
	if len(userIDs) == 0 {
		return nil
	}
	zap.L().Info("enqueue user resolution jobs",
		zap.String("component", "leave_resolution"),
		zap.String("company_id", companyID.String()),
		zap.Int("user_count", len(userIDs)),
		zap.String("reason", reason),
	)
	return s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		return s.resolverJobs.EnqueueUserResolutions(ctx, tx, companyID, userIDs, reason)
	})
}

// EnqueueCompanyResolution enqueues a single resolve_company job. The
// worker will fan out internally in chunks of 100.
func (s *leavePolicyResolutionService) EnqueueCompanyResolution(
	ctx context.Context,
	companyID uuid.UUID,
	reason string,
) error {
	if s.pgClient == nil || s.resolverJobs == nil {
		return errors.New("resolver job repository not configured")
	}
	zap.L().Info("enqueue company resolution job",
		zap.String("component", "leave_resolution"),
		zap.String("company_id", companyID.String()),
		zap.String("reason", reason),
	)
	return s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		return s.resolverJobs.EnqueueCompanyResolution(ctx, tx, companyID, reason)
	})
}

// ============================================================
// Synchronous resolver — kept for the worker and single-user calls
// ============================================================

func (s *leavePolicyResolutionService) ResolveUserLeaveEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
	reason string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	logger := zap.L().With(
		zap.String("component", "leave_resolution"),
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
		zap.Time("as_of", asOf),
		zap.String("reason", reason),
	)

	logger.Info("resolve user — entry")

	idempKey := resolveUserIdempotencyKey(ctx, userID, asOf)
	logger.Debug("resolve user — idempotency key", zap.String("idemp_key", idempKey))

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("resolve user — short-circuited by idempotency",
			zap.String("idemp_key", idempKey),
		)
		return nil
	}

	positionID, workCenterCode, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		logger.Error("resolve user — GetUserPositionContext failed", zap.Error(err))
		return fmt.Errorf("failed to get user position context: %w", err)
	}
	logger.Info("resolve user — position context",
		zap.String("position_id", uuidPtrStr(positionID)),
		zap.String("work_center_code", strPtrStr(workCenterCode)),
	)

	rules, err := s.repo.ResolveUserPolicyRules(ctx, companyID, userID, asOf)
	if err != nil {
		logger.Error("resolve user — ResolveUserPolicyRules failed", zap.Error(err))
		return fmt.Errorf("resolve policy rules failed: %w", err)
	}
	logger.Info("resolve user — policy rules resolved", zap.Int("rule_count", len(rules)))

	for i, r := range rules {
		logger.Info("resolve user — rule",
			zap.Int("index", i),
			zap.String("policy_id", r.PolicyID.String()),
			zap.String("leave_type_id", r.LeaveTypeID.String()),
			zap.Int("total_days", r.TotalDays),
			zap.String("accrual_method", r.AccrualMethod),
			zap.String("carry_forward_limit", intPtrStr(r.CarryForwardLimit)),
		)
	}

	if len(rules) == 0 {
		logger.Warn("resolve user — no matching policy rules; skipping and storing marker")
		_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
		return ErrNoMatchingPolicy
	}

	processedLeaveTypes := make(map[uuid.UUID]bool)
	created, updated, skipped := 0, 0, 0

	for _, rule := range rules {
		if processedLeaveTypes[rule.LeaveTypeID] {
			logger.Info("resolve user — leave type already processed, skipping",
				zap.String("leave_type_id", rule.LeaveTypeID.String()),
			)
			continue
		}

		existing, err := s.repo.GetActivePolicyEntitlement(ctx, companyID, userID, rule.LeaveTypeID, positionID)
		if err != nil {
			logger.Error("resolve user — GetActivePolicyEntitlement failed",
				zap.String("leave_type_id", rule.LeaveTypeID.String()),
				zap.Error(err),
			)
			return fmt.Errorf("failed to check existing entitlement: %w", err)
		}

		if existing != nil {
			logger.Info("resolve user — existing entitlement found",
				zap.String("leave_type_id", rule.LeaveTypeID.String()),
				zap.String("existing_policy_id", uuidPtrStr(existing.PolicyID)),
				zap.String("target_policy_id", rule.PolicyID.String()),
				zap.Int("existing_total_days", existing.TotalDays),
				zap.Int("target_total_days", rule.TotalDays),
			)
		} else {
			logger.Info("resolve user — no existing entitlement; will create",
				zap.String("leave_type_id", rule.LeaveTypeID.String()),
				zap.String("target_policy_id", rule.PolicyID.String()),
				zap.Int("target_total_days", rule.TotalDays),
			)
		}

		if existing != nil && existing.PolicyID != nil &&
			*existing.PolicyID == rule.PolicyID &&
			existing.TotalDays == rule.TotalDays {
			logger.Info("resolve user — entitlement already correct; skipping",
				zap.String("leave_type_id", rule.LeaveTypeID.String()),
				zap.String("policy_id", rule.PolicyID.String()),
				zap.Int("total_days", rule.TotalDays),
			)
			processedLeaveTypes[rule.LeaveTypeID] = true
			skipped++
			continue
		}

		if err := s.repo.EndActivePolicyEntitlementsByLeaveType(
			ctx, companyID, userID, rule.LeaveTypeID, asOf, positionID,
		); err != nil {
			logger.Error("resolve user — EndActivePolicyEntitlementsByLeaveType failed",
				zap.String("leave_type_id", rule.LeaveTypeID.String()),
				zap.Error(err),
			)
			return fmt.Errorf("failed to end entitlement: %w", err)
		}
		logger.Info("resolve user — ended old entitlements for leave type",
			zap.String("leave_type_id", rule.LeaveTypeID.String()),
			zap.Time("end_date", asOf),
		)

		entitlement := &models.LeaveEntitlement{
			EntitlementID:  uuid.New(),
			CompanyID:      companyID,
			UserID:         userID,
			LeaveTypeID:    rule.LeaveTypeID,
			TotalDays:      rule.TotalDays,
			EffectiveFrom:  asOf,
			PolicyID:       &rule.PolicyID,
			Source:         "policy",
			CreatedAt:      time.Now().UTC(),
			PositionID:     positionID,
			WorkCenterCode: workCenterCode,
		}
		if err := s.repo.CreatePolicyLeaveEntitlement(ctx, entitlement); err != nil {
			logger.Error("resolve user — CreatePolicyLeaveEntitlement failed",
				zap.String("leave_type_id", rule.LeaveTypeID.String()),
				zap.String("policy_id", rule.PolicyID.String()),
				zap.Error(err),
			)
			return fmt.Errorf("failed to create entitlement: %w", err)
		}

		logger.Info("resolve user — entitlement written",
			zap.String("entitlement_id", entitlement.EntitlementID.String()),
			zap.String("leave_type_id", rule.LeaveTypeID.String()),
			zap.String("policy_id", rule.PolicyID.String()),
			zap.Int("total_days", rule.TotalDays),
		)
		processedLeaveTypes[rule.LeaveTypeID] = true

		if existing != nil {
			updated++
		} else {
			created++
		}
	}

	logger.Info("resolve user — summary",
		zap.Int("created", created),
		zap.Int("updated", updated),
		zap.Int("skipped", skipped),
		zap.Int("total_rules", len(rules)),
	)

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"company_id": companyID.String(),
		"user_id":    userID.String(),
		"as_of":      asOf,
		"reason":     reason,
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "leave", "resolution.user", "leave_entitlement",
		nil, actorType, &actorID, nil, nil, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	logger.Info("resolve user — done")
	return nil
}

func (s *leavePolicyResolutionService) ResolveBatchLeaveEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userIDs []uuid.UUID,
	asOf time.Time,
	reason string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*LeavePolicyResolutionResult, error) {
	logger := zap.L().With(
		zap.String("component", "leave_resolution"),
		zap.String("company_id", companyID.String()),
		zap.Int("user_count", len(userIDs)),
		zap.String("reason", reason),
	)
	logger.Info("resolve batch — entry")

	batchKey := resolveBatchIdempotencyKey(ctx)
	logger.Debug("resolve batch — idempotency key", zap.String("batch_key", batchKey))

	var cached *LeavePolicyResolutionResult
	if err := s.idempotencyStore.Get(ctx, nil, batchKey, &cached); err == nil && cached != nil {
		logger.Info("resolve batch — short-circuited by idempotency",
			zap.String("batch_key", batchKey),
		)
		return cached, nil
	}

	result := &LeavePolicyResolutionResult{
		TotalUsers:   len(userIDs),
		SkippedUsers: []uuid.UUID{},
		FailedUsers:  []uuid.UUID{},
		Errors:       []string{},
	}
	for _, userID := range userIDs {
		err := s.ResolveUserLeaveEntitlements(
			ctx, companyID, userID, asOf, reason, actorType, actorID, metadata,
		)
		switch {
		case err == nil:
			result.ProcessedUsers++
		case errors.Is(err, ErrNoMatchingPolicy):
			result.SkippedUsers = append(result.SkippedUsers, userID)
		default:
			result.FailedUsers = append(result.FailedUsers, userID)
			result.Errors = append(result.Errors, err.Error())
		}
	}

	logger.Info("resolve batch — summary",
		zap.Int("total", result.TotalUsers),
		zap.Int("processed", result.ProcessedUsers),
		zap.Int("skipped", len(result.SkippedUsers)),
		zap.Int("failed", len(result.FailedUsers)),
	)

	ip, _ := ctx.Value("ip_address").(string)
	afterJSON, _ := json.Marshal(result)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"company_id": companyID.String(),
		"total":      result.TotalUsers,
		"processed":  result.ProcessedUsers,
		"skipped":    len(result.SkippedUsers),
		"failed":     len(result.FailedUsers),
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "leave", "resolution.batch", "leave_entitlement",
		nil, actorType, &actorID, nil, afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, batchKey, result)

	logger.Info("resolve batch — done")
	return result, nil
}

func (s *leavePolicyResolutionService) GetLeaveEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userID *uuid.UUID,
	locationID *uuid.UUID,
	page, pageSize int,
) ([]*models.LeaveEntitlement, int64, error) {
	return s.repo.GetLeaveEntitlementsByCompanyAndUser(ctx, companyID, userID, locationID, page, pageSize)
}

func (s *leavePolicyResolutionService) GetUserEffectivePolicies(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) ([]*models.LeavePolicyRuleResolution, error) {
	return s.repo.ResolveUserPolicyRules(ctx, companyID, userID, asOf)
}

// ============================================================
// Resolver worker support
// ============================================================

func (s *leavePolicyResolutionService) EndActivePolicyEntitlements(
	ctx context.Context, companyID, userID uuid.UUID, effectiveTo time.Time,
) error {
	positionID, _, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		return fmt.Errorf("get user position context: %w", err)
	}
	return s.repo.EndActivePolicyEntitlements(ctx, companyID, userID, effectiveTo, positionID)
}

func (s *leavePolicyResolutionService) ListActiveEmployeeUserIDs(
	ctx context.Context, companyID uuid.UUID,
) ([]uuid.UUID, error) {
	return s.repo.ListActiveEmployeeUserIDs(ctx, companyID)
}

func (s *leavePolicyResolutionService) ListActiveEmployeeUserIDsByPosition(
	ctx context.Context, companyID, positionID uuid.UUID,
) ([]uuid.UUID, error) {
	return s.repo.ListActiveEmployeeUserIDsByPosition(ctx, companyID, positionID)
}

// ============================================================
// Idempotency key helpers
// ============================================================

// resolveUserIdempotencyKey builds a per-user, per-operation key.
//
// Priority order:
//
//  1. resolver_job_id  → one key per resolver job, unique across jobs.
//     Multiple jobs for the same user on the same day
//     each get their own key and both run.
//
//  2. idempotency_key  → one key per HTTP request. Retries of the same
//     request are idempotent; distinct clicks are not.
//
//  3. fallback         → day-scoped, last-resort safety net. Only fires
//     when a caller supplies NEITHER a job id NOR a
//     request key — a wiring bug we want to collapse
//     rather than multiply.
func resolveUserIdempotencyKey(ctx context.Context, userID uuid.UUID, asOf time.Time) string {
	if jobID, _ := ctx.Value("resolver_job_id").(string); jobID != "" {
		return fmt.Sprintf("resolve_user_job-%s-user-%s", jobID, userID.String())
	}
	if reqKey, _ := ctx.Value("idempotency_key").(string); reqKey != "" {
		return fmt.Sprintf("%s-user-%s", reqKey, userID.String())
	}
	return fmt.Sprintf("resolve_user-%s-%s", userID.String(), asOf.Format("2006-01-02"))
}

func resolveBatchIdempotencyKey(ctx context.Context) string {
	if reqKey, _ := ctx.Value("idempotency_key").(string); reqKey != "" {
		return fmt.Sprintf("%s-batch", reqKey)
	}
	return fmt.Sprintf("resolve_batch-%s", uuid.New().String())
}

// ============================================================
// Logging helpers — small pointer→string adapters so zap fields
// don't panic on nil pointers and read cleanly in the log output.
// ============================================================

func uuidPtrStr(id *uuid.UUID) string {
	if id == nil {
		return "<nil>"
	}
	return id.String()
}

func strPtrStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func intPtrStr(i *int) string {
	if i == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%d", *i)
}
