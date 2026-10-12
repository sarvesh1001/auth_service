package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

type LeavePolicyConfigService interface {
	CreatePolicy(ctx context.Context, policy *models.LeavePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeavePolicy, error)
	DeactivatePolicy(ctx context.Context, policyID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	GetPolicy(ctx context.Context, policyID uuid.UUID) (*models.LeavePolicy, error)
	ListActivePolicies(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]*models.LeavePolicy, error)
	UpdatePolicy(ctx context.Context, policyID uuid.UUID, update *models.LeavePolicyUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	AddPolicyRule(ctx context.Context, rule *models.LeavePolicyRule, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeavePolicyRule, error)
	UpdatePolicyRule(ctx context.Context, companyID uuid.UUID, policyRuleID uuid.UUID, update *models.LeavePolicyRuleUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	RemovePolicyRule(ctx context.Context, policyRuleID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	GetPolicyRules(ctx context.Context, policyID uuid.UUID) ([]*models.LeavePolicyRule, error)
}

type leavePolicyConfigService struct {
	repo             repository.LeaveRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService

	pgClient     *client.PostgresClient
	resolverJobs repository.ResolverJobRepository
}

func NewLeavePolicyConfigService(
	repo repository.LeaveRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	resolverJobs repository.ResolverJobRepository,
) LeavePolicyConfigService {
	return &leavePolicyConfigService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		resolverJobs:     resolverJobs,
	}
}

// withResolutionEnqueue runs a policy mutation inside a transaction, then
// enqueues the company-wide resolution job in the SAME transaction. If either
// the write or the enqueue fails, both roll back — a policy change cannot be
// persisted without a corresponding resolver job.
//
// Rationale: the previous "write first, enqueue best-effort" pattern left the
// system in a state where a policy was live but every employee's entitlement
// still reflected the old rules, silently. The next policy edit would catch
// up, but that could be days away.
func (s *leavePolicyConfigService) withResolutionEnqueue(
	ctx context.Context,
	companyID uuid.UUID,
	reason string,
	fn func(tx *sql.Tx) error,
) error {
	if s.pgClient == nil {
		return errors.New("postgres client not configured")
	}
	if s.resolverJobs == nil {
		return errors.New("resolver job repository not configured")
	}
	if companyID == uuid.Nil {
		return errors.New("company_id is required for policy change")
	}
	return s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return s.resolverJobs.EnqueueCompanyResolution(ctx, tx, companyID, reason)
	})
}

// ---------- POLICY ----------

func (s *leavePolicyConfigService) CreatePolicy(
	ctx context.Context,
	policy *models.LeavePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeavePolicy, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_policy-%s", uuid.New().String())
	}
	var cached *models.LeavePolicy
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	// ── Validation ──────────────────────────────────────────────────
	if policy.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company_id is required")
	}
	if policy.PolicyName == "" {
		return nil, fmt.Errorf("policy_name is required")
	}
	if policy.AppliesToType == "" {
		return nil, fmt.Errorf("applies_to_type is required")
	}
	switch policy.AppliesToType {
	case "company":
		policy.AppliesToPositionID = nil
		policy.AppliesToWorkCenterCode = nil
	case "position":
		if policy.AppliesToPositionID == nil {
			return nil, fmt.Errorf("applies_to_position_id required")
		}
	case "work_center":
		if policy.AppliesToWorkCenterCode == nil {
			return nil, fmt.Errorf("applies_to_work_center_code required")
		}
	default:
		return nil, fmt.Errorf("invalid applies_to_type")
	}
	if policy.Priority <= 0 {
		return nil, fmt.Errorf("priority must be > 0")
	}

	policy.PolicyID = uuid.New()
	policy.IsActive = true
	policy.CreatedAt = time.Now().UTC()

	// ── Write + enqueue atomically ─────────────────────────────────
	if err := s.withResolutionEnqueue(ctx, policy.CompanyID, "policy change",
		func(tx *sql.Tx) error {
			return s.repo.CreateLeavePolicyTx(ctx, tx, policy)
		},
	); err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}

	// ── Audit + idempotency (after commit, best-effort) ────────────
	afterJSON, _ := json.Marshal(policy)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"policy_id":  policy.PolicyID.String(),
		"company_id": policy.CompanyID.String(),
		"name":       policy.PolicyName,
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&policy.CompanyID,
		"leave",
		"policy.create",
		"leave_policy",
		&policy.PolicyID,
		actorType,
		&actorID,
		[]byte("{}"),
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, policy)

	return policy, nil
}

func (s *leavePolicyConfigService) DeactivatePolicy(
	ctx context.Context,
	policyID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("deactivate_policy-%s", policyID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	policy, err := s.repo.GetLeavePolicyByID(ctx, policyID)
	if err != nil {
		return err
	}
	beforeJSON, _ := json.Marshal(policy)

	// ── Write + enqueue atomically ─────────────────────────────────
	if err := s.withResolutionEnqueue(ctx, policy.CompanyID, "policy change",
		func(tx *sql.Tx) error {
			return s.repo.DeactivateLeavePolicyTx(ctx, tx, policyID)
		},
	); err != nil {
		return fmt.Errorf("deactivate policy: %w", err)
	}

	// ── Audit + idempotency ────────────────────────────────────────
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"policy_id": policyID.String(),
		"ip":        ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&policy.CompanyID,
		"leave",
		"policy.deactivate",
		"leave_policy",
		&policyID,
		actorType,
		&actorID,
		beforeJSON,
		[]byte("{}"),
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

func (s *leavePolicyConfigService) GetPolicy(ctx context.Context, policyID uuid.UUID) (*models.LeavePolicy, error) {
	return s.repo.GetLeavePolicyByID(ctx, policyID)
}

func (s *leavePolicyConfigService) ListActivePolicies(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]*models.LeavePolicy, error) {
	return s.repo.GetActiveLeavePoliciesByCompany(ctx, companyID, asOf)
}

func (s *leavePolicyConfigService) UpdatePolicy(
	ctx context.Context,
	policyID uuid.UUID,
	update *models.LeavePolicyUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_policy-%s", policyID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	policy, err := s.repo.GetLeavePolicyByID(ctx, policyID)
	if err != nil {
		return err
	}
	beforeJSON, _ := json.Marshal(policy)

	// ── Validation ────────────────────────────────────────────────
	if update.AppliesToType != nil {
		switch *update.AppliesToType {
		case "company":
			update.AppliesToPositionID = nil
			update.AppliesToWorkCenterCode = nil
		case "position":
			if update.AppliesToPositionID == nil {
				return fmt.Errorf("applies_to_position_id required")
			}
		case "work_center":
			if update.AppliesToWorkCenterCode == nil {
				return fmt.Errorf("applies_to_work_center_code required")
			}
		default:
			return fmt.Errorf("invalid applies_to_type")
		}
	}
	if update.Priority != nil && *update.Priority <= 0 {
		return fmt.Errorf("priority must be > 0")
	}

	// ── Write + enqueue atomically ─────────────────────────────────
	if err := s.withResolutionEnqueue(ctx, policy.CompanyID, "policy change",
		func(tx *sql.Tx) error {
			return s.repo.UpdateLeavePolicyTx(ctx, tx, policyID, update)
		},
	); err != nil {
		return fmt.Errorf("update policy: %w", err)
	}

	// ── Audit + idempotency ────────────────────────────────────────
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"policy_id": policyID.String(),
		"ip":        ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&policy.CompanyID,
		"leave",
		"policy.update",
		"leave_policy",
		&policyID,
		actorType,
		&actorID,
		beforeJSON,
		nil,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

// ---------- RULES ----------

func (s *leavePolicyConfigService) AddPolicyRule(
	ctx context.Context,
	rule *models.LeavePolicyRule,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeavePolicyRule, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("add_rule-%s", uuid.New().String())
	}
	var cached *models.LeavePolicyRule
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	// ── Validation ────────────────────────────────────────────────
	if rule.PolicyID == uuid.Nil {
		return nil, fmt.Errorf("policy_id required")
	}
	if rule.LeaveTypeID == uuid.Nil {
		return nil, fmt.Errorf("leave_type_id required")
	}
	if rule.TotalDays <= 0 {
		return nil, fmt.Errorf("total_days must be > 0")
	}

	// Look up the parent policy up-front so we have companyID for both the
	// transaction closure and the audit metadata. If the policy is missing,
	// fail before we attempt the insert.
	policy, err := s.repo.GetLeavePolicyByID(ctx, rule.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("parent policy not found: %w", err)
	}

	rule.PolicyRuleID = uuid.New()
	rule.CreatedAt = time.Now().UTC()

	// ── Write + enqueue atomically ─────────────────────────────────
	if err := s.withResolutionEnqueue(ctx, policy.CompanyID, "policy change",
		func(tx *sql.Tx) error {
			return s.repo.AddPolicyRuleTx(ctx, tx, rule)
		},
	); err != nil {
		return nil, fmt.Errorf("add policy rule: %w", err)
	}

	// ── Audit + idempotency ────────────────────────────────────────
	afterJSON, _ := json.Marshal(rule)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"policy_rule_id": rule.PolicyRuleID.String(),
		"policy_id":      rule.PolicyID.String(),
		"leave_type_id":  rule.LeaveTypeID.String(),
		"ip":             ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&policy.CompanyID,
		"leave",
		"policy_rule.add",
		"leave_policy_rule",
		&rule.PolicyRuleID,
		actorType,
		&actorID,
		[]byte("{}"),
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, rule)

	return rule, nil
}

func (s *leavePolicyConfigService) RemovePolicyRule(
	ctx context.Context,
	policyRuleID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("remove_rule-%s", policyRuleID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// ── Resolve the parent policy so we know which company to re-resolve.
	//    Previously this relied on metadata["company_id"], which is a bug:
	//    if the handler forgot to supply it, no resolver job was enqueued
	//    and no error was raised. Now we look it up explicitly.
	policyRule, err := s.repo.GetPolicyRuleByID(ctx, policyRuleID)
	if err != nil {
		return fmt.Errorf("policy rule not found: %w", err)
	}
	policy, err := s.repo.GetLeavePolicyByID(ctx, policyRule.PolicyID)
	if err != nil {
		return fmt.Errorf("parent policy not found: %w", err)
	}

	// ── Write + enqueue atomically ─────────────────────────────────
	if err := s.withResolutionEnqueue(ctx, policy.CompanyID, "policy change",
		func(tx *sql.Tx) error {
			return s.repo.DeletePolicyRuleTx(ctx, tx, policyRuleID)
		},
	); err != nil {
		return fmt.Errorf("remove policy rule: %w", err)
	}

	// ── Audit + idempotency ────────────────────────────────────────
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"policy_rule_id": policyRuleID.String(),
		"policy_id":      policy.PolicyID.String(),
		"company_id":     policy.CompanyID.String(),
		"ip":             ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&policy.CompanyID,
		"leave",
		"policy_rule.remove",
		"leave_policy_rule",
		&policyRuleID,
		actorType,
		&actorID,
		nil,
		[]byte("{}"),
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

func (s *leavePolicyConfigService) GetPolicyRules(ctx context.Context, policyID uuid.UUID) ([]*models.LeavePolicyRule, error) {
	return s.repo.GetPolicyRules(ctx, policyID)
}

func (s *leavePolicyConfigService) UpdatePolicyRule(
	ctx context.Context,
	companyID uuid.UUID,
	policyRuleID uuid.UUID,
	update *models.LeavePolicyRuleUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_rule-%s", policyRuleID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// ── Validation ────────────────────────────────────────────────
	if update.TotalDays != nil && *update.TotalDays <= 0 {
		return fmt.Errorf("total_days must be > 0")
	}
	if update.CarryForwardLimit != nil && *update.CarryForwardLimit < 0 {
		return fmt.Errorf("carry_forward_limit cannot be negative")
	}
	if update.AccrualMethod != nil {
		valid := map[string]bool{"none": true, "monthly": true, "quarterly": true, "yearly": true}
		if !valid[*update.AccrualMethod] {
			return fmt.Errorf("invalid accrual method")
		}
	}

	// ── Write + enqueue atomically ─────────────────────────────────
	if err := s.withResolutionEnqueue(ctx, companyID, "policy change",
		func(tx *sql.Tx) error {
			return s.repo.UpdatePolicyRuleTx(ctx, tx, companyID, policyRuleID, update)
		},
	); err != nil {
		return fmt.Errorf("update policy rule: %w", err)
	}

	// ── Audit + idempotency ────────────────────────────────────────
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"policy_rule_id": policyRuleID.String(),
		"company_id":     companyID.String(),
		"ip":             ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"leave",
		"policy_rule.update",
		"leave_policy_rule",
		&policyRuleID,
		actorType,
		&actorID,
		nil,
		nil,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}
