package exemption

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/resolver"
	auditservice "auth-service/internal/infrastructure/audit"
	"auth-service/internal/locationctx"
)

// Sentinel errors — handlers can map these to HTTP status codes with errors.Is.
var (
	ErrExemptionNotFound = errors.New("exemption not found")
	ErrInvalidSubject    = errors.New("invalid subject_type")
	ErrInvalidDateRange  = errors.New("from_date must be on or before to_date")
	ErrOverlap           = errors.New("overlapping exemption already exists for this subject")
	ErrUnauthorized      = errors.New("actor is not authorized for this subject")
)

// Allowed subjects — keep in sync with the resolver package constants.
var allowedSubjectTypes = map[string]struct{}{
	resolver.SubjectTypeEmployee: {},
	resolver.SubjectTypeStudent:  {},
	resolver.SubjectTypeCustomer: {},
}

type CreateExemptionInput struct {
	SubjectType string
	SubjectID   uuid.UUID
	FromDate    time.Time
	ToDate      time.Time
	Reason      *string
	ApprovedBy  *uuid.UUID // optional, admin-supplied
}

type UpdateExemptionInput struct {
	FromDate   *time.Time
	ToDate     *time.Time
	Reason     *string
	ApprovedBy *uuid.UUID
}

type ExemptionService interface {
	Create(
		ctx context.Context,
		companyID uuid.UUID,
		input *CreateExemptionInput,
		actorType string,
		actorID uuid.UUID,
	) (*models.AttendanceExemption, error)

	Update(
		ctx context.Context,
		companyID uuid.UUID,
		exemptionID uuid.UUID,
		input *UpdateExemptionInput,
		actorType string,
		actorID uuid.UUID,
	) (*models.AttendanceExemption, error)

	Delete(
		ctx context.Context,
		companyID uuid.UUID,
		exemptionID uuid.UUID,
		actorType string,
		actorID uuid.UUID,
	) error

	GetByID(
		ctx context.Context,
		companyID uuid.UUID,
		exemptionID uuid.UUID,
	) (*models.AttendanceExemption, error)
}

type exemptionService struct {
	repo             repository.AttendanceExemptionRepository
	locationResolver resolver.SubjectLocationResolver
	audit            *auditservice.AuditService
	logger           *zap.Logger
}

func NewExemptionService(
	repo repository.AttendanceExemptionRepository,
	locationResolver resolver.SubjectLocationResolver,
	audit *auditservice.AuditService,
	logger *zap.Logger,
) ExemptionService {
	return &exemptionService{
		repo:             repo,
		locationResolver: locationResolver,
		audit:            audit,
		logger:           logger,
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (s *exemptionService) Create(
	ctx context.Context,
	companyID uuid.UUID,
	input *CreateExemptionInput,
	actorType string,
	actorID uuid.UUID,
) (*models.AttendanceExemption, error) {
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company_id is required")
	}
	if input == nil {
		return nil, fmt.Errorf("input is required")
	}
	if _, ok := allowedSubjectTypes[input.SubjectType]; !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSubject, input.SubjectType)
	}
	if input.SubjectID == uuid.Nil {
		return nil, fmt.Errorf("subject_id is required")
	}
	if input.FromDate.IsZero() || input.ToDate.IsZero() {
		return nil, fmt.Errorf("from_date and to_date are required")
	}
	if input.FromDate.After(input.ToDate) {
		return nil, ErrInvalidDateRange
	}

	// Enforce caller's location scope against the target subject.
	if err := s.ensureSubjectInScope(ctx, companyID, input.SubjectType, input.SubjectID); err != nil {
		return nil, err
	}

	// Reject overlaps: any active exemption that touches the same window.
	overlaps, err := s.hasOverlap(ctx, companyID, input.SubjectType, input.SubjectID, input.FromDate, input.ToDate, uuid.Nil)
	if err != nil {
		return nil, fmt.Errorf("check overlap: %w", err)
	}
	if overlaps {
		return nil, ErrOverlap
	}

	var createdBy *uuid.UUID
	if actorID != uuid.Nil {
		createdBy = &actorID
	}

	exemption := &models.AttendanceExemption{
		CompanyID:   companyID,
		SubjectType: input.SubjectType,
		SubjectID:   input.SubjectID,
		FromDate:    input.FromDate,
		ToDate:      input.ToDate,
		Reason:      input.Reason,
		ApprovedBy:  input.ApprovedBy,
		CreatedBy:   createdBy,
	}

	if err := s.repo.Create(ctx, nil, exemption); err != nil {
		return nil, fmt.Errorf("create exemption: %w", err)
	}

	s.logAudit(ctx, companyID, "attendance.exemption.create", exemption.ExemptionID,
		actorType, actorID, nil, exemption, nil)
	s.logger.Info("Attendance exemption created",
		zap.String("company_id", companyID.String()),
		zap.String("subject_type", exemption.SubjectType),
		zap.String("subject_id", exemption.SubjectID.String()),
	)
	return exemption, nil
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (s *exemptionService) Update(
	ctx context.Context,
	companyID uuid.UUID,
	exemptionID uuid.UUID,
	input *UpdateExemptionInput,
	actorType string,
	actorID uuid.UUID,
) (*models.AttendanceExemption, error) {
	if exemptionID == uuid.Nil {
		return nil, fmt.Errorf("exemption_id is required")
	}
	if input == nil {
		return nil, fmt.Errorf("input is required")
	}

	existing, err := s.fetchScoped(ctx, companyID, exemptionID)
	if err != nil {
		return nil, err
	}
	before := *existing // shallow copy for audit

	// Apply mutations.
	if input.FromDate != nil {
		existing.FromDate = *input.FromDate
	}
	if input.ToDate != nil {
		existing.ToDate = *input.ToDate
	}
	if input.Reason != nil {
		existing.Reason = input.Reason
	}
	if input.ApprovedBy != nil {
		existing.ApprovedBy = input.ApprovedBy
	}

	if existing.FromDate.After(existing.ToDate) {
		return nil, ErrInvalidDateRange
	}

	// Re-run scope check in case the subject was reassigned since creation.
	if err := s.ensureSubjectInScope(ctx, companyID, existing.SubjectType, existing.SubjectID); err != nil {
		return nil, err
	}

	// Overlap check must exclude this row.
	overlaps, err := s.hasOverlap(ctx, companyID, existing.SubjectType, existing.SubjectID,
		existing.FromDate, existing.ToDate, exemptionID)
	if err != nil {
		return nil, fmt.Errorf("check overlap: %w", err)
	}
	if overlaps {
		return nil, ErrOverlap
	}

	if err := s.repo.Update(ctx, nil, existing); err != nil {
		return nil, fmt.Errorf("update exemption: %w", err)
	}

	s.logAudit(ctx, companyID, "attendance.exemption.update", exemptionID,
		actorType, actorID, before, existing, nil)
	s.logger.Info("Attendance exemption updated",
		zap.String("exemption_id", exemptionID.String()),
		zap.String("company_id", companyID.String()),
	)
	return existing, nil
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (s *exemptionService) Delete(
	ctx context.Context,
	companyID uuid.UUID,
	exemptionID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
) error {
	if exemptionID == uuid.Nil {
		return fmt.Errorf("exemption_id is required")
	}

	existing, err := s.fetchScoped(ctx, companyID, exemptionID)
	if err != nil {
		return err
	}

	if err := s.repo.Delete(ctx, nil, exemptionID); err != nil {
		return fmt.Errorf("delete exemption: %w", err)
	}

	s.logAudit(ctx, companyID, "attendance.exemption.delete", exemptionID,
		actorType, actorID, existing, nil, nil)
	s.logger.Info("Attendance exemption deleted",
		zap.String("exemption_id", exemptionID.String()),
		zap.String("company_id", companyID.String()),
	)
	return nil
}

// ---------------------------------------------------------------------------
// GetByID (read, still company-scoped)
// ---------------------------------------------------------------------------

func (s *exemptionService) GetByID(
	ctx context.Context,
	companyID uuid.UUID,
	exemptionID uuid.UUID,
) (*models.AttendanceExemption, error) {
	return s.fetchScoped(ctx, companyID, exemptionID)
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

// fetchScoped loads by ID and rejects rows that belong to a different company.
// Returns ErrExemptionNotFound (not Forbidden) so we don't leak existence.
func (s *exemptionService) fetchScoped(
	ctx context.Context,
	companyID uuid.UUID,
	exemptionID uuid.UUID,
) (*models.AttendanceExemption, error) {
	row, err := s.repo.GetByID(ctx, nil, exemptionID)
	if err != nil {
		return nil, fmt.Errorf("get exemption: %w", err)
	}
	if row == nil || row.CompanyID != companyID {
		return nil, ErrExemptionNotFound
	}
	return row, nil
}

// ensureSubjectInScope mirrors CorrectionService.ensureSubjectInScope.
func (s *exemptionService) ensureSubjectInScope(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
) error {
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		// No location context → treat as fail-closed for mutations.
		// If your middleware guarantees one for every request, this
		// branch should be unreachable.
		return fmt.Errorf("location context missing: %w", ErrUnauthorized)
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}
	if s.locationResolver == nil {
		return nil // no resolver wired → can't enforce, allow (log-only mode)
	}
	subjectLoc, err := s.locationResolver.ResolveLocation(ctx, companyID, subjectType, subjectID)
	if err != nil {
		return fmt.Errorf("resolve subject location: %w", err)
	}
	if subjectLoc == nil {
		return resolver.ErrSubjectHasNoLocation
	}
	if locCtx.LocationID == nil || *subjectLoc != *locCtx.LocationID {
		return resolver.ErrSubjectOutsideScope
	}
	return nil
}

// hasOverlap returns true if any *other* exemption for the same subject
// intersects the [from, to] window. excludeID skips the current row during update.
func (s *exemptionService) hasOverlap(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
	from, to time.Time,
	excludeID uuid.UUID,
) (bool, error) {
	filter := repository.ExemptionFilter{
		CompanyID:   &companyID,
		SubjectType: &subjectType,
		SubjectID:   &subjectID,
		FromDate:    &from,
		ToDate:      &to,
	}
	pag := repository.Pagination{Limit: 1000, Offset: 0}
	rows, err := s.repo.List(ctx, nil, filter, pag)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if excludeID != uuid.Nil && r.ExemptionID == excludeID {
			continue
		}
		// Overlap: NOT (r.ToDate < from || r.FromDate > to)
		if !r.ToDate.Before(from) && !r.FromDate.After(to) {
			return true, nil
		}
	}
	return false, nil
}

func (s *exemptionService) logAudit(
	ctx context.Context,
	companyID uuid.UUID,
	action string,
	resourceID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	before interface{},
	after interface{},
	metadata map[string]interface{},
) {
	if s.audit == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(before)
	}
	if after != nil {
		afterJSON, _ = json.Marshal(after)
	}
	var actorPtr *uuid.UUID
	if actorID != uuid.Nil {
		actorPtr = &actorID
	}
	_ = s.audit.LogAction(
		ctx, nil, &companyID,
		"attendance", action, "attendance_exemption",
		&resourceID, actorType, actorPtr,
		beforeJSON, afterJSON, metadata,
	)
}