// internal/hr/service/reminder_service.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/models/employee"
	"auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
)

// ============================================================================
// Constants — reminder types and severities. SQL strings and Go must agree.
// ============================================================================

const (
	// Family prefixes — anything starting with these is closed by
	// MarkActioned when HR acts on the underlying thing.
	ReminderTypePrefixProbation = "probation_"
	ReminderTypePrefixOnHold    = "on_hold_"
	ReminderTypePrefixNotice    = "notice_"

	// Concrete types
	ReminderProbationT14     = "probation_reminder_t14"
	ReminderProbationT7      = "probation_reminder_t7"
	ReminderProbationT3      = "probation_reminder_t3"
	ReminderProbationOverdue = "probation_overdue"

	ReminderOnHoldExpiring = "on_hold_expiring"

	ReminderNoticeExpiring = "notice_expiring"

	// Confirmation events — no action required, just an FYI row
	ReminderProbationConfirmed = "probation_confirmed"
	ReminderProbationFailed    = "probation_failed"
	ReminderProbationExtended  = "probation_extended"
	ReminderOnHoldStarted      = "on_hold_started"
	ReminderOnHoldEnded        = "on_hold_ended"
)

const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// ============================================================================
// Recipient resolution
// ============================================================================

// RecipientInfo is a single user who should see a reminder.
type RecipientInfo struct {
	UserID   uuid.UUID
	UserType string // "hr" | "manager" | "admin"
}

// RecipientResolver finds everyone who should receive a reminder about an
// employee.
//
// Implementations MUST be scope-aware:
//   - ALL-scope HR       → always included
//   - PRIMARY-scope HR   → included only if the subject is at their primary
//   - SELECTED-scope HR  → included only if they have a grant for the
//     subject's location
//
// This is enforced at the DB query level in HRRecipientResolverImpl, so
// reminders never land in the inbox of HR users who cannot act on them.
type RecipientResolver interface {
	ResolveRecipients(
		ctx context.Context,
		companyID uuid.UUID,
		subjectUserID uuid.UUID,
	) ([]RecipientInfo, error)
}

// ============================================================================
// ActionPayload — deep-link metadata the mobile app uses to route
// ============================================================================

type ActionPayload struct {
	Screen            string `json:"screen"`                // "probation" | "on_hold" | "notice" | "employee"
	EmployeeID        string `json:"employee_id,omitempty"` // user_id
	EmployeeProfileID string `json:"employee_profile_id,omitempty"`
	EntityID          string `json:"entity_id,omitempty"` // probation_id / notice_id / on_hold_id
	EndDate           string `json:"end_date,omitempty"`  // "2006-01-02"
	ExtraNote         string `json:"extra_note,omitempty"`
}

// ============================================================================
// Service
// ============================================================================

type ReminderService struct {
	repo     repository.ReminderRepository
	resolver RecipientResolver
	audit    *audit.AuditService
	logger   *zap.Logger
}

func NewReminderService(
	repo repository.ReminderRepository,
	resolver RecipientResolver,
	auditService *audit.AuditService,
	logger *zap.Logger,
) *ReminderService {
	if repo == nil {
		panic("reminder repository is required")
	}
	if resolver == nil {
		panic("recipient resolver is required")
	}
	if auditService == nil {
		panic("audit service is required")
	}
	if logger == nil {
		logger = zap.L()
	}
	return &ReminderService{
		repo:     repo,
		resolver: resolver,
		audit:    auditService,
		logger:   logger.Named("reminder_service"),
	}
}

// ============================================================================
// Dispatch — the write path called by LifecycleNotifierImpl and lifecycle hooks
// ============================================================================

// DispatchInput describes one reminder event.
type DispatchInput struct {
	CompanyID     uuid.UUID
	SubjectUserID uuid.UUID

	// LocationID stamps every row with the subject employee's current
	// primary_location_id. nil = company-wide reminder (visible to ALL-
	// scope HR users only). Resolved by LifecycleNotifierImpl before
	// dispatch; callers constructing an input manually must set it
	// themselves if the reminder is location-scoped.
	LocationID *uuid.UUID

	Type     string // one of the Reminder* constants
	Severity string // SeverityInfo | SeverityWarning | SeverityCritical

	Title string
	Body  string

	// Action is optional; omit for FYI reminders (e.g. "probation confirmed").
	Action *ActionPayload

	// DedupeScope makes the row unique per (recipient, type, scope).
	// Convention: the date the reminder is *about*, e.g. probation end date
	// for T-14, so reruns on the same day are no-ops. If zero, uses today.
	DedupeScope time.Time

	// ExpiresIn hides the row from the feed after this duration.
	// Zero = never expires.
	ExpiresIn time.Duration

	// Metadata is free-form extra context for the client.
	Metadata map[string]interface{}
}

// Dispatch resolves recipients, builds one reminder per recipient, and
// inserts them in a single batch. Duplicates on (recipient, dedupe_key)
// are silently skipped — safe to call repeatedly.
//
// Returns the number of rows inserted.
func (s *ReminderService) Dispatch(ctx context.Context, in DispatchInput) (int, error) {
	if in.CompanyID == uuid.Nil {
		return 0, fmt.Errorf("company_id is required")
	}
	if in.SubjectUserID == uuid.Nil {
		return 0, fmt.Errorf("subject_user_id is required")
	}
	if in.Type == "" || in.Title == "" {
		return 0, fmt.Errorf("type and title are required")
	}
	if in.Severity == "" {
		in.Severity = SeverityInfo
	}

	recipients, err := s.resolver.ResolveRecipients(ctx, in.CompanyID, in.SubjectUserID)
	if err != nil {
		return 0, fmt.Errorf("resolve recipients: %w", err)
	}
	if len(recipients) == 0 {
		s.logger.Warn("no recipients for reminder",
			zap.String("company_id", in.CompanyID.String()),
			zap.String("subject_user_id", in.SubjectUserID.String()),
			zap.String("type", in.Type),
		)
		return 0, nil
	}

	scopeDate := in.DedupeScope
	if scopeDate.IsZero() {
		scopeDate = time.Now().UTC()
	}
	scope := scopeDate.UTC().Format("2006-01-02")

	var actionJSON, metadataJSON json.RawMessage
	if in.Action != nil {
		actionJSON, _ = json.Marshal(in.Action)
	}
	if len(in.Metadata) > 0 {
		metadataJSON, _ = json.Marshal(in.Metadata)
	}

	var expiresAt *time.Time
	if in.ExpiresIn > 0 {
		t := time.Now().UTC().Add(in.ExpiresIn)
		expiresAt = &t
	}

	body := in.Body
	var bodyPtr *string
	if body != "" {
		bodyPtr = &body
	}

	rows := make([]*employee.Reminder, 0, len(recipients))
	for _, r := range recipients {
		rows = append(rows, &employee.Reminder{
			ReminderID:    uuid.New(),
			CompanyID:     in.CompanyID,
			RecipientID:   r.UserID,
			RecipientType: r.UserType,

			SubjectUserID: &in.SubjectUserID,

			// Stamp every row with the subject's location (nil = company-wide).
			LocationID: in.LocationID,

			ReminderType: in.Type,
			Severity:     in.Severity,
			Title:        in.Title,
			Body:         bodyPtr,

			ActionType:    actionTypeFor(in.Action),
			ActionPayload: actionJSON,

			Metadata: metadataJSON,
			Status:   "unread",

			ExpiresAt: expiresAt,

			// Dedupe key is per-recipient-unique. Combined with the unique
			// index (recipient_id, dedupe_key), reruns on the same day are
			// silent no-ops, but a fresh reminder next year is not.
			DedupeKey: fmt.Sprintf("%s:%s:%s", in.Type, in.SubjectUserID.String(), scope),

			CreatedAt: time.Now().UTC(),
		})
	}

	inserted, err := s.repo.CreateBatch(ctx, rows)
	if err != nil {
		return 0, fmt.Errorf("insert reminders: %w", err)
	}

	s.logger.Info("reminder dispatched",
		zap.String("company_id", in.CompanyID.String()),
		zap.String("subject_user_id", in.SubjectUserID.String()),
		zap.String("type", in.Type),
		zap.Any("location_id", in.LocationID),
		zap.Int("recipients", len(recipients)),
		zap.Int("inserted", inserted),
	)
	return inserted, nil
}

func actionTypeFor(a *ActionPayload) *string {
	if a == nil {
		return nil
	}
	s := "navigate"
	return &s
}

// ============================================================================
// MarkActioned — called by lifecycle methods after HR acts
// ============================================================================

// MarkActioned closes every open reminder about (subject, type-prefix).
//
// Example: after ConfirmProbation succeeds:
//
//	reminderSvc.MarkActioned(ctx, companyID, userID, ReminderTypePrefixProbation)
//
// → all probation reminders about that employee flip to 'actioned'
// → drop out of the unread badge
// → stay in history as resolved events.
//
// Errors are logged, never propagated — a reminder table issue must never
// fail the underlying business transition.
func (s *ReminderService) MarkActioned(
	ctx context.Context,
	companyID, subjectUserID uuid.UUID,
	typePrefix string,
) {
	n, err := s.repo.MarkActionedBySubject(ctx, companyID, subjectUserID, typePrefix)
	if err != nil {
		s.logger.Warn("mark reminders actioned failed",
			zap.String("company_id", companyID.String()),
			zap.String("subject_user_id", subjectUserID.String()),
			zap.String("type_prefix", typePrefix),
			zap.Error(err),
		)
		return
	}
	if n > 0 {
		s.logger.Info("reminders marked actioned",
			zap.String("subject_user_id", subjectUserID.String()),
			zap.String("type_prefix", typePrefix),
			zap.Int64("count", n),
		)
	}
}

// ============================================================================
// Feed reads — location-scoped
// ============================================================================

type ReminderFeedPage struct {
	Items       []*employee.Reminder `json:"items"`
	TotalCount  int                  `json:"total_count"`
	Page        int                  `json:"page"`
	PageSize    int                  `json:"page_size"`
	UnreadCount int                  `json:"unread_count"`
}

// List returns a page of the caller's feed, location-scoped to whatever
// filters.LocationIDs contains. Pass nil for ALL-scope users.
//
// The badge count uses the same location filter so the two agree — a
// caller viewing the Mumbai feed should not see a badge that includes
// Delhi reminders.
func (s *ReminderService) List(
	ctx context.Context,
	recipientID uuid.UUID,
	filters repository.ReminderFilters,
	page, pageSize int,
) (*ReminderFeedPage, error) {
	items, total, err := s.repo.List(ctx, recipientID, filters, page, pageSize)
	if err != nil {
		return nil, err
	}

	// Same location scope as the feed.
	unread, err := s.repo.UnreadCount(ctx, recipientID, filters.LocationIDs)
	if err != nil {
		// Non-fatal — the feed still works without the badge.
		s.logger.Warn("unread count failed", zap.Error(err))
		unread = 0
	}
	return &ReminderFeedPage{
		Items:       items,
		TotalCount:  total,
		Page:        page,
		PageSize:    pageSize,
		UnreadCount: unread,
	}, nil
}

type ReminderCounts struct {
	Unread     int            `json:"unread"`
	BySeverity map[string]int `json:"by_severity"`
}

// Counts returns the unread badge, scoped to locationIDs.
// Pass nil for ALL-scope users.
func (s *ReminderService) Counts(
	ctx context.Context,
	recipientID uuid.UUID,
	locationIDs []uuid.UUID,
) (*ReminderCounts, error) {
	total, err := s.repo.UnreadCount(ctx, recipientID, locationIDs)
	if err != nil {
		return nil, err
	}
	bySev, err := s.repo.CountBySeverity(ctx, recipientID, locationIDs)
	if err != nil {
		// Non-fatal.
		bySev = map[string]int{}
	}
	return &ReminderCounts{Unread: total, BySeverity: bySev}, nil
}

// ============================================================================
// Mutations — scoped to the calling HR user only (no location filter)
//
// Rationale: the caller already owns the reminder_id. Adding a location
// check would break the case where HR marks a reminder read and then
// switches location before the request lands.
// ============================================================================

func (s *ReminderService) MarkRead(ctx context.Context, recipientID, reminderID uuid.UUID) error {
	if reminderID == uuid.Nil {
		return fmt.Errorf("reminder_id is required")
	}
	return s.repo.MarkRead(ctx, recipientID, reminderID)
}

func (s *ReminderService) MarkAllRead(ctx context.Context, recipientID uuid.UUID) (int64, error) {
	return s.repo.MarkAllRead(ctx, recipientID)
}

func (s *ReminderService) Dismiss(ctx context.Context, recipientID, reminderID uuid.UUID) error {
	if reminderID == uuid.Nil {
		return fmt.Errorf("reminder_id is required")
	}
	return s.repo.Dismiss(ctx, recipientID, reminderID)
}

// ============================================================================
// Health
// ============================================================================

func (s *ReminderService) HealthCheck(ctx context.Context) error {
	return s.repo.HealthCheck(ctx)
}

// ============================================================================
// Scope-aware RecipientResolver
// ============================================================================

// HRRecipientResolverImpl resolves everyone with `hr.employee.update` whose
// location scope covers the subject employee's current location.
//
// This is the *first* of two location layers:
//
//  1. Write-time (this resolver): only HR users who can act on the subject
//     get a reminder row at all.
//  2. Read-time (List / Counts): filters by X-Location-ID so a user whose
//     scope has since narrowed still can't see stale reminders.
//
// Both layers are required. Neither alone is enough.
type HRRecipientResolverImpl struct {
	pg *client.PostgresClient
}

func NewHRRecipientResolver(pg *client.PostgresClient) RecipientResolver {
	return &HRRecipientResolverImpl{pg: pg}
}

func (r *HRRecipientResolverImpl) ResolveRecipients(
	ctx context.Context,
	companyID uuid.UUID,
	subjectUserID uuid.UUID,
) ([]RecipientInfo, error) {
	// The CTE loads the subject's primary location once, then matches it
	// against each HR user's scope:
	//
	//   - ALL      → always eligible
	//   - PRIMARY  → eligible only if subject's location == HR's primary
	//   - SELECTED → eligible only if HR has an employee_location_access
	//                grant for the subject's location
	//
	// Employees with no primary_location_id (rare but possible) only get
	// ALL-scope recipients, since PRIMARY/SELECTED both need a location to
	// compare against.
	rows, err := r.pg.Query(ctx, `
		WITH subject AS (
			SELECT primary_location_id
			  FROM company_employees
			 WHERE company_id = $1 AND user_id = $2
		)
		SELECT DISTINCT hr.user_id
		  FROM company_employees hr
		  JOIN role_permissions rp ON rp.role_id = hr.role_id
		  JOIN permissions      p  ON p.permission_id = rp.permission_id
		  CROSS JOIN subject s
		 WHERE hr.company_id = $1
		   AND hr.is_active  = true
		   AND hr.user_id   <> $2
		   AND p.permission_name = 'hr.employee.update'
		   AND (
		        hr.location_access_scope = 'ALL'

		     OR (hr.location_access_scope = 'PRIMARY'
		         AND s.primary_location_id IS NOT NULL
		         AND hr.primary_location_id = s.primary_location_id)

		     OR (hr.location_access_scope = 'SELECTED'
		         AND s.primary_location_id IS NOT NULL
		         AND EXISTS (
		             SELECT 1 FROM employee_location_access ela
		             WHERE ela.company_id  = hr.company_id
		               AND ela.user_id     = hr.user_id
		               AND ela.location_id = s.primary_location_id
		         ))
		   )
	`, companyID, subjectUserID)
	if err != nil {
		return nil, fmt.Errorf("resolve HR recipients: %w", err)
	}
	defer rows.Close()

	out := make([]RecipientInfo, 0, 8)
	for rows.Next() {
		var uid uuid.UUID
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		out = append(out, RecipientInfo{UserID: uid, UserType: "hr"})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fallback: if nobody matched (subject has no location AND no HR user
	// is ALL-scope), route to the company owner so reminders never vanish.
	// The owner almost always has ALL-scope in practice; this is a
	// belt-and-braces path for tenant misconfigurations.
	if len(out) == 0 {
		var owner uuid.UUID
		if err := r.pg.QueryRow(ctx, `
			SELECT owner_user_id FROM companies WHERE company_id = $1
		`, companyID).Scan(&owner); err == nil && owner != uuid.Nil && owner != subjectUserID {
			out = append(out, RecipientInfo{UserID: owner, UserType: "admin"})
		}
	}

	return out, nil
}
