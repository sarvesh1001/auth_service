package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// ---------------------------------------------------------------------
// DTOs (can also be moved to types.go)
// ---------------------------------------------------------------------

type NotificationTargetInput struct {
	TargetType     models.TargetType
	TargetEntityID uuid.UUID
}

type CreateNotificationRequest struct {
	CompanyID uuid.UUID
	Title     string
	Message   string
	Type      models.NotificationType
	Priority  models.NotificationPriority
	ExpiresAt *time.Time
	Targets   []NotificationTargetInput
	CreatedBy *uuid.UUID
}

type UpdateNotificationRequest struct {
	NotificationID uuid.UUID
	Title          string
	Message        string
	Type           models.NotificationType
	Priority       models.NotificationPriority
	ExpiresAt      *time.Time
	UpdatedBy      *uuid.UUID
}

type ListUserNotificationsRequest struct {
	UserID        uuid.UUID
	Types         []models.NotificationType
	Priorities    []models.NotificationPriority
	ReadStatus    *bool // true=read, false=unread, nil=all
	Limit         int
	Offset        int
	SortField     string
	SortDirection string
}

type UserNotificationCounts struct {
	Total      int64
	Unread     int64
	ByPriority map[models.NotificationPriority]int64
}

// NotificationOutboxEvent is the structure stored in outbox for notification.created events.
// It includes both the notification and its targets, matching the consumer's expected format.
type NotificationOutboxEvent struct {
	NotificationID uuid.UUID `json:"notification_id"`
	Title          string    `json:"title"`
	Message        string    `json:"message"`
	Type           string    `json:"type"`
	Priority       string    `json:"priority"`
	CompanyID      uuid.UUID `json:"company_id"`
	Targets        []struct {
		TargetType string    `json:"target_type"`
		EntityID   uuid.UUID `json:"entity_id"`
	} `json:"targets"`
	CreatedAt time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------
// NotificationService interface
// ---------------------------------------------------------------------

type NotificationService interface {
	// Create a new notification with its targets.
	Create(ctx context.Context, req CreateNotificationRequest, idempotencyKey string) (*models.Notification, error)

	// Get a notification by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.Notification, error)

	// Update an existing notification (title, message, etc.) – targets cannot be changed via update.
	Update(ctx context.Context, req UpdateNotificationRequest) (*models.Notification, error)

	// Delete (soft delete) a notification.
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// List notifications for a specific user. Uses the NotificationReads table to filter read/unread.
	ListUserNotifications(ctx context.Context, req ListUserNotificationsRequest) ([]*models.Notification, int64, error)

	// Mark a notification as read for a user.
	MarkAsRead(ctx context.Context, notificationID, userID uuid.UUID) error

	// Mark all notifications for a user as read.
	MarkAllAsRead(ctx context.Context, userID uuid.UUID) error

	// Get the read status for a set of notifications for a user.
	GetReadStatuses(ctx context.Context, notificationIDs []uuid.UUID, userID uuid.UUID) (map[uuid.UUID]bool, error)

	// Get counts (total, unread, by priority) for a user.
	GetCounts(ctx context.Context, userID uuid.UUID) (*UserNotificationCounts, error)

	// Get a summary of notifications for a user (e.g., recent unread).
	GetUserNotificationSummary(ctx context.Context, userID uuid.UUID) ([]*models.Notification, error)

	// Add targets to an existing notification.
	AddTargets(ctx context.Context, notificationID uuid.UUID, targets []NotificationTargetInput) error

	// Remove targets from a notification.
	RemoveTargets(ctx context.Context, notificationID uuid.UUID, targetIDs []uuid.UUID) error

	// Get all targets for a notification.
	GetTargets(ctx context.Context, notificationID uuid.UUID) ([]*models.NotificationTarget, error)

	// Get the read count for a notification.
	GetReadCount(ctx context.Context, notificationID uuid.UUID) (int64, error)
}

// ---------------------------------------------------------------------
// notificationService struct
// ---------------------------------------------------------------------

type notificationService struct {
	repo             repository.NotificationRepository
	idempotencyStore IdempotencyStore
	auditLogger      AuditLogger
	outboxStore      OutboxStore
	eventPublisher   EventPublisher
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

func NewNotificationService(
	repo repository.NotificationRepository,
	idempotencyStore IdempotencyStore,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) NotificationService {
	return &notificationService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditLogger:      auditLogger,
		outboxStore:      outboxStore,
		eventPublisher:   eventPublisher,
		pgClient:         pgClient,
		logger:           logger.Named("notification_service"),
	}
}

// ---------------------------------------------------------------------
// Sanitization & Validation
// ---------------------------------------------------------------------

func (s *notificationService) sanitizeCreate(req *CreateNotificationRequest) {
	req.Title = strings.TrimSpace(req.Title)
	req.Message = strings.TrimSpace(req.Message)
	// Types are enums, no trimming needed.
}

func (s *notificationService) validateCreateInput(req CreateNotificationRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.Title == "" {
		return fmt.Errorf("%w: title is required", ErrInvalidInput)
	}
	if req.Message == "" {
		return fmt.Errorf("%w: message is required", ErrInvalidInput)
	}
	if req.Type == "" {
		return fmt.Errorf("%w: type is required", ErrInvalidInput)
	}
	if req.Priority == "" {
		return fmt.Errorf("%w: priority is required", ErrInvalidInput)
	}
	return nil
}

func (s *notificationService) validateUpdateInput(req UpdateNotificationRequest) error {
	if req.NotificationID == uuid.Nil {
		return fmt.Errorf("%w: notification_id is required", ErrInvalidInput)
	}
	if req.Title == "" {
		return fmt.Errorf("%w: title is required", ErrInvalidInput)
	}
	if req.Message == "" {
		return fmt.Errorf("%w: message is required", ErrInvalidInput)
	}
	if req.Type == "" {
		return fmt.Errorf("%w: type is required", ErrInvalidInput)
	}
	if req.Priority == "" {
		return fmt.Errorf("%w: priority is required", ErrInvalidInput)
	}
	return nil
}

// ---------------------------------------------------------------------
// Core CRUD Operations
// ---------------------------------------------------------------------

func (s *notificationService) Create(ctx context.Context, req CreateNotificationRequest, idempotencyKey string) (*models.Notification, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("title", req.Title),
		zap.String("idempotency_key", idempotencyKey),
	)

	s.sanitizeCreate(&req)
	if err := s.validateCreateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var notif models.Notification
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &notif); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &notif, nil
		}
	}

	// Convert input targets to repository models
	var targets []*models.NotificationTarget
	for _, t := range req.Targets {
		targets = append(targets, &models.NotificationTarget{
			TargetType:     t.TargetType,
			TargetEntityID: t.TargetEntityID,
			CreatedBy:      req.CreatedBy,
		})
	}

	// Prepare notification model
	notification := &models.Notification{
		CompanyID: req.CompanyID,
		Title:     req.Title,
		Message:   req.Message,
		Type:      req.Type,
		Priority:  req.Priority,
		ExpiresAt: req.ExpiresAt,
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.CreatedBy, // on create, both are same
	}

	// Insert notification and its targets in a single transaction
	if err := s.repo.Create(ctx, tx, notification, targets); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, notification); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	// Audit log
	if err := s.auditLogger.Log(ctx, tx, "CREATE", notification.NotificationID, nil, notification, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Build combined outbox event with targets
	outboxEvent := NotificationOutboxEvent{
		NotificationID: notification.NotificationID,
		Title:          notification.Title,
		Message:        notification.Message,
		Type:           string(notification.Type),
		Priority:       string(notification.Priority),
		CompanyID:      notification.CompanyID,
		CreatedAt:      notification.CreatedAt,
		Targets: make([]struct {
			TargetType string    `json:"target_type"`
			EntityID   uuid.UUID `json:"entity_id"`
		}, len(targets)),
	}
	for i, t := range targets {
		outboxEvent.Targets[i] = struct {
			TargetType string    `json:"target_type"`
			EntityID   uuid.UUID `json:"entity_id"`
		}{
			TargetType: string(t.TargetType),
			EntityID:   t.TargetEntityID,
		}
	}

	// Store outbox event for notification creation
	if err := s.outboxStore.Store(ctx, tx, string(EventNotificationCreated), outboxEvent); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("notification created", zap.String("id", notification.NotificationID.String()))
	return notification, nil
}

func (s *notificationService) GetByID(ctx context.Context, id uuid.UUID) (*models.Notification, error) {
	notif, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if notif == nil {
		return nil, fmt.Errorf("%w: notification %s", ErrNotFound, id)
	}
	return notif, nil
}

func (s *notificationService) Update(ctx context.Context, req UpdateNotificationRequest) (*models.Notification, error) {
	logger := s.logger.With(
		zap.String("method", "Update"),
		zap.String("notification_id", req.NotificationID.String()),
	)

	if err := s.validateUpdateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Retrieve existing notification (with lock, if needed)
	existing, err := s.repo.GetByID(ctx, tx, req.NotificationID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: notification %s", ErrNotFound, req.NotificationID)
	}

	// Update fields
	existing.Title = req.Title
	existing.Message = req.Message
	existing.Type = req.Type
	existing.Priority = req.Priority
	existing.ExpiresAt = req.ExpiresAt
	existing.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", existing.NotificationID, existing, existing, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventNotificationUpdated), existing); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("notification updated")
	return existing, nil
}

func (s *notificationService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "Delete"),
		zap.String("notification_id", id.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventNotificationDeleted), map[string]interface{}{
		"notification_id": id,
		"deleted_by":      deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("notification deleted")
	return nil
}

// ---------------------------------------------------------------------
// User‑facing operations (read status)
// ---------------------------------------------------------------------

func (s *notificationService) ListUserNotifications(ctx context.Context, req ListUserNotificationsRequest) ([]*models.Notification, int64, error) {
	logger := s.logger.With(
		zap.String("method", "ListUserNotifications"),
		zap.String("user_id", req.UserID.String()),
	)

	// Build filter for repository (only notifications that are relevant to this user)
	// The repository's List method already handles user‑specific read status if we set the filter's UserID and ReadStatus.
	filter := repository.NotificationFilter{
		UserID:     &req.UserID,
		ReadStatus: req.ReadStatus,
	}
	if len(req.Types) > 0 {
		types := make([]models.NotificationType, len(req.Types))
		copy(types, req.Types)
		filter.Types = types
	}
	if len(req.Priorities) > 0 {
		priorities := make([]models.NotificationPriority, len(req.Priorities))
		copy(priorities, req.Priorities)
		filter.Priorities = priorities
	}

	// Convert sort
	sortField := req.SortField
	if sortField == "" {
		sortField = "created_at"
	}
	sortDir := strings.ToUpper(req.SortDirection)
	if sortDir != "ASC" && sortDir != "DESC" {
		sortDir = "DESC"
	}
	srt := repository.Sort{Field: sortField, Direction: sortDir}

	// Pagination
	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}
	pag := repository.Pagination{Limit: limit, Offset: offset}

	notifications, err := s.repo.List(ctx, s.pgClient.DB, filter, pag, srt)
	if err != nil {
		logger.Error("failed to list notifications", zap.Error(err))
		return nil, 0, err
	}

	total, err := s.repo.Count(ctx, s.pgClient.DB, filter)
	if err != nil {
		logger.Error("failed to count notifications", zap.Error(err))
		return nil, 0, err
	}

	return notifications, total, nil
}

func (s *notificationService) MarkAsRead(ctx context.Context, notificationID, userID uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "MarkAsRead"),
		zap.String("notification_id", notificationID.String()),
		zap.String("user_id", userID.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.MarkAsRead(ctx, tx, notificationID, userID); err != nil {
		return err
	}

	// Optionally audit and outbox for read events
	if err := s.auditLogger.Log(ctx, tx, "MARK_READ", notificationID, nil, map[string]interface{}{"user_id": userID}, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventNotificationRead), map[string]interface{}{
		"notification_id": notificationID,
		"user_id":         userID,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("notification marked as read")
	return nil
}

func (s *notificationService) MarkAllAsRead(ctx context.Context, userID uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "MarkAllAsRead"),
		zap.String("user_id", userID.String()),
	)

	// Get all unread notification IDs for this user
	filter := repository.NotificationFilter{
		UserID:     &userID,
		ReadStatus: ptrBool(false), // unread
	}
	pag := repository.Pagination{Limit: 1000, Offset: 0}
	srt := repository.Sort{Field: "created_at", Direction: "ASC"}

	notifications, err := s.repo.List(ctx, s.pgClient.DB, filter, pag, srt)
	if err != nil {
		return fmt.Errorf("failed to fetch unread notifications: %w", err)
	}

	if len(notifications) == 0 {
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, n := range notifications {
		if err := s.repo.MarkAsRead(ctx, tx, n.NotificationID, userID); err != nil {
			return err
		}
	}

	if err := s.auditLogger.Log(ctx, tx, "MARK_ALL_READ", uuid.Nil, nil, map[string]interface{}{"user_id": userID}, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventNotificationAllRead), map[string]interface{}{
		"user_id": userID,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("all notifications marked as read")
	return nil
}

func (s *notificationService) GetReadStatuses(ctx context.Context, notificationIDs []uuid.UUID, userID uuid.UUID) (map[uuid.UUID]bool, error) {
	return s.repo.GetReadStatuses(ctx, s.pgClient.DB, notificationIDs, userID)
}

func (s *notificationService) GetReadCount(ctx context.Context, notificationID uuid.UUID) (int64, error) {
	return s.repo.GetReadCount(ctx, s.pgClient.DB, notificationID)
}

func (s *notificationService) GetCounts(ctx context.Context, userID uuid.UUID) (*UserNotificationCounts, error) {
	// Total count
	totalFilter := repository.NotificationFilter{UserID: &userID}
	total, err := s.repo.Count(ctx, s.pgClient.DB, totalFilter)
	if err != nil {
		return nil, err
	}

	// Unread count
	unreadFilter := repository.NotificationFilter{UserID: &userID, ReadStatus: ptrBool(false)}
	unread, err := s.repo.Count(ctx, s.pgClient.DB, unreadFilter)
	if err != nil {
		return nil, err
	}

	// Counts by priority – we need to count with filter by priority.
	// Since repository.Count does not support grouping, we'll do individual queries or extend repository.
	byPriority := make(map[models.NotificationPriority]int64)
	priorities := []models.NotificationPriority{
		models.PriorityLow, models.PriorityNormal, models.PriorityHigh, models.PriorityUrgent,
	}
	for _, pri := range priorities {
		filter := repository.NotificationFilter{
			UserID:     &userID,
			Priorities: []models.NotificationPriority{pri},
		}
		cnt, err := s.repo.Count(ctx, s.pgClient.DB, filter)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			byPriority[pri] = cnt
		}
	}

	return &UserNotificationCounts{
		Total:      total,
		Unread:     unread,
		ByPriority: byPriority,
	}, nil
}

// GetUserNotificationSummary returns recent unread notifications (or all recent) for a user.
func (s *notificationService) GetUserNotificationSummary(ctx context.Context, userID uuid.UUID) ([]*models.Notification, error) {
	filter := repository.NotificationFilter{
		UserID:     &userID,
		ReadStatus: ptrBool(false), // only unread
	}
	pag := repository.Pagination{Limit: 10, Offset: 0}
	srt := repository.Sort{Field: "created_at", Direction: "DESC"}

	notifs, err := s.repo.List(ctx, s.pgClient.DB, filter, pag, srt)
	if err != nil {
		return nil, err
	}
	return notifs, nil
}

// ---------------------------------------------------------------------
// Target Management
// ---------------------------------------------------------------------

func (s *notificationService) AddTargets(ctx context.Context, notificationID uuid.UUID, targets []NotificationTargetInput) error {
	_ = s.logger.With(
		zap.String("method", "AddTargets"),
		zap.String("notification_id", notificationID.String()),
	)

	// Convert input to repository models
	repoTargets := make([]*models.NotificationTarget, len(targets))
	for i, t := range targets {
		repoTargets[i] = &models.NotificationTarget{
			NotificationID: notificationID,
			TargetType:     t.TargetType,
			TargetEntityID: t.TargetEntityID,
			// CreatedBy not available here; will be set in repository? Actually, the repo expects CreatedBy.
			// We'll need to pass it. We could fetch from existing notification or require caller to provide.
			// For simplicity, we'll pass nil, but the repository will not set created_by. We may need to extend.
			// Let's pass nil, and the repository will insert with NULL created_by.
		}
	}

	return s.repo.AddTargets(ctx, s.pgClient.DB, notificationID, repoTargets)
}

func (s *notificationService) RemoveTargets(ctx context.Context, notificationID uuid.UUID, targetIDs []uuid.UUID) error {
	return s.repo.RemoveTargets(ctx, s.pgClient.DB, notificationID, targetIDs)
}

func (s *notificationService) GetTargets(ctx context.Context, notificationID uuid.UUID) ([]*models.NotificationTarget, error) {
	return s.repo.GetTargets(ctx, s.pgClient.DB, notificationID)
}

// ---------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------

func ptrBool(b bool) *bool {
	return &b
}
