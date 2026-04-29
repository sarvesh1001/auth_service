package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// ---------------------------------------------------------------------
// Event types (matching outbox pattern)
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// DTOs
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

// NotificationOutboxEvent is the structure stored in outbox for notification events.
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
	Create(ctx context.Context, req CreateNotificationRequest, idempotencyKey string) (*models.Notification, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Notification, error)
	Update(ctx context.Context, req UpdateNotificationRequest) (*models.Notification, error)
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	ListUserNotifications(ctx context.Context, req ListUserNotificationsRequest) ([]*models.Notification, int64, error)
	MarkAsRead(ctx context.Context, notificationID, userID uuid.UUID) error
	MarkAllAsRead(ctx context.Context, userID uuid.UUID) error
	GetReadStatuses(ctx context.Context, notificationIDs []uuid.UUID, userID uuid.UUID) (map[uuid.UUID]bool, error)
	GetReadCount(ctx context.Context, notificationID uuid.UUID) (int64, error)
	GetCounts(ctx context.Context, userID uuid.UUID) (*UserNotificationCounts, error)
	GetUserNotificationSummary(ctx context.Context, userID uuid.UUID) ([]*models.Notification, error)
	AddTargets(ctx context.Context, notificationID uuid.UUID, targets []NotificationTargetInput) error
	RemoveTargets(ctx context.Context, notificationID uuid.UUID, targetIDs []uuid.UUID) error
	GetTargets(ctx context.Context, notificationID uuid.UUID) ([]*models.NotificationTarget, error)
}

// ---------------------------------------------------------------------
// notificationService struct
// ---------------------------------------------------------------------

type notificationService struct {
	repo     repository.NotificationRepository
	pgClient *client.PostgresClient
	logger   *zap.Logger

	// Infrastructure dependencies (same pattern as assignment)
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
}

func NewNotificationService(
	repo repository.NotificationRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
) NotificationService {
	return &notificationService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("notification_service"),
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
	}
}

// ---------------------------------------------------------------------
// Helper: store outbox event for notification
// ---------------------------------------------------------------------

func (s *notificationService) storeOutboxEvent(ctx context.Context, tx *sql.Tx, eventType EventType, aggregateID uuid.UUID, payload interface{}) error {
	var data []byte
	var err error
	if payload != nil {
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal outbox payload: %w", err)
		}
	}

	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "notification",
		AggregateID:   aggregateID.String(),
		EventType:     string(eventType),
		Topic:         TopicStudent,
		Payload:       data,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, outboxEvent)
}

// ---------------------------------------------------------------------
// Sanitization & Validation
// ---------------------------------------------------------------------

func (s *notificationService) sanitizeCreate(req *CreateNotificationRequest) {
	req.Title = strings.TrimSpace(req.Title)
	req.Message = strings.TrimSpace(req.Message)
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

	// Idempotency check (same pattern as assignment service)
	if idempotencyKey != "" {
		var existing models.Notification
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.NotificationID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
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

	notification := &models.Notification{
		CompanyID: req.CompanyID,
		Title:     req.Title,
		Message:   req.Message,
		Type:      req.Type,
		Priority:  req.Priority,
		ExpiresAt: req.ExpiresAt,
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.CreatedBy,
	}

	if err := s.repo.Create(ctx, tx, notification, targets); err != nil {
		return nil, err
	}

	// Store idempotency key inside transaction
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, notification); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "create", "notification",
			&notification.NotificationID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"title":      notification.Title,
				"type":       notification.Type,
				"priority":   notification.Priority,
				"company_id": notification.CompanyID,
			})
	}

	// Build outbox payload
	outboxPayload := NotificationOutboxEvent{
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
		outboxPayload.Targets[i] = struct {
			TargetType string    `json:"target_type"`
			EntityID   uuid.UUID `json:"entity_id"`
		}{
			TargetType: string(t.TargetType),
			EntityID:   t.TargetEntityID,
		}
	}

	if err := s.storeOutboxEvent(ctx, tx, EventNotificationCreated, notification.NotificationID, outboxPayload); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
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

	existing, err := s.repo.GetByID(ctx, tx, req.NotificationID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: notification %s", ErrNotFound, req.NotificationID)
	}

	existing.Title = req.Title
	existing.Message = req.Message
	existing.Type = req.Type
	existing.Priority = req.Priority
	existing.ExpiresAt = req.ExpiresAt
	existing.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "notification",
			&req.NotificationID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_title": existing.Title,
				"new_title": req.Title,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventNotificationUpdated, existing.NotificationID, existing); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "notification",
			&id, "user", deletedBy, nil, nil, nil)
	}

	deletePayload := map[string]interface{}{
		"notification_id": id,
		"deleted_by":      deletedBy,
	}
	if err := s.storeOutboxEvent(ctx, tx, EventNotificationDeleted, id, deletePayload); err != nil {
		return fmt.Errorf("outbox store: %w", err)
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

	sortField := req.SortField
	if sortField == "" {
		sortField = "created_at"
	}
	sortDir := strings.ToUpper(req.SortDirection)
	if sortDir != "ASC" && sortDir != "DESC" {
		sortDir = "DESC"
	}
	srt := repository.Sort{Field: sortField, Direction: sortDir}

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "mark_read", "notification",
			&notificationID, "user", &userID, nil, nil, map[string]interface{}{
				"user_id": userID,
			})
	}

	readPayload := map[string]interface{}{
		"notification_id": notificationID,
		"user_id":         userID,
	}
	if err := s.storeOutboxEvent(ctx, tx, EventNotificationRead, notificationID, readPayload); err != nil {
		return fmt.Errorf("outbox store: %w", err)
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

	filter := repository.NotificationFilter{
		UserID:     &userID,
		ReadStatus: ptrBool(false),
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "mark_all_read", "notification",
			nil, "user", &userID, nil, nil, map[string]interface{}{
				"user_id": userID,
			})
	}

	allReadPayload := map[string]interface{}{
		"user_id": userID,
	}
	if err := s.storeOutboxEvent(ctx, tx, EventNotificationAllRead, userID, allReadPayload); err != nil {
		return fmt.Errorf("outbox store: %w", err)
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
	totalFilter := repository.NotificationFilter{UserID: &userID}
	total, err := s.repo.Count(ctx, s.pgClient.DB, totalFilter)
	if err != nil {
		return nil, err
	}

	unreadFilter := repository.NotificationFilter{UserID: &userID, ReadStatus: ptrBool(false)}
	unread, err := s.repo.Count(ctx, s.pgClient.DB, unreadFilter)
	if err != nil {
		return nil, err
	}

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

func (s *notificationService) GetUserNotificationSummary(ctx context.Context, userID uuid.UUID) ([]*models.Notification, error) {
	filter := repository.NotificationFilter{
		UserID:     &userID,
		ReadStatus: ptrBool(false),
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
	repoTargets := make([]*models.NotificationTarget, len(targets))
	for i, t := range targets {
		repoTargets[i] = &models.NotificationTarget{
			NotificationID: notificationID,
			TargetType:     t.TargetType,
			TargetEntityID: t.TargetEntityID,
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
