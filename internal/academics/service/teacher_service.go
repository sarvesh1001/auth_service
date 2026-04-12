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

type TeacherService interface {
	Create(ctx context.Context, req CreateTeacherRequest, idempotencyKey string) (*models.Teacher, error)
	BulkCreate(ctx context.Context, reqs []CreateTeacherRequest) ([]*models.Teacher, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Teacher, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*models.Teacher, error)
	GetByEmployeeCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Teacher, error)
	List(ctx context.Context, filter repository.TeacherFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Teacher, error)
	Count(ctx context.Context, filter repository.TeacherFilter) (int64, error)
	Update(ctx context.Context, req UpdateTeacherRequest) (*models.Teacher, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string, updatedBy *uuid.UUID) error
	CountByCompany(ctx context.Context, companyID uuid.UUID) (int64, error)
	AddSubject(ctx context.Context, teacherID, subjectID uuid.UUID, isPrimary bool) error
	RemoveSubject(ctx context.Context, teacherID, subjectID uuid.UUID) error
	GetSubjectsByTeacher(ctx context.Context, teacherID uuid.UUID) ([]*models.TeacherSubject, error)
	GetTeachersBySubject(ctx context.Context, subjectID uuid.UUID) ([]*models.Teacher, error)
	UpdateSubjectPrimary(ctx context.Context, teacherID, subjectID uuid.UUID, isPrimary bool) error
	AddSection(ctx context.Context, teacherID, sectionID uuid.UUID, isClassTeacher bool) error
	RemoveSection(ctx context.Context, teacherID, sectionID uuid.UUID) error
	GetSectionsByTeacher(ctx context.Context, teacherID uuid.UUID) ([]*models.TeacherSection, error)
	GetTeachersBySection(ctx context.Context, sectionID uuid.UUID) ([]*models.Teacher, error)
	UpdateClassTeacherStatus(ctx context.Context, teacherID, sectionID uuid.UUID, isClassTeacher bool) error
	SetSchedulePreference(ctx context.Context, pref *models.TeacherSchedulePreference) error
	GetSchedulePreferences(ctx context.Context, teacherID uuid.UUID) ([]*models.TeacherSchedulePreference, error)
	UpdateSchedulePreference(ctx context.Context, pref *models.TeacherSchedulePreference) error
	DeleteSchedulePreference(ctx context.Context, preferenceID uuid.UUID) error
	ClearSchedulePreferences(ctx context.Context, teacherID uuid.UUID) error
}

type teacherService struct {
	repo             repository.TeacherRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	notificationSvc  NotificationService
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
}

func NewTeacherService(
	repo repository.TeacherRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationSvc NotificationService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
) TeacherService {
	return &teacherService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("teacher_service"),
		notificationSvc:  notificationSvc,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
	}
}

func (s *teacherService) storeOutboxEvent(ctx context.Context, tx *sql.Tx, eventType EventType, aggregateID uuid.UUID, payload interface{}) error {
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
		AggregateType: "teacher",
		AggregateID:   aggregateID.String(),
		EventType:     string(eventType),
		Payload:       data,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, outboxEvent)
}

func (s *teacherService) sanitizeCreate(req *CreateTeacherRequest) {
	req.EmployeeCode = strings.TrimSpace(strings.ToUpper(req.EmployeeCode))
	req.Qualification = strings.TrimSpace(req.Qualification)
	req.Specialization = strings.TrimSpace(req.Specialization)
}

func (s *teacherService) sanitizeUpdate(req *UpdateTeacherRequest) {
	req.EmployeeCode = strings.TrimSpace(strings.ToUpper(req.EmployeeCode))
	req.Qualification = strings.TrimSpace(req.Qualification)
	req.Specialization = strings.TrimSpace(req.Specialization)
}

func (s *teacherService) validateCreateInput(req CreateTeacherRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.UserID == uuid.Nil {
		return fmt.Errorf("%w: user_id is required", ErrInvalidInput)
	}
	if req.EmployeeCode == "" {
		return fmt.Errorf("%w: employee_code is required", ErrInvalidInput)
	}
	if req.Status == "" {
		req.Status = string(models.TeacherActive)
	}
	if !models.IsValidTeacherStatus(req.Status) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidInput, req.Status)
	}
	return nil
}

func (s *teacherService) validateUpdateInput(req UpdateTeacherRequest) error {
	if req.TeacherID == uuid.Nil {
		return fmt.Errorf("%w: teacher_id is required", ErrInvalidInput)
	}
	if req.EmployeeCode == "" {
		return fmt.Errorf("%w: employee_code is required", ErrInvalidInput)
	}
	if req.Status != "" && !models.IsValidTeacherStatus(req.Status) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidInput, req.Status)
	}
	return nil
}

func (s *teacherService) Create(ctx context.Context, req CreateTeacherRequest, idempotencyKey string) (*models.Teacher, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("employee_code", req.EmployeeCode),
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
		var existing models.Teacher
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.TeacherID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}
	existing, _ := s.repo.GetByEmployeeCode(ctx, tx, req.CompanyID, req.EmployeeCode)
	if existing != nil {
		return nil, fmt.Errorf("%w: employee code %s already exists for company %s", ErrDuplicate, req.EmployeeCode, req.CompanyID)
	}
	teacher := &models.Teacher{
		CompanyID:      req.CompanyID,
		UserID:         req.UserID,
		EmployeeCode:   req.EmployeeCode,
		Qualification:  req.Qualification,
		Specialization: req.Specialization,
		JoiningDate:    req.JoiningDate,
		Status:         models.TeacherStatus(req.Status),
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.UpdatedBy,
	}
	if err := s.repo.Create(ctx, tx, teacher); err != nil {
		return nil, err
	}
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, teacher); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "create", "teacher",
			&teacher.TeacherID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"employee_code": teacher.EmployeeCode,
				"user_id":       teacher.UserID,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherCreated, teacher.TeacherID, teacher); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("teacher created", zap.String("id", teacher.TeacherID.String()))
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Teacher Account Created",
			Message:   fmt.Sprintf("Your teacher account with employee code %s has been created.", teacher.EmployeeCode),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: teacher.UserID,
				},
			},
			CreatedBy: req.CreatedBy,
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for teacher creation", zap.Error(err))
		}
	}()
	return teacher, nil
}

func (s *teacherService) BulkCreate(ctx context.Context, reqs []CreateTeacherRequest) ([]*models.Teacher, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))
	for i := range reqs {
		s.sanitizeCreate(&reqs[i])
	}
	type key struct {
		companyID uuid.UUID
		empCode   string
	}
	batchKeys := make(map[key]int)
	for i, req := range reqs {
		if err := s.validateCreateInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		k := key{companyID: req.CompanyID, empCode: req.EmployeeCode}
		if _, dup := batchKeys[k]; dup {
			return nil, fmt.Errorf("item %d: %w: duplicate employee code %s in batch", i, ErrDuplicate, req.EmployeeCode)
		}
		batchKeys[k] = i
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	for k := range batchKeys {
		existing, _ := s.repo.GetByEmployeeCode(ctx, tx, k.companyID, k.empCode)
		if existing != nil {
			return nil, fmt.Errorf("%w: employee code %s already exists", ErrDuplicate, k.empCode)
		}
	}
	teachers := make([]*models.Teacher, 0, len(reqs))
	for _, req := range reqs {
		teachers = append(teachers, &models.Teacher{
			CompanyID:      req.CompanyID,
			UserID:         req.UserID,
			EmployeeCode:   req.EmployeeCode,
			Qualification:  req.Qualification,
			Specialization: req.Specialization,
			JoiningDate:    req.JoiningDate,
			Status:         models.TeacherStatus(req.Status),
			CreatedBy:      req.CreatedBy,
			UpdatedBy:      req.UpdatedBy,
		})
	}
	if err := s.repo.BulkCreate(ctx, tx, teachers); err != nil {
		return nil, err
	}
	for _, t := range teachers {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_create", "teacher",
				&t.TeacherID, "user", t.CreatedBy, nil, nil, map[string]interface{}{
					"employee_code": t.EmployeeCode,
				})
		}
		if err := s.storeOutboxEvent(ctx, tx, EventTeacherCreated, t.TeacherID, t); err != nil {
			return nil, fmt.Errorf("outbox store for teacher %s: %w", t.TeacherID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk created teachers", zap.Int("count", len(teachers)))
	for _, t := range teachers {
		go func(teacher *models.Teacher) {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: teacher.CompanyID,
				Title:     "Teacher Account Created",
				Message:   fmt.Sprintf("Your teacher account with employee code %s has been created.", teacher.EmployeeCode),
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets: []NotificationTargetInput{
					{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
				},
				CreatedBy: teacher.CreatedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
				logger.Error("failed to create notification for teacher creation",
					zap.String("teacher_id", teacher.TeacherID.String()),
					zap.Error(err))
			}
		}(t)
	}
	return teachers, nil
}

func (s *teacherService) GetByID(ctx context.Context, id uuid.UUID) (*models.Teacher, error) {
	t, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("%w: teacher %s", ErrNotFound, id)
	}
	return t, nil
}

func (s *teacherService) GetByUserID(ctx context.Context, userID uuid.UUID) (*models.Teacher, error) {
	t, err := s.repo.GetByUserID(ctx, s.pgClient.DB, userID)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("%w: teacher for user %s", ErrNotFound, userID)
	}
	return t, nil
}

func (s *teacherService) GetByEmployeeCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Teacher, error) {
	code = strings.TrimSpace(strings.ToUpper(code))
	t, err := s.repo.GetByEmployeeCode(ctx, s.pgClient.DB, companyID, code)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("%w: teacher with code %s for company %s", ErrNotFound, code, companyID)
	}
	return t, nil
}

func (s *teacherService) List(ctx context.Context, filter repository.TeacherFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Teacher, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, pagination, sort)
}

func (s *teacherService) Count(ctx context.Context, filter repository.TeacherFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *teacherService) CountByCompany(ctx context.Context, companyID uuid.UUID) (int64, error) {
	return s.repo.CountByCompany(ctx, s.pgClient.DB, companyID)
}

func (s *teacherService) Update(ctx context.Context, req UpdateTeacherRequest) (*models.Teacher, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("teacher_id", req.TeacherID.String()))
	s.sanitizeUpdate(&req)
	if err := s.validateUpdateInput(req); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, req.TeacherID)
	if err != nil {
		return nil, err
	}
	if teacher == nil {
		return nil, fmt.Errorf("%w: teacher %s", ErrNotFound, req.TeacherID)
	}
	if req.EmployeeCode != teacher.EmployeeCode {
		existing, _ := s.repo.GetByEmployeeCode(ctx, tx, teacher.CompanyID, req.EmployeeCode)
		if existing != nil && existing.TeacherID != teacher.TeacherID {
			return nil, fmt.Errorf("%w: employee code %s already exists", ErrDuplicate, req.EmployeeCode)
		}
	}
	oldTeacher := *teacher
	teacher.UserID = req.UserID
	teacher.EmployeeCode = req.EmployeeCode
	teacher.Qualification = req.Qualification
	teacher.Specialization = req.Specialization
	teacher.JoiningDate = req.JoiningDate
	if req.Status != "" {
		teacher.Status = models.TeacherStatus(req.Status)
	}
	teacher.UpdatedBy = req.UpdatedBy
	if err := s.repo.Update(ctx, tx, teacher); err != nil {
		return nil, err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "teacher",
			&req.TeacherID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_employee_code": oldTeacher.EmployeeCode,
				"new_employee_code": teacher.EmployeeCode,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherUpdated, teacher.TeacherID, map[string]interface{}{
		"old": oldTeacher,
		"new": teacher,
	}); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("teacher updated")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Teacher Profile Updated",
			Message:   fmt.Sprintf("Your teacher profile (employee code %s) has been updated.", teacher.EmployeeCode),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
			CreatedBy: req.UpdatedBy,
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for teacher update", zap.Error(err))
		}
	}()
	return teacher, nil
}

func (s *teacherService) UpdateStatus(ctx context.Context, id uuid.UUID, status string, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateStatus"), zap.String("teacher_id", id.String()))
	if !models.IsValidTeacherStatus(status) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidInput, status)
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, id)
	}
	oldStatus := teacher.Status
	if err := s.repo.UpdateStatus(ctx, tx, id, status, updatedBy); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update_status", "teacher",
			&id, "user", updatedBy, nil, nil, map[string]interface{}{
				"old_status": oldStatus,
				"new_status": status,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherStatusUpdated, id, map[string]interface{}{
		"teacher_id": id,
		"old_status": oldStatus,
		"new_status": status,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("teacher status updated")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Teacher Status Changed",
			Message:   fmt.Sprintf("Your teacher status has been changed from %s to %s.", oldStatus, status),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
			CreatedBy: updatedBy,
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for teacher status update", zap.Error(err))
		}
	}()
	return nil
}

func (s *teacherService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("teacher_id", id.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, _ := s.repo.GetByID(ctx, tx, id)
	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "teacher",
			&id, "user", deletedBy, nil, nil, nil)
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherDeleted, id, map[string]interface{}{
		"teacher_id": id,
		"deleted_by": deletedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("teacher deleted")
	if teacher != nil && teacher.UserID != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: teacher.CompanyID,
				Title:     "Teacher Account Deleted",
				Message:   fmt.Sprintf("Your teacher account (employee code %s) has been deleted.", teacher.EmployeeCode),
				Type:      models.NotificationTypeWarning,
				Priority:  models.PriorityHigh,
				Targets: []NotificationTargetInput{
					{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
				},
				CreatedBy: deletedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
				logger.Error("failed to create notification for teacher deletion", zap.Error(err))
			}
		}()
	}
	return nil
}

func (s *teacherService) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string, updatedBy *uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	logger := s.logger.With(zap.String("method", "BulkUpdateStatus"), zap.Int("count", len(ids)), zap.String("status", status))
	if !models.IsValidTeacherStatus(status) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidInput, status)
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teachers, err := s.repo.GetByIDs(ctx, tx, ids)
	if err != nil {
		return err
	}
	if err := s.repo.BulkUpdateStatus(ctx, tx, ids, status, updatedBy); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_update_status", "teacher",
			nil, "user", updatedBy, nil, nil, map[string]interface{}{
				"teacher_ids": ids,
				"status":      status,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherBulkStatusUpdated, uuid.Nil, map[string]interface{}{
		"teacher_ids": ids,
		"status":      status,
		"updated_by":  updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk status update completed")
	for _, t := range teachers {
		go func(teacher *models.Teacher) {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: teacher.CompanyID,
				Title:     "Teacher Status Updated (Bulk)",
				Message:   fmt.Sprintf("Your teacher status has been updated to %s.", status),
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets: []NotificationTargetInput{
					{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
				},
				CreatedBy: updatedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
				logger.Error("failed to create notification for bulk teacher status update",
					zap.String("teacher_id", teacher.TeacherID.String()),
					zap.Error(err))
			}
		}(t)
	}
	return nil
}

func (s *teacherService) AddSubject(ctx context.Context, teacherID, subjectID uuid.UUID, isPrimary bool) error {
	logger := s.logger.With(zap.String("method", "AddSubject"), zap.String("teacher_id", teacherID.String()), zap.String("subject_id", subjectID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, teacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, teacherID)
	}
	if err := s.repo.AddSubject(ctx, tx, teacherID, subjectID, isPrimary); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "add_subject", "teacher_subject",
			&teacherID, "user", nil, nil, nil, map[string]interface{}{
				"subject_id": subjectID,
				"is_primary": isPrimary,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherSubjectAssigned, teacherID, map[string]interface{}{
		"teacher_id": teacherID,
		"subject_id": subjectID,
		"is_primary": isPrimary,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("subject added to teacher")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Subject Assigned",
			Message:   fmt.Sprintf("You have been assigned to teach subject ID %s (primary: %v).", subjectID, isPrimary),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for subject assignment", zap.Error(err))
		}
	}()
	return nil
}

func (s *teacherService) RemoveSubject(ctx context.Context, teacherID, subjectID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveSubject"), zap.String("teacher_id", teacherID.String()), zap.String("subject_id", subjectID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, teacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, teacherID)
	}
	if err := s.repo.RemoveSubject(ctx, tx, teacherID, subjectID); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "remove_subject", "teacher_subject",
			&teacherID, "user", nil, nil, nil, map[string]interface{}{
				"subject_id": subjectID,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherSubjectRemoved, teacherID, map[string]interface{}{
		"teacher_id": teacherID,
		"subject_id": subjectID,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("subject removed from teacher")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Subject Unassigned",
			Message:   fmt.Sprintf("You are no longer assigned to teach subject ID %s.", subjectID),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for subject removal", zap.Error(err))
		}
	}()
	return nil
}

func (s *teacherService) GetSubjectsByTeacher(ctx context.Context, teacherID uuid.UUID) ([]*models.TeacherSubject, error) {
	return s.repo.GetSubjectsByTeacher(ctx, s.pgClient.DB, teacherID)
}

func (s *teacherService) GetTeachersBySubject(ctx context.Context, subjectID uuid.UUID) ([]*models.Teacher, error) {
	return s.repo.GetTeachersBySubject(ctx, s.pgClient.DB, subjectID)
}

func (s *teacherService) UpdateSubjectPrimary(ctx context.Context, teacherID, subjectID uuid.UUID, isPrimary bool) error {
	logger := s.logger.With(zap.String("method", "UpdateSubjectPrimary"), zap.String("teacher_id", teacherID.String()), zap.String("subject_id", subjectID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, teacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, teacherID)
	}
	if err := s.repo.UpdateSubjectPrimary(ctx, tx, teacherID, subjectID, isPrimary); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update_subject_primary", "teacher_subject",
			&teacherID, "user", nil, nil, nil, map[string]interface{}{
				"subject_id": subjectID,
				"is_primary": isPrimary,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherSubjectUpdated, teacherID, map[string]interface{}{
		"teacher_id": teacherID,
		"subject_id": subjectID,
		"is_primary": isPrimary,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("teacher subject primary status updated")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Subject Primary Status Changed",
			Message:   fmt.Sprintf("Your primary status for subject ID %s has been set to %v.", subjectID, isPrimary),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for subject primary update", zap.Error(err))
		}
	}()
	return nil
}

func (s *teacherService) AddSection(ctx context.Context, teacherID, sectionID uuid.UUID, isClassTeacher bool) error {
	logger := s.logger.With(zap.String("method", "AddSection"), zap.String("teacher_id", teacherID.String()), zap.String("section_id", sectionID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, teacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, teacherID)
	}
	if err := s.repo.AddSection(ctx, tx, teacherID, sectionID, isClassTeacher); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "add_section", "teacher_section",
			&teacherID, "user", nil, nil, nil, map[string]interface{}{
				"section_id":       sectionID,
				"is_class_teacher": isClassTeacher,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherSectionAssigned, teacherID, map[string]interface{}{
		"teacher_id":       teacherID,
		"section_id":       sectionID,
		"is_class_teacher": isClassTeacher,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("section added to teacher")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Section Assigned",
			Message:   fmt.Sprintf("You have been assigned to section %s (class teacher: %v).", sectionID.String(), isClassTeacher),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for section assignment", zap.Error(err))
		}
	}()
	return nil
}

func (s *teacherService) RemoveSection(ctx context.Context, teacherID, sectionID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveSection"), zap.String("teacher_id", teacherID.String()), zap.String("section_id", sectionID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, teacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, teacherID)
	}
	if err := s.repo.RemoveSection(ctx, tx, teacherID, sectionID); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "remove_section", "teacher_section",
			&teacherID, "user", nil, nil, nil, map[string]interface{}{
				"section_id": sectionID,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherSectionRemoved, teacherID, map[string]interface{}{
		"teacher_id": teacherID,
		"section_id": sectionID,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("section removed from teacher")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Section Unassigned",
			Message:   fmt.Sprintf("You are no longer assigned to section %s.", sectionID.String()),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for section removal", zap.Error(err))
		}
	}()
	return nil
}

func (s *teacherService) GetSectionsByTeacher(ctx context.Context, teacherID uuid.UUID) ([]*models.TeacherSection, error) {
	return s.repo.GetSectionsByTeacher(ctx, s.pgClient.DB, teacherID)
}

func (s *teacherService) GetTeachersBySection(ctx context.Context, sectionID uuid.UUID) ([]*models.Teacher, error) {
	return s.repo.GetTeachersBySection(ctx, s.pgClient.DB, sectionID)
}

func (s *teacherService) UpdateClassTeacherStatus(ctx context.Context, teacherID, sectionID uuid.UUID, isClassTeacher bool) error {
	logger := s.logger.With(zap.String("method", "UpdateClassTeacherStatus"), zap.String("teacher_id", teacherID.String()), zap.String("section_id", sectionID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, teacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, teacherID)
	}
	if err := s.repo.UpdateClassTeacherStatus(ctx, tx, teacherID, sectionID, isClassTeacher); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update_class_teacher", "teacher_section",
			&teacherID, "user", nil, nil, nil, map[string]interface{}{
				"section_id":       sectionID,
				"is_class_teacher": isClassTeacher,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherClassTeacherUpdated, teacherID, map[string]interface{}{
		"teacher_id":       teacherID,
		"section_id":       sectionID,
		"is_class_teacher": isClassTeacher,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("class teacher status updated")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Class Teacher Status Changed",
			Message:   fmt.Sprintf("Your class teacher status for section %s has been set to %v.", sectionID.String(), isClassTeacher),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for class teacher update", zap.Error(err))
		}
	}()
	return nil
}

func (s *teacherService) SetSchedulePreference(ctx context.Context, pref *models.TeacherSchedulePreference) error {
	logger := s.logger.With(zap.String("method", "SetSchedulePreference"), zap.String("teacher_id", pref.TeacherID.String()), zap.Int("day_of_week", pref.DayOfWeek))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, pref.TeacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, pref.TeacherID)
	}
	if err := s.repo.SetSchedulePreference(ctx, tx, pref); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "set_schedule_preference", "teacher_schedule_preference",
			&pref.PreferenceID, "user", pref.CreatedBy, nil, nil, map[string]interface{}{
				"day_of_week": pref.DayOfWeek,
				"start_time":  pref.PreferredStartTime,
				"end_time":    pref.PreferredEndTime,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherSchedulePreferenceSet, pref.PreferenceID, pref); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("schedule preference set")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Schedule Preference Set",
			Message:   fmt.Sprintf("Your schedule preference for day %d has been saved.", pref.DayOfWeek),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
			CreatedBy: pref.CreatedBy,
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for schedule preference set", zap.Error(err))
		}
	}()
	return nil
}

func (s *teacherService) GetSchedulePreferences(ctx context.Context, teacherID uuid.UUID) ([]*models.TeacherSchedulePreference, error) {
	return s.repo.GetSchedulePreferences(ctx, s.pgClient.DB, teacherID)
}

func (s *teacherService) UpdateSchedulePreference(ctx context.Context, pref *models.TeacherSchedulePreference) error {
	logger := s.logger.With(zap.String("method", "UpdateSchedulePreference"), zap.String("preference_id", pref.PreferenceID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, pref.TeacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, pref.TeacherID)
	}
	if err := s.repo.UpdateSchedulePreference(ctx, tx, pref); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update_schedule_preference", "teacher_schedule_preference",
			&pref.PreferenceID, "user", pref.CreatedBy, nil, nil, map[string]interface{}{
				"day_of_week": pref.DayOfWeek,
				"start_time":  pref.PreferredStartTime,
				"end_time":    pref.PreferredEndTime,
			})
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherSchedulePreferenceUpdated, pref.PreferenceID, pref); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("schedule preference updated")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Schedule Preference Updated",
			Message:   fmt.Sprintf("Your schedule preference for day %d has been updated.", pref.DayOfWeek),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
			CreatedBy: pref.CreatedBy,
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for schedule preference update", zap.Error(err))
		}
	}()
	return nil
}

func (s *teacherService) DeleteSchedulePreference(ctx context.Context, preferenceID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteSchedulePreference"), zap.String("preference_id", preferenceID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.DeleteSchedulePreference(ctx, tx, preferenceID); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete_schedule_preference", "teacher_schedule_preference",
			&preferenceID, "user", nil, nil, nil, nil)
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherSchedulePreferenceDeleted, preferenceID, map[string]interface{}{
		"preference_id": preferenceID,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("schedule preference deleted")
	return nil
}

func (s *teacherService) ClearSchedulePreferences(ctx context.Context, teacherID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "ClearSchedulePreferences"), zap.String("teacher_id", teacherID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	teacher, err := s.repo.GetByID(ctx, tx, teacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, teacherID)
	}
	if err := s.repo.ClearSchedulePreferences(ctx, tx, teacherID); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "clear_schedule_preferences", "teacher_schedule_preference",
			&teacherID, "user", nil, nil, nil, nil)
	}
	if err := s.storeOutboxEvent(ctx, tx, EventTeacherSchedulePreferencesCleared, teacherID, map[string]interface{}{
		"teacher_id": teacherID,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("schedule preferences cleared")
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     "Schedule Preferences Cleared",
			Message:   "All your schedule preferences have been cleared.",
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetUser, TargetEntityID: teacher.UserID},
			},
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, ""); err != nil {
			logger.Error("failed to create notification for schedule preferences cleared", zap.Error(err))
		}
	}()
	return nil
}
