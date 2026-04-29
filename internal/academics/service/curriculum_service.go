package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

type CurriculumService interface {
	AssignSubjectToCourse(ctx context.Context, req AssignSubjectRequest, idempotencyKey string) error
	BulkAssignSubjects(ctx context.Context, reqs []AssignSubjectRequest, idempotencyKey string) error
	GetSubjectsByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.SubjectCourseMapping, error)
	GetSubjectsByCourseAndTerm(ctx context.Context, courseID uuid.UUID, termNumber int) ([]*models.SubjectCourseMapping, error)
	GetCoursesBySubject(ctx context.Context, subjectID uuid.UUID) ([]*models.SubjectCourseMapping, error)
	RemoveMapping(ctx context.Context, mappingID uuid.UUID, idempotencyKey string) error
	RemoveAllForCourse(ctx context.Context, courseID uuid.UUID, idempotencyKey string) error
	Exists(ctx context.Context, courseID, subjectID uuid.UUID, termNumber int) (bool, error)
	ValidateCurriculum(ctx context.Context, courseID uuid.UUID) error
}

type curriculumService struct {
	mappingRepo         repository.SubjectCourseMappingRepository
	courseRepo          repository.CourseRepository
	subjectRepo         repository.SubjectRepository
	pgClient            *client.PostgresClient
	logger              *zap.Logger
	notificationService NotificationService
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	outboxRepo          outbox.Repository
}

func NewCurriculumService(
	mappingRepo repository.SubjectCourseMappingRepository,
	courseRepo repository.CourseRepository,
	subjectRepo repository.SubjectRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationService NotificationService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
) CurriculumService {
	return &curriculumService{
		mappingRepo:         mappingRepo,
		courseRepo:          courseRepo,
		subjectRepo:         subjectRepo,
		pgClient:            pgClient,
		logger:              logger.Named("curriculum_service"),
		notificationService: notificationService,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		outboxRepo:          outboxRepo,
	}
}

// storeOutboxEvent now includes the Topic field.
func (s *curriculumService) storeOutboxEvent(ctx context.Context, tx *sql.Tx, eventType EventType, aggregateID uuid.UUID, payload interface{}) error {
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
		AggregateType: "subject_course_mapping",
		AggregateID:   aggregateID.String(),
		EventType:     string(eventType),
		Topic:         TopicSubject, // <-- ADDED TOPIC
		Payload:       data,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, outboxEvent)
}

func (s *curriculumService) buildNotificationRequestForCurriculum(
	course *models.Course,
	subject *models.Subject,
	termNumber int,
	operation string,
	actor *uuid.UUID,
) CreateNotificationRequest {
	var title, message string
	var notificationType models.NotificationType
	priority := models.PriorityNormal

	switch operation {
	case "assigned":
		title = "Subject Assigned to Course"
		message = fmt.Sprintf("Subject '%s' (%s) has been assigned to course '%s' (%s) for term %d",
			subject.Name, subject.Code, course.Name, course.Code, termNumber)
		notificationType = models.NotificationTypeInfo
	case "unassigned":
		title = "Subject Removed from Course"
		message = fmt.Sprintf("Subject '%s' (%s) has been removed from course '%s' (%s) for term %d",
			subject.Name, subject.Code, course.Name, course.Code, termNumber)
		notificationType = models.NotificationTypeWarning
		priority = models.PriorityHigh
	default:
		title = "Curriculum Changed"
		message = fmt.Sprintf("Curriculum for course '%s' has been modified", course.Name)
		notificationType = models.NotificationTypeInfo
	}

	return CreateNotificationRequest{
		CompanyID: course.CompanyID,
		Title:     title,
		Message:   message,
		Type:      notificationType,
		Priority:  priority,
		ExpiresAt: nil,
		Targets: []NotificationTargetInput{
			{
				TargetType:     models.TargetCourse,
				TargetEntityID: course.CourseID,
			},
			{
				TargetType:     models.TargetCompany,
				TargetEntityID: course.CompanyID,
			},
		},
		CreatedBy: actor,
	}
}

func (s *curriculumService) AssignSubjectToCourse(ctx context.Context, req AssignSubjectRequest, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "AssignSubjectToCourse"),
		zap.String("course_id", req.CourseID.String()),
		zap.String("subject_id", req.SubjectID.String()),
		zap.Int("term", req.TermNumber),
		zap.String("idempotency_key", idempotencyKey),
	)

	if err := s.validateAssign(req); err != nil {
		return err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing struct{ Dummy bool }
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	course, err := s.courseRepo.GetByIDForUpdate(ctx, tx, req.CourseID)
	if err != nil {
		return err
	}
	if course == nil {
		return fmt.Errorf("%w: course %s", ErrNotFound, req.CourseID)
	}

	subject, err := s.subjectRepo.GetByID(ctx, tx, req.SubjectID)
	if err != nil {
		return err
	}
	if subject == nil {
		return fmt.Errorf("%w: subject %s", ErrNotFound, req.SubjectID)
	}

	exists, err := s.mappingRepo.Exists(ctx, tx, req.CourseID, req.SubjectID, req.TermNumber)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: subject already assigned for term %d", ErrDuplicate, req.TermNumber)
	}

	mapping := &models.SubjectCourseMapping{
		CourseID:     req.CourseID,
		SubjectID:    req.SubjectID,
		TermNumber:   req.TermNumber,
		IsCompulsory: req.IsCompulsory,
	}

	if err := s.mappingRepo.Create(ctx, tx, mapping); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "assign", "subject_course_mapping",
			&mapping.MappingID, "user", nil, nil, nil, map[string]interface{}{
				"course_id":     mapping.CourseID,
				"subject_id":    mapping.SubjectID,
				"term_number":   mapping.TermNumber,
				"is_compulsory": mapping.IsCompulsory,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventSubjectAssigned, mapping.MappingID, mapping); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject assigned", zap.String("mapping_id", mapping.MappingID.String()))

	if s.notificationService != nil {
		notifReq := s.buildNotificationRequestForCurriculum(course, subject, req.TermNumber, "assigned", nil)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

func (s *curriculumService) BulkAssignSubjects(ctx context.Context, reqs []AssignSubjectRequest, idempotencyKey string) error {
	if len(reqs) == 0 {
		return nil
	}

	logger := s.logger.With(
		zap.String("method", "BulkAssignSubjects"),
		zap.Int("count", len(reqs)),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing struct{ Dummy bool }
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	courseIDs := make(map[uuid.UUID]struct{})
	subjectIDs := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		courseIDs[req.CourseID] = struct{}{}
		subjectIDs[req.SubjectID] = struct{}{}
	}

	coursesMap := make(map[uuid.UUID]*models.Course)
	for cid := range courseIDs {
		course, err := s.courseRepo.GetByIDForUpdate(ctx, tx, cid)
		if err != nil {
			return err
		}
		if course == nil {
			return fmt.Errorf("%w: course %s", ErrNotFound, cid)
		}
		coursesMap[cid] = course
	}

	subjectsMap := make(map[uuid.UUID]*models.Subject)
	for sid := range subjectIDs {
		subject, err := s.subjectRepo.GetByID(ctx, tx, sid)
		if err != nil {
			return err
		}
		if subject == nil {
			return fmt.Errorf("%w: subject %s", ErrNotFound, sid)
		}
		subjectsMap[sid] = subject
	}

	existingMappings, err := s.mappingRepo.ListByCourseIDsAndTermNumbers(ctx, tx, keysToSlice(courseIDs), nil)
	if err != nil {
		return fmt.Errorf("preload mappings: %w", err)
	}
	existingKeyMap := make(map[string]bool)
	for _, m := range existingMappings {
		key := m.CourseID.String() + ":" + m.SubjectID.String() + ":" + fmt.Sprint(m.TermNumber)
		existingKeyMap[key] = true
	}

	seen := make(map[string]bool)
	var mappings []*models.SubjectCourseMapping
	for i, req := range reqs {
		if err := s.validateAssign(req); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
		key := req.CourseID.String() + ":" + req.SubjectID.String() + ":" + fmt.Sprint(req.TermNumber)
		if seen[key] {
			return fmt.Errorf("item %d: %w: duplicate in batch", i, ErrDuplicate)
		}
		seen[key] = true

		if existingKeyMap[key] {
			return fmt.Errorf("item %d: %w: already exists", i, ErrDuplicate)
		}

		if _, ok := coursesMap[req.CourseID]; !ok {
			return fmt.Errorf("item %d: course %s not found", i, req.CourseID)
		}
		if _, ok := subjectsMap[req.SubjectID]; !ok {
			return fmt.Errorf("item %d: subject %s not found", i, req.SubjectID)
		}

		mappings = append(mappings, &models.SubjectCourseMapping{
			CourseID:     req.CourseID,
			SubjectID:    req.SubjectID,
			TermNumber:   req.TermNumber,
			IsCompulsory: req.IsCompulsory,
		})
	}

	if err := s.mappingRepo.BulkCreate(ctx, tx, mappings); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	for _, m := range mappings {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_assign", "subject_course_mapping",
				&m.MappingID, "user", nil, nil, nil, map[string]interface{}{
					"course_id":     m.CourseID,
					"subject_id":    m.SubjectID,
					"term_number":   m.TermNumber,
					"is_compulsory": m.IsCompulsory,
				})
		}
		if err := s.storeOutboxEvent(ctx, tx, EventSubjectAssigned, m.MappingID, m); err != nil {
			return fmt.Errorf("outbox store for mapping %s: %w", m.MappingID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk assigned subjects", zap.Int("count", len(mappings)))

	if s.notificationService != nil {
		for _, m := range mappings {
			course := coursesMap[m.CourseID]
			subject := subjectsMap[m.SubjectID]
			notifReq := s.buildNotificationRequestForCurriculum(course, subject, m.TermNumber, "assigned", nil)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification for mapping",
					zap.String("mapping_id", m.MappingID.String()),
					zap.Error(err))
			}
		}
	}

	return nil
}

func (s *curriculumService) RemoveMapping(ctx context.Context, mappingID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "RemoveMapping"),
		zap.String("mapping_id", mappingID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing struct{ Dummy bool }
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	mapping, err := s.mappingRepo.GetByIDForUpdate(ctx, tx, mappingID)
	if err != nil {
		return err
	}
	if mapping == nil {
		return fmt.Errorf("%w: mapping %s", ErrNotFound, mappingID)
	}

	course, err := s.courseRepo.GetByID(ctx, tx, mapping.CourseID)
	if err != nil {
		return err
	}
	if course == nil {
		return fmt.Errorf("%w: course %s for mapping", ErrNotFound, mapping.CourseID)
	}

	subject, err := s.subjectRepo.GetByID(ctx, tx, mapping.SubjectID)
	if err != nil {
		return err
	}
	if subject == nil {
		return fmt.Errorf("%w: subject %s for mapping", ErrNotFound, mapping.SubjectID)
	}

	if err := s.mappingRepo.Delete(ctx, tx, mappingID); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "unassign", "subject_course_mapping",
			&mappingID, "user", nil, nil, nil, map[string]interface{}{
				"course_id":   mapping.CourseID,
				"subject_id":  mapping.SubjectID,
				"term_number": mapping.TermNumber,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventSubjectUnassigned, mappingID, mapping); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("mapping removed")

	if s.notificationService != nil {
		notifReq := s.buildNotificationRequestForCurriculum(course, subject, mapping.TermNumber, "unassigned", nil)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

func (s *curriculumService) RemoveAllForCourse(ctx context.Context, courseID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "RemoveAllForCourse"),
		zap.String("course_id", courseID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing struct{ Dummy bool }
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	course, err := s.courseRepo.GetByIDForUpdate(ctx, tx, courseID)
	if err != nil {
		return err
	}
	if course == nil {
		return fmt.Errorf("%w: course %s", ErrNotFound, courseID)
	}

	mappings, err := s.mappingRepo.ListByCourse(ctx, tx, courseID)
	if err != nil {
		return err
	}

	if err := s.mappingRepo.DeleteByCourse(ctx, tx, courseID); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	for _, m := range mappings {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "remove_all", "subject_course_mapping",
				&m.MappingID, "user", nil, nil, nil, map[string]interface{}{
					"course_id":   m.CourseID,
					"subject_id":  m.SubjectID,
					"term_number": m.TermNumber,
				})
		}
		if err := s.storeOutboxEvent(ctx, tx, EventSubjectUnassigned, m.MappingID, m); err != nil {
			return fmt.Errorf("outbox store for mapping %s: %w", m.MappingID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("all mappings removed", zap.Int("count", len(mappings)))

	if s.notificationService != nil && len(mappings) > 0 {
		title := "All Subjects Removed from Course"
		message := fmt.Sprintf("All subjects have been removed from course '%s' (%s)", course.Name, course.Code)
		notifReq := CreateNotificationRequest{
			CompanyID: course.CompanyID,
			Title:     title,
			Message:   message,
			Type:      models.NotificationTypeWarning,
			Priority:  models.PriorityHigh,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetCourse, TargetEntityID: course.CourseID},
				{TargetType: models.TargetCompany, TargetEntityID: course.CompanyID},
			},
			CreatedBy: nil,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create summary notification", zap.Error(err))
		}
	}

	return nil
}

func (s *curriculumService) GetSubjectsByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.SubjectCourseMapping, error) {
	return s.mappingRepo.ListByCourse(ctx, s.pgClient.DB, courseID)
}

func (s *curriculumService) GetSubjectsByCourseAndTerm(ctx context.Context, courseID uuid.UUID, termNumber int) ([]*models.SubjectCourseMapping, error) {
	return s.mappingRepo.ListByCourseAndTerm(ctx, s.pgClient.DB, courseID, termNumber)
}

func (s *curriculumService) GetCoursesBySubject(ctx context.Context, subjectID uuid.UUID) ([]*models.SubjectCourseMapping, error) {
	return s.mappingRepo.ListBySubject(ctx, s.pgClient.DB, subjectID)
}

func (s *curriculumService) Exists(ctx context.Context, courseID, subjectID uuid.UUID, termNumber int) (bool, error) {
	return s.mappingRepo.Exists(ctx, s.pgClient.DB, courseID, subjectID, termNumber)
}

func (s *curriculumService) ValidateCurriculum(ctx context.Context, courseID uuid.UUID) error {
	return nil
}

func (s *curriculumService) validateAssign(req AssignSubjectRequest) error {
	if req.CourseID == uuid.Nil {
		return fmt.Errorf("%w: course_id is required", ErrInvalidInput)
	}
	if req.SubjectID == uuid.Nil {
		return fmt.Errorf("%w: subject_id is required", ErrInvalidInput)
	}
	if req.TermNumber <= 0 {
		return fmt.Errorf("%w: term_number must be positive", ErrInvalidInput)
	}
	return nil
}
