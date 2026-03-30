package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// ---------------------------------------------------------------------
// CurriculumService interface (unchanged)
// ---------------------------------------------------------------------

type CurriculumService interface {
	AssignSubjectToCourse(ctx context.Context, req AssignSubjectRequest) error
	BulkAssignSubjects(ctx context.Context, reqs []AssignSubjectRequest) error

	GetSubjectsByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.SubjectCourseMapping, error)
	GetSubjectsByCourseAndTerm(ctx context.Context, courseID uuid.UUID, termNumber int) ([]*models.SubjectCourseMapping, error)

	GetCoursesBySubject(ctx context.Context, subjectID uuid.UUID) ([]*models.SubjectCourseMapping, error)

	RemoveMapping(ctx context.Context, mappingID uuid.UUID) error
	RemoveAllForCourse(ctx context.Context, courseID uuid.UUID) error

	Exists(ctx context.Context, courseID, subjectID uuid.UUID, termNumber int) (bool, error)

	ValidateCurriculum(ctx context.Context, courseID uuid.UUID) error
}

// ---------------------------------------------------------------------
// curriculumService struct (updated)
// ---------------------------------------------------------------------

type curriculumService struct {
	mappingRepo repository.SubjectCourseMappingRepository
	courseRepo  repository.CourseRepository
	subjectRepo repository.SubjectRepository

	auditLogger         AuditLogger
	outboxStore         OutboxStore
	notificationService NotificationService // added

	pgClient *client.PostgresClient
	logger   *zap.Logger
}

// ---------------------------------------------------------------------
// Constructor (updated)
// ---------------------------------------------------------------------

func NewCurriculumService(
	mappingRepo repository.SubjectCourseMappingRepository,
	courseRepo repository.CourseRepository,
	subjectRepo repository.SubjectRepository,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationService NotificationService, // new parameter
) CurriculumService {
	return &curriculumService{
		mappingRepo:         mappingRepo,
		courseRepo:          courseRepo,
		subjectRepo:         subjectRepo,
		auditLogger:         auditLogger,
		outboxStore:         outboxStore,
		pgClient:            pgClient,
		logger:              logger.Named("curriculum_service"),
		notificationService: notificationService,
	}
}

// ---------------------------------------------------------------------
// Helper for notification creation
// ---------------------------------------------------------------------

// buildNotificationRequestForCurriculum constructs a CreateNotificationRequest for curriculum changes.
func (s *curriculumService) buildNotificationRequestForCurriculum(
	course *models.Course,
	subject *models.Subject,
	termNumber int,
	operation string, // "assigned" or "unassigned"
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

// ---------------------------------------------------------------------
// Core Operations (updated with notifications)
// ---------------------------------------------------------------------

func (s *curriculumService) AssignSubjectToCourse(ctx context.Context, req AssignSubjectRequest) error {
	logger := s.logger.With(
		zap.String("method", "AssignSubjectToCourse"),
		zap.String("course_id", req.CourseID.String()),
		zap.String("subject_id", req.SubjectID.String()),
		zap.Int("term", req.TermNumber),
	)

	if err := s.validateAssign(req); err != nil {
		return err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Lock the course to prevent concurrent curriculum changes
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

	// Audit log
	if err := s.auditLogger.Log(ctx, tx, "CURRICULUM_ASSIGN",
		mapping.MappingID, nil, mapping, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(EventSubjectAssigned), mapping); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject assigned", zap.String("mapping_id", mapping.MappingID.String()))

	// Create notification (after commit)
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequestForCurriculum(course, subject, req.TermNumber, "assigned", nil) // actor is nil because request doesn't have one
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

func (s *curriculumService) BulkAssignSubjects(ctx context.Context, reqs []AssignSubjectRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	logger := s.logger.With(zap.String("method", "BulkAssignSubjects"), zap.Int("count", len(reqs)))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Collect all course and subject IDs
	courseIDs := make(map[uuid.UUID]struct{})
	subjectIDs := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		courseIDs[req.CourseID] = struct{}{}
		subjectIDs[req.SubjectID] = struct{}{}
	}

	// Preload and lock courses
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

	// Preload subjects (no lock needed for subjects as they're read-only)
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

	// Preload existing mappings
	existingMappings, err := s.mappingRepo.ListByCourseIDsAndTermNumbers(ctx, tx, keysToSlice(courseIDs), nil)
	if err != nil {
		return fmt.Errorf("preload mappings: %w", err)
	}
	existingKeyMap := make(map[string]bool)
	for _, m := range existingMappings {
		key := m.CourseID.String() + ":" + m.SubjectID.String() + ":" + fmt.Sprint(m.TermNumber)
		existingKeyMap[key] = true
	}

	// Validate and build new mappings
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

		// Verify course and subject exist (already in maps)
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

	// Audit logs (optional per mapping)
	for _, m := range mappings {
		if err := s.auditLogger.Log(ctx, tx, "CURRICULUM_BULK_ASSIGN",
			m.MappingID, nil, m, nil); err != nil {
			logger.Error("audit log failed", zap.String("mapping_id", m.MappingID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventSubjectAssigned), m); err != nil {
			return fmt.Errorf("outbox store for mapping %s: %w", m.MappingID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk assigned subjects", zap.Int("count", len(mappings)))

	// Create notifications (after commit)
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

func (s *curriculumService) RemoveMapping(ctx context.Context, mappingID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveMapping"), zap.String("mapping_id", mappingID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	mapping, err := s.mappingRepo.GetByIDForUpdate(ctx, tx, mappingID)
	if err != nil {
		return err
	}
	if mapping == nil {
		return fmt.Errorf("%w: mapping %s", ErrNotFound, mappingID)
	}

	// Fetch course and subject details for notification
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

	// Audit log
	if err := s.auditLogger.Log(ctx, tx, "CURRICULUM_UNASSIGN",
		mappingID, mapping, nil, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(EventSubjectUnassigned), mapping); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("mapping removed")

	// Create notification (after commit)
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequestForCurriculum(course, subject, mapping.TermNumber, "unassigned", nil)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

func (s *curriculumService) RemoveAllForCourse(ctx context.Context, courseID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveAllForCourse"), zap.String("course_id", courseID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Lock the course
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

	// Audit and outbox for each removed mapping
	for _, m := range mappings {
		if err := s.auditLogger.Log(ctx, tx, "CURRICULUM_REMOVE_ALL",
			m.MappingID, m, nil, nil); err != nil {
			logger.Error("audit log failed", zap.String("mapping_id", m.MappingID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventSubjectUnassigned), m); err != nil {
			return fmt.Errorf("outbox store for mapping %s: %w", m.MappingID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("all mappings removed", zap.Int("count", len(mappings)))

	// Create notifications (after commit) – for each removed mapping
	if s.notificationService != nil && len(mappings) > 0 {
		// Fetch subject details (we already have them? Not in mappings list; we need to fetch each subject)
		// Alternatively, we can send a summary notification. For simplicity, we'll send one summary notification.
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

// ---------------------------------------------------------------------
// Read‑only operations (unchanged)
// ---------------------------------------------------------------------

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
	// Example: ensure that for each term, the total credits of compulsory subjects do not exceed a limit, etc.
	return nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

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
