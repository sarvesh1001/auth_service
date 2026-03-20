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

type curriculumService struct {
	mappingRepo    repository.SubjectCourseMappingRepository
	courseRepo     repository.CourseRepository
	subjectRepo    repository.SubjectRepository
	eventPublisher EventPublisher
	pgClient       *client.PostgresClient
	logger         *zap.Logger
}

func NewCurriculumService(
	mappingRepo repository.SubjectCourseMappingRepository,
	courseRepo repository.CourseRepository,
	subjectRepo repository.SubjectRepository,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) CurriculumService {
	return &curriculumService{
		mappingRepo:    mappingRepo,
		courseRepo:     courseRepo,
		subjectRepo:    subjectRepo,
		eventPublisher: eventPublisher,
		pgClient:       pgClient,
		logger:         logger.Named("curriculum_service"),
	}
}

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

	// Verify course exists (not deleted)
	course, err := s.courseRepo.GetByID(ctx, tx, req.CourseID)
	if err != nil {
		return err
	}
	if course == nil {
		return fmt.Errorf("%w: course %s", ErrNotFound, req.CourseID)
	}

	// Verify subject exists (not deleted)
	subject, err := s.subjectRepo.GetByID(ctx, tx, req.SubjectID)
	if err != nil {
		return err
	}
	if subject == nil {
		return fmt.Errorf("%w: subject %s", ErrNotFound, req.SubjectID)
	}

	// Check if mapping already exists
	exists, err := s.mappingRepo.Exists(ctx, tx, req.CourseID, req.SubjectID, req.TermNumber)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: subject already assigned to this course for term %d", ErrDuplicate, req.TermNumber)
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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject assigned to course", zap.String("mapping_id", mapping.MappingID.String()))

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSubjectAssigned,
		Data: mapping,
	}); err != nil {
		logger.Error("failed to publish subject.assigned event", zap.Error(err))
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
	courseIDsMap := make(map[uuid.UUID]struct{})
	subjectIDsMap := make(map[uuid.UUID]struct{})
	termNumbersSet := make(map[int]struct{})
	for _, req := range reqs {
		courseIDsMap[req.CourseID] = struct{}{}
		subjectIDsMap[req.SubjectID] = struct{}{}
		termNumbersSet[req.TermNumber] = struct{}{}
	}
	courseIDs := keysToSlice(courseIDsMap)
	subjectIDs := keysToSlice(subjectIDsMap)
	termNumbers := make([]int, 0, len(termNumbersSet))
	for tn := range termNumbersSet {
		termNumbers = append(termNumbers, tn)
	}

	// Preload courses
	coursesMap, err := s.courseRepo.GetByIDs(ctx, tx, courseIDs)
	if err != nil {
		return fmt.Errorf("failed to preload courses: %w", err)
	}
	if len(coursesMap) != len(courseIDs) {
		for _, cid := range courseIDs {
			if _, ok := coursesMap[cid]; !ok {
				return fmt.Errorf("%w: course %s", ErrNotFound, cid)
			}
		}
	}

	// Preload subjects
	subjectsMap, err := s.subjectRepo.GetByIDs(ctx, tx, subjectIDs)
	if err != nil {
		return fmt.Errorf("failed to preload subjects: %w", err)
	}
	if len(subjectsMap) != len(subjectIDs) {
		for _, sid := range subjectIDs {
			if _, ok := subjectsMap[sid]; !ok {
				return fmt.Errorf("%w: subject %s", ErrNotFound, sid)
			}
		}
	}

	// Preload existing mappings
	existingMappings, err := s.mappingRepo.ListByCourseIDsAndTermNumbers(ctx, tx, courseIDs, termNumbers)
	if err != nil {
		return fmt.Errorf("failed to preload existing mappings: %w", err)
	}
	existingKeyMap := make(map[string]bool)
	for _, m := range existingMappings {
		key := m.CourseID.String() + ":" + m.SubjectID.String() + ":" + fmt.Sprint(m.TermNumber)
		existingKeyMap[key] = true
	}

	// Build list of new mappings, validate in memory
	seen := make(map[string]bool)
	var mappings []*models.SubjectCourseMapping
	for i, req := range reqs {
		if err := s.validateAssign(req); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
		key := req.CourseID.String() + ":" + req.SubjectID.String() + ":" + fmt.Sprint(req.TermNumber)
		if seen[key] {
			return fmt.Errorf("item %d: %w: duplicate assignment in batch", i, ErrDuplicate)
		}
		seen[key] = true

		if existingKeyMap[key] {
			return fmt.Errorf("item %d: %w: mapping already exists", i, ErrDuplicate)
		}

		// Verify course and subject exist (already checked via maps)
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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk assigned subjects to courses", zap.Int("count", len(mappings)))

	// Publish events for each new mapping
	for _, m := range mappings {
		if err := s.eventPublisher.Publish(ctx, Event{
			Type: EventSubjectAssigned,
			Data: m,
		}); err != nil {
			logger.Error("failed to publish subject.assigned event", zap.String("mapping_id", m.MappingID.String()), zap.Error(err))
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

func (s *curriculumService) RemoveMapping(ctx context.Context, mappingID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveMapping"), zap.String("mapping_id", mappingID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Optionally fetch the mapping before deletion to include in event
	mapping, err := s.mappingRepo.GetByID(ctx, tx, mappingID)
	if err != nil {
		return err
	}
	if mapping == nil {
		return fmt.Errorf("%w: mapping %s", ErrNotFound, mappingID)
	}

	if err := s.mappingRepo.Delete(ctx, tx, mappingID); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject-course mapping removed")

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSubjectUnassigned,
		Data: mapping,
	}); err != nil {
		logger.Error("failed to publish subject.unassigned event", zap.Error(err))
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

	// Optionally fetch mappings before deletion for events
	mappings, err := s.mappingRepo.ListByCourse(ctx, tx, courseID)
	if err != nil {
		return err
	}

	if err := s.mappingRepo.DeleteByCourse(ctx, tx, courseID); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("all subject mappings removed for course", zap.Int("count", len(mappings)))

	// Publish individual events for each removed mapping
	for _, m := range mappings {
		if err := s.eventPublisher.Publish(ctx, Event{
			Type: EventSubjectUnassigned,
			Data: m,
		}); err != nil {
			logger.Error("failed to publish subject.unassigned event", zap.String("mapping_id", m.MappingID.String()), zap.Error(err))
		}
	}

	return nil
}

func (s *curriculumService) Exists(ctx context.Context, courseID, subjectID uuid.UUID, termNumber int) (bool, error) {
	return s.mappingRepo.Exists(ctx, s.pgClient.DB, courseID, subjectID, termNumber)
}

func (s *curriculumService) ValidateCurriculum(ctx context.Context, courseID uuid.UUID) error {
	// Example: ensure that for each term, the total credits of compulsory subjects do not exceed a limit, etc.
	// Not implemented here.
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
