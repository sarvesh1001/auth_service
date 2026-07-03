package factory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/academics"
	"auth-service/internal/academics/handler"
	"auth-service/internal/academics/repository"
	academicsvc "auth-service/internal/academics/service"
	"auth-service/internal/client"
	"auth-service/internal/email"
	"auth-service/internal/encryption"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	mainservice "auth-service/internal/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------
// EventPublisher interface and Kafka wrapper
// ---------------------------------------------------------------------

type EventPublisher interface {
	Publish(ctx context.Context, topic string, key string, data []byte) error
}

type kafkaEventPublisher struct {
	producer *client.KafkaProducer
}

func (k *kafkaEventPublisher) Publish(ctx context.Context, topic string, key string, data []byte) error {
	return k.producer.ProduceMessage(ctx, topic, []byte(key), data, nil)
}

// ---------------------------------------------------------------------
// Interface adapters (retained for compatibility)
// ---------------------------------------------------------------------

type auditLoggerAdapter struct {
	svc *audit.AuditService
}

func (a *auditLoggerAdapter) Log(ctx context.Context, tx *sql.Tx, action string, entityID uuid.UUID, oldValue, newValue interface{}, userID *uuid.UUID) error {
	var afterState []byte
	if newValue != nil {
		afterState, _ = json.Marshal(newValue)
	}
	actorType := "system"
	if userID != nil {
		actorType = "user"
	}
	return a.svc.LogAction(ctx, tx, nil, "academics", action, "notification", &entityID, actorType, userID, nil, afterState, nil)
}

type outboxStoreAdapter struct {
	repo outbox.Repository
}

func (o *outboxStoreAdapter) Store(ctx context.Context, tx *sql.Tx, eventType string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:   uuid.New().String(),
		EventType: eventType,
		Payload:   data,
		CreatedAt: time.Now(),
	}
	return o.repo.Store(ctx, tx, event)
}

type eventPublisherAdapter struct {
	pub EventPublisher
}

func (e *eventPublisherAdapter) Publish(ctx context.Context, event academicsvc.Event) error {
	data, err := json.Marshal(event.Data)
	if err != nil {
		return err
	}
	return e.pub.Publish(ctx, string(event.Type), string(event.Type), data)
}

// ---------------------------------------------------------------------
// AcademicsInfraFactory
// ---------------------------------------------------------------------

type AcademicsInfraFactory struct {
	log *zap.Logger

	// Shared dependencies
	postgresClient *client.PostgresClient
	eventPublisher EventPublisher
	auditService   *audit.AuditService
	emailSender    email.Sender
	sessionService *mainservice.SessionService

	// Repositories
	academicEventRepo        repository.AcademicEventRepository
	academicYearRepo         repository.AcademicYearRepository
	admissionRepo            repository.AdmissionRepository
	analyticsRepo            repository.AnalyticsRepository
	assignmentRepo           repository.AssignmentRepository
	courseRepo               repository.CourseRepository
	enrollmentRepo           repository.EnrollmentRepository
	examRepo                 repository.ExamRepository
	feeRepo                  repository.FeeRepository
	gradingRepo              repository.GradingRepository
	guardianRepo             repository.GuardianRepository
	libraryRepo              repository.LibraryRepository
	notificationRepo         repository.NotificationRepository
	roomRepo                 repository.RoomRepository
	sectionRepo              repository.SectionRepository
	studentAuthRepo          repository.StudentAuthRepository
	studentRepo              repository.StudentRepository
	subjectCourseMappingRepo repository.SubjectCourseMappingRepository
	subjectRepo              repository.SubjectRepository
	submissionRepo           repository.SubmissionRepository
	teacherRepo              repository.TeacherRepository
	termRepo                 repository.TermRepository
	timetableRepo            repository.TimetableRepository
	transportRepo            repository.TransportRepository

	// Idempotency & Outbox
	idempotencyStore idempotency.Store
	outboxRepo       outbox.Repository

	// Services
	notificationService academicsvc.NotificationService
	examService         academicsvc.ExamService
	studentAuthService  academicsvc.StudentAuthService
	guardianService     academicsvc.GuardianService
	enrollmentService   academicsvc.EnrollmentService
	sectionService      academicsvc.SectionService
	academicYearService academicsvc.AcademicYearService
	gradingService      academicsvc.GradingService
	transportService    academicsvc.TransportService
	teacherService      academicsvc.TeacherService
	submissionService   academicsvc.SubmissionService
	curriculumService   academicsvc.CurriculumService
	subjectService      academicsvc.SubjectService
	studentService      academicsvc.StudentService
	libraryService      academicsvc.LibraryService
	roomService         academicsvc.RoomService
	timetableService    academicsvc.TimetableService
	courseService       academicsvc.CourseService
	termService         academicsvc.TermService
	analyticsService    academicsvc.AnalyticsService
	admissionService    academicsvc.AdmissionService
	assignmentService   academicsvc.AssignmentService
	feeService          academicsvc.FeeService

	// Handlers
	academicYearHandler      *handler.AcademicYearHandler
	sectionHandler           *handler.SectionHandler
	enrollmentHandler        *handler.EnrollmentHandler
	guardianHandler          *handler.GuardianHandler
	examHandler              *handler.ExamHandler
	notificationHandler      *handler.NotificationHandler
	submissionHandler        *handler.SubmissionHandler
	teacherHandler           *handler.TeacherHandler
	transportHandler         *handler.TransportHandler
	gradingHandler           *handler.GradingHandler
	courseHandler            *handler.CourseHandler
	timetableHandler         *handler.TimetableHandler
	libraryHandler           *handler.LibraryHandler
	studentHandler           *handler.StudentHandler
	roomHandler              *handler.RoomHandler
	subjectHandler           *handler.SubjectHandler
	feeHandler               *handler.FeeHandler
	assignmentHandler        *handler.AssignmentHandler
	admissionHandler         *handler.AdmissionHandler
	termHandler              *handler.TermHandler
	analyticsHandler         *handler.AnalyticsHandler
	curriculumHandler        *handler.CurriculumHandler
	academicSessionRepo      repository.AcademicSessionRepository
	sessionGenerationService academicsvc.SessionGenerationService
	sessionGenerationHandler *handler.SessionGenerationHandler
}

// NewAcademicsInfraFactory constructor
func NewAcademicsInfraFactory(
	postgresClient *client.PostgresClient,
	redisClient *client.RedisClient,
	sharedOutboxRepo outbox.Repository,
	encryptionManager *encryption.EncryptionManager,
	eventPublisher EventPublisher,
	auditService *audit.AuditService,
	emailSender email.Sender,
	sessionService *mainservice.SessionService,
	logger *zap.Logger,
) (*AcademicsInfraFactory, error) {
	log := logger.Named("academics_infra")
	log.Info("🏭 AcademicsInfraFactory construction started")

	af := &AcademicsInfraFactory{
		log:            log,
		postgresClient: postgresClient,
		eventPublisher: eventPublisher,
		auditService:   auditService,
		emailSender:    emailSender,
		sessionService: sessionService,
		outboxRepo:     sharedOutboxRepo,
	}

	// Idempotency store
	log.Info("Initialising idempotency store")
	pgStore := idempotency.NewPostgresStore(postgresClient.DB)
	redisCache := idempotency.NewRedisCache(redisClient, 24*time.Hour)
	af.idempotencyStore = idempotency.NewHybridStore(pgStore, redisCache)

	// Repositories – log each creation
	af.academicEventRepo = repository.NewAcademicEventRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "AcademicEvent"))
	af.academicYearRepo = repository.NewAcademicYearRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "AcademicYear"))
	af.admissionRepo = repository.NewAdmissionRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Admission"))
	af.analyticsRepo = repository.NewAnalyticsRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Analytics"))
	af.assignmentRepo = repository.NewAssignmentRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Assignment"))
	af.courseRepo = repository.NewCourseRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Course"))
	af.enrollmentRepo = repository.NewEnrollmentRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Enrollment"))
	af.examRepo = repository.NewExamRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Exam"))
	af.feeRepo = repository.NewFeeRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Fee"))
	af.gradingRepo = repository.NewGradingRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Grading"))
	af.guardianRepo = repository.NewGuardianRepository(af.log, encryptionManager)
	log.Info("Repository initialised", zap.String("repo", "Guardian"))
	af.libraryRepo = repository.NewLibraryRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Library"))
	af.notificationRepo = repository.NewNotificationRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Notification"))
	af.roomRepo = repository.NewRoomRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Room"))
	af.sectionRepo = repository.NewSectionRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Section"))
	af.studentAuthRepo = repository.NewStudentAuthRepository(af.log, encryptionManager)
	log.Info("Repository initialised", zap.String("repo", "StudentAuth"))
	af.studentRepo = repository.NewStudentRepository(af.log, encryptionManager)
	log.Info("Repository initialised", zap.String("repo", "Student"))
	af.subjectCourseMappingRepo = repository.NewSubjectCourseMappingRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "SubjectCourseMapping"))
	af.subjectRepo = repository.NewSubjectRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Subject"))
	af.submissionRepo = repository.NewSubmissionRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Submission"))
	af.teacherRepo = repository.NewTeacherRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Teacher"))
	af.termRepo = repository.NewTermRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Term"))
	af.timetableRepo = repository.NewTimetableRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Timetable"))
	af.transportRepo = repository.NewTransportRepository(af.log)
	log.Info("Repository initialised", zap.String("repo", "Transport"))

	// AcademicSessionRepo – the critical one
	af.academicSessionRepo = repository.NewAcademicSessionRepository(af.log)
	log.Info("✅ AcademicSessionRepository initialised",
		zap.Bool("is_nil", af.academicSessionRepo == nil),
		zap.String("type", fmt.Sprintf("%T", af.academicSessionRepo)),
	)

	log.Info("🏭 AcademicsInfraFactory construction completed")
	return af, nil
}

// ================================
// Repository Getters
// ================================

func (af *AcademicsInfraFactory) AcademicEventRepo() repository.AcademicEventRepository {
	return af.academicEventRepo
}
func (af *AcademicsInfraFactory) AcademicYearRepo() repository.AcademicYearRepository {
	return af.academicYearRepo
}
func (af *AcademicsInfraFactory) AdmissionRepo() repository.AdmissionRepository {
	return af.admissionRepo
}
func (af *AcademicsInfraFactory) AnalyticsRepo() repository.AnalyticsRepository {
	return af.analyticsRepo
}
func (af *AcademicsInfraFactory) AssignmentRepo() repository.AssignmentRepository {
	return af.assignmentRepo
}
func (af *AcademicsInfraFactory) CourseRepo() repository.CourseRepository {
	return af.courseRepo
}
func (af *AcademicsInfraFactory) EnrollmentRepo() repository.EnrollmentRepository {
	return af.enrollmentRepo
}
func (af *AcademicsInfraFactory) ExamRepo() repository.ExamRepository {
	return af.examRepo
}
func (af *AcademicsInfraFactory) FeeRepo() repository.FeeRepository {
	return af.feeRepo
}
func (af *AcademicsInfraFactory) GradingRepo() repository.GradingRepository {
	return af.gradingRepo
}
func (af *AcademicsInfraFactory) GuardianRepo() repository.GuardianRepository {
	return af.guardianRepo
}
func (af *AcademicsInfraFactory) LibraryRepo() repository.LibraryRepository {
	return af.libraryRepo
}
func (af *AcademicsInfraFactory) NotificationRepo() repository.NotificationRepository {
	return af.notificationRepo
}
func (af *AcademicsInfraFactory) RoomRepo() repository.RoomRepository {
	return af.roomRepo
}
func (af *AcademicsInfraFactory) SectionRepo() repository.SectionRepository {
	return af.sectionRepo
}
func (af *AcademicsInfraFactory) StudentAuthRepo() repository.StudentAuthRepository {
	return af.studentAuthRepo
}
func (af *AcademicsInfraFactory) StudentRepo() repository.StudentRepository {
	return af.studentRepo
}
func (af *AcademicsInfraFactory) SubjectCourseMappingRepo() repository.SubjectCourseMappingRepository {
	return af.subjectCourseMappingRepo
}
func (af *AcademicsInfraFactory) SubjectRepo() repository.SubjectRepository {
	return af.subjectRepo
}
func (af *AcademicsInfraFactory) SubmissionRepo() repository.SubmissionRepository {
	return af.submissionRepo
}
func (af *AcademicsInfraFactory) TeacherRepo() repository.TeacherRepository {
	return af.teacherRepo
}
func (af *AcademicsInfraFactory) TermRepo() repository.TermRepository {
	return af.termRepo
}
func (af *AcademicsInfraFactory) TimetableRepo() repository.TimetableRepository {
	return af.timetableRepo
}
func (af *AcademicsInfraFactory) TransportRepo() repository.TransportRepository {
	return af.transportRepo
}
func (af *AcademicsInfraFactory) IdempotencyStore() idempotency.Store {
	return af.idempotencyStore
}
func (af *AcademicsInfraFactory) OutboxRepository() outbox.Repository {
	return af.outboxRepo
}

// ================================
// Service Getters – with logging
// ================================

func (af *AcademicsInfraFactory) NotificationService() academicsvc.NotificationService {
	if af.notificationService == nil {
		af.log.Info("🔄 Creating NotificationService")
		af.notificationService = academicsvc.NewNotificationService(
			af.NotificationRepo(),
			af.postgresClient,
			af.log,
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
		af.log.Info("✅ NotificationService created", zap.Bool("is_nil", af.notificationService == nil))
	}
	return af.notificationService
}

func (af *AcademicsInfraFactory) ExamService() academicsvc.ExamService {
	if af.examService == nil {
		af.log.Info("🔄 Creating ExamService")
		af.examService = academicsvc.NewExamService(
			af.ExamRepo(),
			af.TermRepo(),
			af.AcademicYearRepo(),
			af.SubjectRepo(),
			af.EnrollmentRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
		)
		af.log.Info("✅ ExamService created", zap.Bool("is_nil", af.examService == nil))
	}
	return af.examService
}

func (af *AcademicsInfraFactory) StudentAuthService() academicsvc.StudentAuthService {
	if af.studentAuthService == nil {
		af.log.Info("🔄 Creating StudentAuthService")
		af.studentAuthService = academicsvc.NewStudentAuthService(
			af.StudentRepo(),
			af.StudentAuthRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
		)
		af.log.Info("✅ StudentAuthService created", zap.Bool("is_nil", af.studentAuthService == nil))
	}
	return af.studentAuthService
}

func (af *AcademicsInfraFactory) GuardianService() academicsvc.GuardianService {
	if af.guardianService == nil {
		af.log.Info("🔄 Creating GuardianService")
		af.guardianService = academicsvc.NewGuardianService(
			af.GuardianRepo(),
			af.StudentRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
		)
		af.log.Info("✅ GuardianService created", zap.Bool("is_nil", af.guardianService == nil))
	}
	return af.guardianService
}

func (af *AcademicsInfraFactory) EnrollmentService() academicsvc.EnrollmentService {
	if af.enrollmentService == nil {
		af.log.Info("🔄 Creating EnrollmentService")
		af.enrollmentService = academicsvc.NewEnrollmentService(
			af.EnrollmentRepo(),
			af.StudentRepo(),
			af.SectionRepo(),
			af.CourseRepo(),
			af.AcademicYearRepo(),
			af.TermRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
			&eventPublisherAdapter{pub: af.eventPublisher},
		)
		af.log.Info("✅ EnrollmentService created", zap.Bool("is_nil", af.enrollmentService == nil))
	}
	return af.enrollmentService
}

func (af *AcademicsInfraFactory) SectionService() academicsvc.SectionService {
	if af.sectionService == nil {
		af.log.Info("🔄 Creating SectionService")
		af.sectionService = academicsvc.NewSectionService(
			af.SectionRepo(),
			af.CourseRepo(),
			af.TermRepo(),
			af.EnrollmentRepo(),
			af.auditService,
			af.outboxRepo,
			af.idempotencyStore,
			af.postgresClient,
			af.log,
		)
		af.log.Info("✅ SectionService created", zap.Bool("is_nil", af.sectionService == nil))
	}
	return af.sectionService
}

func (af *AcademicsInfraFactory) AcademicYearService() academicsvc.AcademicYearService {
	if af.academicYearService == nil {
		af.log.Info("🔄 Creating AcademicYearService")
		af.academicYearService = academicsvc.NewAcademicYearService(
			af.AcademicYearRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
		)
		af.log.Info("✅ AcademicYearService created", zap.Bool("is_nil", af.academicYearService == nil))
	}
	return af.academicYearService
}

func (af *AcademicsInfraFactory) GradingService() academicsvc.GradingService {
	if af.gradingService == nil {
		af.log.Info("🔄 Creating GradingService")
		af.gradingService = academicsvc.NewGradingService(
			af.GradingRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			&eventPublisherAdapter{pub: af.eventPublisher},
			af.NotificationService(),
		)
		af.log.Info("✅ GradingService created", zap.Bool("is_nil", af.gradingService == nil))
	}
	return af.gradingService
}

func (af *AcademicsInfraFactory) TransportService() academicsvc.TransportService {
	if af.transportService == nil {
		af.log.Info("🔄 Creating TransportService")
		af.transportService = academicsvc.NewTransportService(
			af.TransportRepo(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
			af.postgresClient,
			af.log,
			af.NotificationService(),
		)
		af.log.Info("✅ TransportService created", zap.Bool("is_nil", af.transportService == nil))
	}
	return af.transportService
}

func (af *AcademicsInfraFactory) TeacherService() academicsvc.TeacherService {
	if af.teacherService == nil {
		af.log.Info("🔄 Creating TeacherService")
		af.teacherService = academicsvc.NewTeacherService(
			af.TeacherRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
		af.log.Info("✅ TeacherService created", zap.Bool("is_nil", af.teacherService == nil))
	}
	return af.teacherService
}

func (af *AcademicsInfraFactory) SubmissionService() academicsvc.SubmissionService {
	if af.submissionService == nil {
		af.log.Info("🔄 Creating SubmissionService")
		af.submissionService = academicsvc.NewSubmissionService(
			af.SubmissionRepo(),
			af.AssignmentRepo(),
			af.StudentService(),
			af.TeacherService(),
			af.NotificationService(),
			af.postgresClient,
			af.log,
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
		af.log.Info("✅ SubmissionService created", zap.Bool("is_nil", af.submissionService == nil))
	}
	return af.submissionService
}

func (af *AcademicsInfraFactory) CurriculumService() academicsvc.CurriculumService {
	if af.curriculumService == nil {
		af.log.Info("🔄 Creating CurriculumService")
		af.curriculumService = academicsvc.NewCurriculumService(
			af.SubjectCourseMappingRepo(),
			af.CourseRepo(),
			af.SubjectRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
		af.log.Info("✅ CurriculumService created", zap.Bool("is_nil", af.curriculumService == nil))
	}
	return af.curriculumService
}

func (af *AcademicsInfraFactory) SubjectService() academicsvc.SubjectService {
	if af.subjectService == nil {
		af.log.Info("🔄 Creating SubjectService")
		af.subjectService = academicsvc.NewSubjectService(
			af.SubjectRepo(),
			af.postgresClient,
			af.log,
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
		af.log.Info("✅ SubjectService created", zap.Bool("is_nil", af.subjectService == nil))
	}
	return af.subjectService
}

func (af *AcademicsInfraFactory) StudentService() academicsvc.StudentService {
	if af.studentService == nil {
		af.log.Info("🔄 Creating StudentService")
		af.studentService = academicsvc.NewStudentService(
			af.StudentRepo(),
			af.EnrollmentRepo(),
			af.SectionRepo(),
			af.CourseRepo(),
			af.TermRepo(),
			af.AcademicYearRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
		)
		af.log.Info("✅ StudentService created", zap.Bool("is_nil", af.studentService == nil))
	}
	return af.studentService
}

func (af *AcademicsInfraFactory) LibraryService() academicsvc.LibraryService {
	if af.libraryService == nil {
		af.log.Info("🔄 Creating LibraryService")
		af.libraryService = academicsvc.NewLibraryService(
			af.LibraryRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
			af.StudentService(),
		)
		af.log.Info("✅ LibraryService created", zap.Bool("is_nil", af.libraryService == nil))
	}
	return af.libraryService
}

func (af *AcademicsInfraFactory) RoomService() academicsvc.RoomService {
	if af.roomService == nil {
		af.log.Info("🔄 Creating RoomService")
		af.roomService = academicsvc.NewRoomService(
			af.RoomRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
		af.log.Info("✅ RoomService created", zap.Bool("is_nil", af.roomService == nil))
	}
	return af.roomService
}

// TimetableService – now with extra logging
func (af *AcademicsInfraFactory) TimetableService() academicsvc.TimetableService {
	if af.timetableService == nil {
		af.log.Info("🔄 Creating TimetableService")
		af.timetableService = academicsvc.NewTimetableService(
			af.TimetableRepo(),
			af.SectionRepo(),
			af.CourseRepo(),
			af.SubjectRepo(),
			af.TeacherRepo(),
			af.RoomRepo(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
			af.postgresClient,
			af.log,
			af.NotificationService(),
			af.academicSessionRepo, // ✅ non-nil now
		)
		af.log.Info("✅ TimetableService created",
			zap.Bool("is_nil", af.timetableService == nil),
			zap.Bool("academicSessionRepo_nil", af.academicSessionRepo == nil),
		)
	}
	return af.timetableService
}

func (af *AcademicsInfraFactory) CourseService() academicsvc.CourseService {
	if af.courseService == nil {
		af.log.Info("🔄 Creating CourseService")
		af.courseService = academicsvc.NewCourseService(
			af.CourseRepo(),
			af.SectionRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
		)
		af.log.Info("✅ CourseService created", zap.Bool("is_nil", af.courseService == nil))
	}
	return af.courseService
}

func (af *AcademicsInfraFactory) TermService() academicsvc.TermService {
	if af.termService == nil {
		af.log.Info("🔄 Creating TermService")
		af.termService = academicsvc.NewTermService(
			af.TermRepo(),
			af.AcademicYearRepo(),
			af.SectionRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
		)
		af.log.Info("✅ TermService created", zap.Bool("is_nil", af.termService == nil))
	}
	return af.termService
}

func (af *AcademicsInfraFactory) AnalyticsService() academicsvc.AnalyticsService {
	if af.analyticsService == nil {
		af.log.Info("🔄 Creating AnalyticsService")
		af.analyticsService = academicsvc.NewAnalyticsService(
			af.AnalyticsRepo(),
			af.postgresClient,
			af.log,
			af.idempotencyStore,
			af.auditService,
		)
		af.log.Info("✅ AnalyticsService created", zap.Bool("is_nil", af.analyticsService == nil))
	}
	return af.analyticsService
}

func (af *AcademicsInfraFactory) AdmissionService() academicsvc.AdmissionService {
	if af.admissionService == nil {
		af.log.Info("🔄 Creating AdmissionService")
		af.admissionService = academicsvc.NewAdmissionService(
			af.AdmissionRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
		)
		af.log.Info("✅ AdmissionService created", zap.Bool("is_nil", af.admissionService == nil))
	}
	return af.admissionService
}

func (af *AcademicsInfraFactory) AssignmentService() academicsvc.AssignmentService {
	if af.assignmentService == nil {
		af.log.Info("🔄 Creating AssignmentService")
		af.assignmentService = academicsvc.NewAssignmentService(
			af.AssignmentRepo(),
			af.TeacherRepo(),
			af.SubjectRepo(),
			af.CourseRepo(),
			af.SectionRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			&eventPublisherAdapter{pub: af.eventPublisher},
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
		af.log.Info("✅ AssignmentService created", zap.Bool("is_nil", af.assignmentService == nil))
	}
	return af.assignmentService
}

func (af *AcademicsInfraFactory) FeeService() academicsvc.FeeService {
	if af.feeService == nil {
		af.log.Info("🔄 Creating FeeService")
		af.feeService = academicsvc.NewFeeService(
			af.FeeRepo(),
			af.StudentRepo(),
			af.AcademicYearRepo(),
			af.CourseRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
		)
		af.log.Info("✅ FeeService created", zap.Bool("is_nil", af.feeService == nil))
	}
	return af.feeService
}

// ================================
// Handler Getters – with logging
// ================================

func (af *AcademicsInfraFactory) AcademicYearHandler() *handler.AcademicYearHandler {
	if af.academicYearHandler == nil {
		af.log.Info("🔄 Creating AcademicYearHandler")
		af.academicYearHandler = handler.NewAcademicYearHandler(af.AcademicYearService(), af.log)
		af.log.Info("✅ AcademicYearHandler created", zap.Bool("is_nil", af.academicYearHandler == nil))
	}
	return af.academicYearHandler
}

func (af *AcademicsInfraFactory) SectionHandler() *handler.SectionHandler {
	if af.sectionHandler == nil {
		af.log.Info("🔄 Creating SectionHandler")
		af.sectionHandler = handler.NewSectionHandler(af.SectionService(), af.log)
		af.log.Info("✅ SectionHandler created", zap.Bool("is_nil", af.sectionHandler == nil))
	}
	return af.sectionHandler
}

func (af *AcademicsInfraFactory) EnrollmentHandler() *handler.EnrollmentHandler {
	if af.enrollmentHandler == nil {
		af.log.Info("🔄 Creating EnrollmentHandler")
		af.enrollmentHandler = handler.NewEnrollmentHandler(af.EnrollmentService(), af.log)
		af.log.Info("✅ EnrollmentHandler created", zap.Bool("is_nil", af.enrollmentHandler == nil))
	}
	return af.enrollmentHandler
}

func (af *AcademicsInfraFactory) GuardianHandler() *handler.GuardianHandler {
	if af.guardianHandler == nil {
		af.log.Info("🔄 Creating GuardianHandler")
		af.guardianHandler = handler.NewGuardianHandler(af.GuardianService(), af.log)
		af.log.Info("✅ GuardianHandler created", zap.Bool("is_nil", af.guardianHandler == nil))
	}
	return af.guardianHandler
}

func (af *AcademicsInfraFactory) ExamHandler() *handler.ExamHandler {
	if af.examHandler == nil {
		af.log.Info("🔄 Creating ExamHandler")
		af.examHandler = handler.NewExamHandler(af.ExamService(), af.log)
		af.log.Info("✅ ExamHandler created", zap.Bool("is_nil", af.examHandler == nil))
	}
	return af.examHandler
}

func (af *AcademicsInfraFactory) NotificationHandler() *handler.NotificationHandler {
	if af.notificationHandler == nil {
		af.log.Info("🔄 Creating NotificationHandler")
		af.notificationHandler = handler.NewNotificationHandler(af.NotificationService(), af.log)
		af.log.Info("✅ NotificationHandler created", zap.Bool("is_nil", af.notificationHandler == nil))
	}
	return af.notificationHandler
}

func (af *AcademicsInfraFactory) SubmissionHandler() *handler.SubmissionHandler {
	if af.submissionHandler == nil {
		af.log.Info("🔄 Creating SubmissionHandler")
		af.submissionHandler = handler.NewSubmissionHandler(af.SubmissionService(), af.log)
		af.log.Info("✅ SubmissionHandler created", zap.Bool("is_nil", af.submissionHandler == nil))
	}
	return af.submissionHandler
}

func (af *AcademicsInfraFactory) TeacherHandler() *handler.TeacherHandler {
	if af.teacherHandler == nil {
		af.log.Info("🔄 Creating TeacherHandler")
		af.teacherHandler = handler.NewTeacherHandler(af.TeacherService(), af.log)
		af.log.Info("✅ TeacherHandler created", zap.Bool("is_nil", af.teacherHandler == nil))
	}
	return af.teacherHandler
}

func (af *AcademicsInfraFactory) TransportHandler() *handler.TransportHandler {
	if af.transportHandler == nil {
		af.log.Info("🔄 Creating TransportHandler")
		af.transportHandler = handler.NewTransportHandler(af.TransportService(), af.log)
		af.log.Info("✅ TransportHandler created", zap.Bool("is_nil", af.transportHandler == nil))
	}
	return af.transportHandler
}

func (af *AcademicsInfraFactory) GradingHandler() *handler.GradingHandler {
	if af.gradingHandler == nil {
		af.log.Info("🔄 Creating GradingHandler")
		af.gradingHandler = handler.NewGradingHandler(af.GradingService(), af.log)
		af.log.Info("✅ GradingHandler created", zap.Bool("is_nil", af.gradingHandler == nil))
	}
	return af.gradingHandler
}

func (af *AcademicsInfraFactory) CourseHandler() *handler.CourseHandler {
	if af.courseHandler == nil {
		af.log.Info("🔄 Creating CourseHandler")
		af.courseHandler = handler.NewCourseHandler(af.CourseService(), af.log)
		af.log.Info("✅ CourseHandler created", zap.Bool("is_nil", af.courseHandler == nil))
	}
	return af.courseHandler
}

func (af *AcademicsInfraFactory) TimetableHandler() *handler.TimetableHandler {
	if af.timetableHandler == nil {
		af.log.Info("🔄 Creating TimetableHandler")
		af.timetableHandler = handler.NewTimetableHandler(af.TimetableService(), af.log)
		af.log.Info("✅ TimetableHandler created", zap.Bool("is_nil", af.timetableHandler == nil))
	}
	return af.timetableHandler
}

func (af *AcademicsInfraFactory) LibraryHandler() *handler.LibraryHandler {
	if af.libraryHandler == nil {
		af.log.Info("🔄 Creating LibraryHandler")
		af.libraryHandler = handler.NewLibraryHandler(af.LibraryService(), af.log)
		af.log.Info("✅ LibraryHandler created", zap.Bool("is_nil", af.libraryHandler == nil))
	}
	return af.libraryHandler
}

func (af *AcademicsInfraFactory) StudentHandler() *handler.StudentHandler {
	if af.studentHandler == nil {
		af.log.Info("🔄 Creating StudentHandler")
		af.studentHandler = handler.NewStudentHandler(
			af.StudentService(),
			af.StudentAuthService(),
			af.sessionService,
			af.log,
		)
		af.log.Info("✅ StudentHandler created", zap.Bool("is_nil", af.studentHandler == nil))
	}
	return af.studentHandler
}

// ================================
// Session Generation – with extensive logging
// ================================

func (af *AcademicsInfraFactory) SessionGenerationService() academicsvc.SessionGenerationService {
	if af.sessionGenerationService == nil {
		af.log.Info("🔄 Creating SessionGenerationService")
		timetableSvc := af.TimetableService()
		if timetableSvc == nil {
			af.log.Error("❌ TimetableService is nil – cannot create SessionGenerationService")
			panic("TimetableService is nil – check academicSessionRepo initialisation")
		}
		af.sessionGenerationService = academicsvc.NewSessionGenerationService(
			timetableSvc,
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
			af.postgresClient,
			af.log,
		)
		af.log.Info("✅ SessionGenerationService created",
			zap.Bool("is_nil", af.sessionGenerationService == nil),
			zap.String("type", fmt.Sprintf("%T", af.sessionGenerationService)),
		)
	}
	return af.sessionGenerationService
}

func (af *AcademicsInfraFactory) SessionGenerationHandler() *handler.SessionGenerationHandler {
	if af.sessionGenerationHandler == nil {
		af.log.Info("🔄 Creating SessionGenerationHandler")
		svc := af.SessionGenerationService()
		if svc == nil {
			af.log.Error("❌ SessionGenerationService returned nil – handler cannot be created")
			panic("SessionGenerationService is nil – check all dependencies")
		}
		af.sessionGenerationHandler = handler.NewSessionGenerationHandler(svc, af.log)
		af.log.Info("✅ SessionGenerationHandler created",
			zap.Bool("is_nil", af.sessionGenerationHandler == nil),
			zap.String("address", fmt.Sprintf("%p", af.sessionGenerationHandler)),
		)
	}
	return af.sessionGenerationHandler
}

// ================================
// Other Handlers
// ================================

func (af *AcademicsInfraFactory) RoomHandler() *handler.RoomHandler {
	if af.roomHandler == nil {
		af.log.Info("🔄 Creating RoomHandler")
		af.roomHandler = handler.NewRoomHandler(af.RoomService(), af.log)
		af.log.Info("✅ RoomHandler created", zap.Bool("is_nil", af.roomHandler == nil))
	}
	return af.roomHandler
}

func (af *AcademicsInfraFactory) SubjectHandler() *handler.SubjectHandler {
	if af.subjectHandler == nil {
		af.log.Info("🔄 Creating SubjectHandler")
		af.subjectHandler = handler.NewSubjectHandler(af.SubjectService(), af.log)
		af.log.Info("✅ SubjectHandler created", zap.Bool("is_nil", af.subjectHandler == nil))
	}
	return af.subjectHandler
}

func (af *AcademicsInfraFactory) FeeHandler() *handler.FeeHandler {
	if af.feeHandler == nil {
		af.log.Info("🔄 Creating FeeHandler")
		af.feeHandler = handler.NewFeeHandler(af.FeeService(), af.log)
		af.log.Info("✅ FeeHandler created", zap.Bool("is_nil", af.feeHandler == nil))
	}
	return af.feeHandler
}

func (af *AcademicsInfraFactory) AssignmentHandler() *handler.AssignmentHandler {
	if af.assignmentHandler == nil {
		af.log.Info("🔄 Creating AssignmentHandler")
		af.assignmentHandler = handler.NewAssignmentHandler(af.AssignmentService(), af.log)
		af.log.Info("✅ AssignmentHandler created", zap.Bool("is_nil", af.assignmentHandler == nil))
	}
	return af.assignmentHandler
}

func (af *AcademicsInfraFactory) AdmissionHandler() *handler.AdmissionHandler {
	if af.admissionHandler == nil {
		af.log.Info("🔄 Creating AdmissionHandler")
		af.admissionHandler = handler.NewAdmissionHandler(af.AdmissionService(), af.log)
		af.log.Info("✅ AdmissionHandler created", zap.Bool("is_nil", af.admissionHandler == nil))
	}
	return af.admissionHandler
}

func (af *AcademicsInfraFactory) TermHandler() *handler.TermHandler {
	if af.termHandler == nil {
		af.log.Info("🔄 Creating TermHandler")
		af.termHandler = handler.NewTermHandler(af.TermService(), af.log)
		af.log.Info("✅ TermHandler created", zap.Bool("is_nil", af.termHandler == nil))
	}
	return af.termHandler
}

func (af *AcademicsInfraFactory) AnalyticsHandler() *handler.AnalyticsHandler {
	if af.analyticsHandler == nil {
		af.log.Info("🔄 Creating AnalyticsHandler")
		af.analyticsHandler = handler.NewAnalyticsHandler(af.AnalyticsService(), af.log)
		af.log.Info("✅ AnalyticsHandler created", zap.Bool("is_nil", af.analyticsHandler == nil))
	}
	return af.analyticsHandler
}

func (af *AcademicsInfraFactory) CurriculumHandler() *handler.CurriculumHandler {
	if af.curriculumHandler == nil {
		af.log.Info("🔄 Creating CurriculumHandler")
		af.curriculumHandler = handler.NewCurriculumHandler(af.CurriculumService(), af.log)
		af.log.Info("✅ CurriculumHandler created", zap.Bool("is_nil", af.curriculumHandler == nil))
	}
	return af.curriculumHandler
}

// ================================
// Routes Registration
// ================================

func (af *AcademicsInfraFactory) RegisterRoutes(r chi.Router, jwtService *mainservice.JWTService, logger *zap.Logger) {
	af.log.Info("📌 Registering academic routes")

	// Get the session generation handler specifically for logging
	sessGenHandler := af.SessionGenerationHandler()
	af.log.Info("🔍 SessionGenerationHandler before registration",
		zap.Bool("is_nil", sessGenHandler == nil),
		zap.String("address", fmt.Sprintf("%p", sessGenHandler)),
	)

	academics.RegisterAcademicRoutes(
		r,
		af.AcademicYearHandler(),
		af.AdmissionHandler(),
		af.AnalyticsHandler(),
		af.AssignmentHandler(),
		af.CourseHandler(),
		af.CurriculumHandler(),
		af.EnrollmentHandler(),
		af.ExamHandler(),
		af.FeeHandler(),
		af.GradingHandler(),
		af.GuardianHandler(),
		af.LibraryHandler(),
		af.NotificationHandler(),
		af.RoomHandler(),
		af.SectionHandler(),
		af.StudentHandler(),
		af.SubjectHandler(),
		af.SubmissionHandler(),
		af.TeacherHandler(),
		af.TermHandler(),
		af.TimetableHandler(),
		af.TransportHandler(),
		sessGenHandler,
		logger,
	)
	af.log.Info("✅ Academic routes registered")
}

// Close is a no‑op because the outbox processor is managed centrally
func (af *AcademicsInfraFactory) Close() {
	// No longer needed – central outbox handles shutdown
}
