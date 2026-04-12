package factory

import (
	"context"
	"database/sql"
	"encoding/json"
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
// Interface adapters (retained for compatibility, but only EventPublisher adapter is used)
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
	attendanceRepo           repository.AttendanceRepository
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
	idempotencyStore         idempotency.Store
	outboxRepo               outbox.Repository
	academicsOutboxProcessor *outbox.Processor
	academicsOutboxCancel    context.CancelFunc

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
	attendanceService   academicsvc.AttendanceService
	assignmentService   academicsvc.AssignmentService
	feeService          academicsvc.FeeService

	// Handlers
	academicYearHandler *handler.AcademicYearHandler
	sectionHandler      *handler.SectionHandler
	enrollmentHandler   *handler.EnrollmentHandler
	guardianHandler     *handler.GuardianHandler
	examHandler         *handler.ExamHandler
	notificationHandler *handler.NotificationHandler
	submissionHandler   *handler.SubmissionHandler
	teacherHandler      *handler.TeacherHandler
	transportHandler    *handler.TransportHandler
	gradingHandler      *handler.GradingHandler
	courseHandler       *handler.CourseHandler
	timetableHandler    *handler.TimetableHandler
	libraryHandler      *handler.LibraryHandler
	studentHandler      *handler.StudentHandler
	roomHandler         *handler.RoomHandler
	subjectHandler      *handler.SubjectHandler
	feeHandler          *handler.FeeHandler
	assignmentHandler   *handler.AssignmentHandler
	attendanceHandler   *handler.AttendanceHandler
	admissionHandler    *handler.AdmissionHandler
	termHandler         *handler.TermHandler
	analyticsHandler    *handler.AnalyticsHandler
	curriculumHandler   *handler.CurriculumHandler
}

// NewAcademicsInfraFactory constructor
func NewAcademicsInfraFactory(
	postgresClient *client.PostgresClient,
	redisClient *client.RedisClient,
	kafkaProducer *client.KafkaProducer,
	encryptionManager *encryption.EncryptionManager,
	eventPublisher EventPublisher,
	auditService *audit.AuditService,
	emailSender email.Sender,
	sessionService *mainservice.SessionService,
	logger *zap.Logger,
) (*AcademicsInfraFactory, error) {
	af := &AcademicsInfraFactory{
		log:            logger.Named("academics_infra"),
		postgresClient: postgresClient,
		eventPublisher: eventPublisher,
		auditService:   auditService,
		emailSender:    emailSender,
		sessionService: sessionService,
	}

	// Idempotency store
	pgStore := idempotency.NewPostgresStore(postgresClient.DB)
	redisCache := idempotency.NewRedisCache(redisClient, 24*time.Hour)
	af.idempotencyStore = idempotency.NewHybridStore(pgStore, redisCache)

	// Repositories
	af.academicEventRepo = repository.NewAcademicEventRepository(af.log)
	af.academicYearRepo = repository.NewAcademicYearRepository(af.log)
	af.admissionRepo = repository.NewAdmissionRepository(af.log)
	af.analyticsRepo = repository.NewAnalyticsRepository(af.log)
	af.assignmentRepo = repository.NewAssignmentRepository(af.log)
	af.attendanceRepo = repository.NewAttendanceRepository(af.log)
	af.courseRepo = repository.NewCourseRepository(af.log)
	af.enrollmentRepo = repository.NewEnrollmentRepository(af.log)
	af.examRepo = repository.NewExamRepository(af.log)
	af.feeRepo = repository.NewFeeRepository(af.log)
	af.gradingRepo = repository.NewGradingRepository(af.log)
	af.guardianRepo = repository.NewGuardianRepository(af.log, encryptionManager)
	af.libraryRepo = repository.NewLibraryRepository(af.log)
	af.notificationRepo = repository.NewNotificationRepository(af.log)
	af.roomRepo = repository.NewRoomRepository(af.log)
	af.sectionRepo = repository.NewSectionRepository(af.log)
	af.studentAuthRepo = repository.NewStudentAuthRepository(af.log, encryptionManager)
	af.studentRepo = repository.NewStudentRepository(af.log, encryptionManager)
	af.subjectCourseMappingRepo = repository.NewSubjectCourseMappingRepository(af.log)
	af.subjectRepo = repository.NewSubjectRepository(af.log)
	af.submissionRepo = repository.NewSubmissionRepository(af.log)
	af.teacherRepo = repository.NewTeacherRepository(af.log)
	af.termRepo = repository.NewTermRepository(af.log)
	af.timetableRepo = repository.NewTimetableRepository(af.log)
	af.transportRepo = repository.NewTransportRepository(af.log)

	// Outbox
	if kafkaProducer != nil {
		af.outboxRepo = outbox.NewPostgresRepository(postgresClient.DB)
		af.academicsOutboxProcessor = outbox.NewProcessor(
			af.outboxRepo, kafkaProducer, af.log, "academics-events",
		)
		ctx, cancel := context.WithCancel(context.Background())
		af.academicsOutboxCancel = cancel
		go af.academicsOutboxProcessor.Start(ctx)
		af.log.Info("Academics outbox processor started")
	} else {
		af.log.Warn("Kafka producer not available – outbox will be nil")
	}

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
func (af *AcademicsInfraFactory) AttendanceRepo() repository.AttendanceRepository {
	return af.attendanceRepo
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
// Service Getters (all corrected)
// ================================

func (af *AcademicsInfraFactory) NotificationService() academicsvc.NotificationService {
	if af.notificationService == nil {
		af.notificationService = academicsvc.NewNotificationService(
			af.NotificationRepo(),
			af.postgresClient,
			af.log,
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
	}
	return af.notificationService
}

func (af *AcademicsInfraFactory) ExamService() academicsvc.ExamService {
	if af.examService == nil {
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
	}
	return af.examService
}

func (af *AcademicsInfraFactory) StudentAuthService() academicsvc.StudentAuthService {
	if af.studentAuthService == nil {
		af.studentAuthService = academicsvc.NewStudentAuthService(
			af.StudentRepo(),
			af.StudentAuthRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
		)
	}
	return af.studentAuthService
}

func (af *AcademicsInfraFactory) GuardianService() academicsvc.GuardianService {
	if af.guardianService == nil {
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
	}
	return af.guardianService
}

func (af *AcademicsInfraFactory) EnrollmentService() academicsvc.EnrollmentService {
	if af.enrollmentService == nil {
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
			&eventPublisherAdapter{pub: af.eventPublisher}, // EventPublisher
		)
	}
	return af.enrollmentService
}

func (af *AcademicsInfraFactory) SectionService() academicsvc.SectionService {
	if af.sectionService == nil {
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
	}
	return af.sectionService
}

func (af *AcademicsInfraFactory) AcademicYearService() academicsvc.AcademicYearService {
	if af.academicYearService == nil {
		af.academicYearService = academicsvc.NewAcademicYearService(
			af.AcademicYearRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
		)
	}
	return af.academicYearService
}

func (af *AcademicsInfraFactory) GradingService() academicsvc.GradingService {
	if af.gradingService == nil {
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
	}
	return af.gradingService
}

func (af *AcademicsInfraFactory) TransportService() academicsvc.TransportService {
	if af.transportService == nil {
		af.transportService = academicsvc.NewTransportService(
			af.TransportRepo(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
			af.postgresClient,
			af.log,
			af.NotificationService(),
		)
	}
	return af.transportService
}

func (af *AcademicsInfraFactory) TeacherService() academicsvc.TeacherService {
	if af.teacherService == nil {
		af.teacherService = academicsvc.NewTeacherService(
			af.TeacherRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
	}
	return af.teacherService
}

func (af *AcademicsInfraFactory) SubmissionService() academicsvc.SubmissionService {
	if af.submissionService == nil {
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
	}
	return af.submissionService
}

func (af *AcademicsInfraFactory) CurriculumService() academicsvc.CurriculumService {
	if af.curriculumService == nil {
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
	}
	return af.curriculumService
}

func (af *AcademicsInfraFactory) SubjectService() academicsvc.SubjectService {
	if af.subjectService == nil {
		af.subjectService = academicsvc.NewSubjectService(
			af.SubjectRepo(),
			af.postgresClient,
			af.log,
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
	}
	return af.subjectService
}

func (af *AcademicsInfraFactory) StudentService() academicsvc.StudentService {
	if af.studentService == nil {
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
	}
	return af.studentService
}

func (af *AcademicsInfraFactory) LibraryService() academicsvc.LibraryService {
	if af.libraryService == nil {
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
	}
	return af.libraryService
}

func (af *AcademicsInfraFactory) RoomService() academicsvc.RoomService {
	if af.roomService == nil {
		af.roomService = academicsvc.NewRoomService(
			af.RoomRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
	}
	return af.roomService
}

func (af *AcademicsInfraFactory) TimetableService() academicsvc.TimetableService {
	if af.timetableService == nil {
		af.timetableService = academicsvc.NewTimetableService(
			af.TimetableRepo(),
			af.SectionRepo(),
			af.CourseRepo(), // ✅ Added CourseRepository
			af.SubjectRepo(),
			af.TeacherRepo(),
			af.RoomRepo(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
			af.postgresClient,
			af.log,
			af.NotificationService(),
		)
	}
	return af.timetableService
}
func (af *AcademicsInfraFactory) CourseService() academicsvc.CourseService {
	if af.courseService == nil {
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
	}
	return af.courseService
}

func (af *AcademicsInfraFactory) TermService() academicsvc.TermService {
	if af.termService == nil {
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
	}
	return af.termService
}

func (af *AcademicsInfraFactory) AnalyticsService() academicsvc.AnalyticsService {
	if af.analyticsService == nil {
		af.analyticsService = academicsvc.NewAnalyticsService(
			af.AnalyticsRepo(),
			af.postgresClient,
			af.log,
			af.idempotencyStore,
			af.auditService,
		)
	}
	return af.analyticsService
}

func (af *AcademicsInfraFactory) AdmissionService() academicsvc.AdmissionService {
	if af.admissionService == nil {
		af.admissionService = academicsvc.NewAdmissionService(
			af.AdmissionRepo(),
			af.postgresClient,
			af.log,
			af.outboxRepo,
			af.idempotencyStore,
			af.auditService,
			af.NotificationService(),
		)
	}
	return af.admissionService
}

func (af *AcademicsInfraFactory) AttendanceService() academicsvc.AttendanceService {
	if af.attendanceService == nil {
		af.attendanceService = academicsvc.NewAttendanceService(
			af.AttendanceRepo(),
			af.EnrollmentRepo(),
			af.StudentRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
	}
	return af.attendanceService
}

func (af *AcademicsInfraFactory) AssignmentService() academicsvc.AssignmentService {
	if af.assignmentService == nil {
		af.assignmentService = academicsvc.NewAssignmentService(
			af.AssignmentRepo(),
			af.TeacherRepo(),
			af.SubjectRepo(),
			af.CourseRepo(),
			af.SectionRepo(),
			af.postgresClient,
			af.log,
			af.NotificationService(),
			&eventPublisherAdapter{pub: af.eventPublisher}, // EventPublisher
			af.idempotencyStore,
			af.auditService,
			af.outboxRepo,
		)
	}
	return af.assignmentService
}

func (af *AcademicsInfraFactory) FeeService() academicsvc.FeeService {
	if af.feeService == nil {
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
	}
	return af.feeService
}

// ================================
// Handler Getters (unchanged)
// ================================

func (af *AcademicsInfraFactory) AcademicYearHandler() *handler.AcademicYearHandler {
	if af.academicYearHandler == nil {
		af.academicYearHandler = handler.NewAcademicYearHandler(af.AcademicYearService(), af.log)
	}
	return af.academicYearHandler
}

func (af *AcademicsInfraFactory) SectionHandler() *handler.SectionHandler {
	if af.sectionHandler == nil {
		af.sectionHandler = handler.NewSectionHandler(af.SectionService(), af.log)
	}
	return af.sectionHandler
}

func (af *AcademicsInfraFactory) EnrollmentHandler() *handler.EnrollmentHandler {
	if af.enrollmentHandler == nil {
		af.enrollmentHandler = handler.NewEnrollmentHandler(af.EnrollmentService(), af.log)
	}
	return af.enrollmentHandler
}

func (af *AcademicsInfraFactory) GuardianHandler() *handler.GuardianHandler {
	if af.guardianHandler == nil {
		af.guardianHandler = handler.NewGuardianHandler(af.GuardianService(), af.log)
	}
	return af.guardianHandler
}

func (af *AcademicsInfraFactory) ExamHandler() *handler.ExamHandler {
	if af.examHandler == nil {
		af.examHandler = handler.NewExamHandler(af.ExamService(), af.log)
	}
	return af.examHandler
}

func (af *AcademicsInfraFactory) NotificationHandler() *handler.NotificationHandler {
	if af.notificationHandler == nil {
		af.notificationHandler = handler.NewNotificationHandler(af.NotificationService(), af.log)
	}
	return af.notificationHandler
}

func (af *AcademicsInfraFactory) SubmissionHandler() *handler.SubmissionHandler {
	if af.submissionHandler == nil {
		af.submissionHandler = handler.NewSubmissionHandler(af.SubmissionService(), af.log)
	}
	return af.submissionHandler
}

func (af *AcademicsInfraFactory) TeacherHandler() *handler.TeacherHandler {
	if af.teacherHandler == nil {
		af.teacherHandler = handler.NewTeacherHandler(af.TeacherService(), af.log)
	}
	return af.teacherHandler
}

func (af *AcademicsInfraFactory) TransportHandler() *handler.TransportHandler {
	if af.transportHandler == nil {
		af.transportHandler = handler.NewTransportHandler(af.TransportService(), af.log)
	}
	return af.transportHandler
}

func (af *AcademicsInfraFactory) GradingHandler() *handler.GradingHandler {
	if af.gradingHandler == nil {
		af.gradingHandler = handler.NewGradingHandler(af.GradingService(), af.log)
	}
	return af.gradingHandler
}

func (af *AcademicsInfraFactory) CourseHandler() *handler.CourseHandler {
	if af.courseHandler == nil {
		af.courseHandler = handler.NewCourseHandler(af.CourseService(), af.log)
	}
	return af.courseHandler
}

func (af *AcademicsInfraFactory) TimetableHandler() *handler.TimetableHandler {
	if af.timetableHandler == nil {
		af.timetableHandler = handler.NewTimetableHandler(af.TimetableService(), af.log)
	}
	return af.timetableHandler
}

func (af *AcademicsInfraFactory) LibraryHandler() *handler.LibraryHandler {
	if af.libraryHandler == nil {
		af.libraryHandler = handler.NewLibraryHandler(af.LibraryService(), af.log)
	}
	return af.libraryHandler
}

func (af *AcademicsInfraFactory) StudentHandler() *handler.StudentHandler {
	if af.studentHandler == nil {
		af.studentHandler = handler.NewStudentHandler(
			af.StudentService(),
			af.StudentAuthService(),
			af.sessionService,
			af.log,
		)
	}
	return af.studentHandler
}

func (af *AcademicsInfraFactory) RoomHandler() *handler.RoomHandler {
	if af.roomHandler == nil {
		af.roomHandler = handler.NewRoomHandler(af.RoomService(), af.log)
	}
	return af.roomHandler
}

func (af *AcademicsInfraFactory) SubjectHandler() *handler.SubjectHandler {
	if af.subjectHandler == nil {
		af.subjectHandler = handler.NewSubjectHandler(af.SubjectService(), af.log)
	}
	return af.subjectHandler
}

func (af *AcademicsInfraFactory) FeeHandler() *handler.FeeHandler {
	if af.feeHandler == nil {
		af.feeHandler = handler.NewFeeHandler(af.FeeService(), af.log)
	}
	return af.feeHandler
}

func (af *AcademicsInfraFactory) AssignmentHandler() *handler.AssignmentHandler {
	if af.assignmentHandler == nil {
		af.assignmentHandler = handler.NewAssignmentHandler(af.AssignmentService(), af.log)
	}
	return af.assignmentHandler
}

func (af *AcademicsInfraFactory) AttendanceHandler() *handler.AttendanceHandler {
	if af.attendanceHandler == nil {
		af.attendanceHandler = handler.NewAttendanceHandler(af.AttendanceService(), af.log)
	}
	return af.attendanceHandler
}

func (af *AcademicsInfraFactory) AdmissionHandler() *handler.AdmissionHandler {
	if af.admissionHandler == nil {
		af.admissionHandler = handler.NewAdmissionHandler(af.AdmissionService(), af.log)
	}
	return af.admissionHandler
}

func (af *AcademicsInfraFactory) TermHandler() *handler.TermHandler {
	if af.termHandler == nil {
		af.termHandler = handler.NewTermHandler(af.TermService(), af.log)
	}
	return af.termHandler
}

func (af *AcademicsInfraFactory) AnalyticsHandler() *handler.AnalyticsHandler {
	if af.analyticsHandler == nil {
		af.analyticsHandler = handler.NewAnalyticsHandler(af.AnalyticsService(), af.log)
	}
	return af.analyticsHandler
}

func (af *AcademicsInfraFactory) CurriculumHandler() *handler.CurriculumHandler {
	if af.curriculumHandler == nil {
		af.curriculumHandler = handler.NewCurriculumHandler(af.CurriculumService(), af.log)
	}
	return af.curriculumHandler
}

// ================================
// Routes Registration
// ================================

func (af *AcademicsInfraFactory) RegisterRoutes(r chi.Router, jwtService *mainservice.JWTService, logger *zap.Logger) {
	academics.RegisterAcademicRoutes(
		r,
		af.AcademicYearHandler(),
		af.AdmissionHandler(),
		af.AnalyticsHandler(),
		af.AssignmentHandler(),
		af.AttendanceHandler(),
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
		logger,
		jwtService,
		af.StudentHandler(),
		af.SubjectHandler(),
		af.SubmissionHandler(),
		af.TeacherHandler(),
		af.TermHandler(),
		af.TimetableHandler(),
		af.TransportHandler(),
	)
}

// Close shuts down the outbox processor
func (af *AcademicsInfraFactory) Close() {
	if af.academicsOutboxCancel != nil {
		af.academicsOutboxCancel()
	}
}
