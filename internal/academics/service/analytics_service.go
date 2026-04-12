package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

// AnalyticsService defines all analytics operations.
type AnalyticsService interface {
	// Academic year metrics (existing)
	GetAcademicYearMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.AcademicYearMetrics, error)
	ListAcademicYearMetrics(ctx context.Context, limit, offset int) ([]*models.AcademicYearMetrics, error)
	RefreshAcademicYearMetrics(ctx context.Context, academicYearID uuid.UUID) error
	RefreshAllAcademicYearMetrics(ctx context.Context) error

	// New read operations for domain‑specific metrics
	GetExamMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.ExamMetrics, error)
	ListExamMetrics(ctx context.Context, limit, offset int) ([]*models.ExamMetrics, error)
	GetFeeMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.FeeMetrics, error)
	ListFeeMetrics(ctx context.Context, limit, offset int) ([]*models.FeeMetrics, error)
	GetGradingMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.GradingMetrics, error)
	ListGradingMetrics(ctx context.Context, limit, offset int) ([]*models.GradingMetrics, error)
	GetGuardianMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.GuardianMetrics, error)
	ListGuardianMetrics(ctx context.Context, limit, offset int) ([]*models.GuardianMetrics, error)
	GetLibraryMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.LibraryMetrics, error)
	ListLibraryMetrics(ctx context.Context, limit, offset int) ([]*models.LibraryMetrics, error)

	// Existing incremental processors
	ProcessAdmissionCreated(ctx context.Context, payload []byte) error
	ProcessAdmissionStatusUpdated(ctx context.Context, payload []byte) error
	ProcessTermCreated(ctx context.Context, payload []byte) error
	ProcessAssignmentCreated(ctx context.Context, payload []byte) error
	ProcessAssignmentUpdated(ctx context.Context, payload []byte) error
	ProcessAssignmentDeleted(ctx context.Context, payload []byte) error
	ProcessAssignmentPublished(ctx context.Context, payload []byte) error
	ProcessAttendanceMarked(ctx context.Context, payload []byte) error
	ProcessAttendanceBulkMarked(ctx context.Context, payload []byte) error
	ProcessAttendanceExemptionCreated(ctx context.Context, payload []byte) error
	ProcessAttendanceExemptionDeleted(ctx context.Context, payload []byte) error
	ProcessSubjectAssigned(ctx context.Context, payload []byte) error
	ProcessSubjectUnassigned(ctx context.Context, payload []byte) error
	ProcessEnrollmentCreated(ctx context.Context, payload []byte) error
	ProcessEnrollmentUpdated(ctx context.Context, payload []byte) error
	ProcessEnrollmentDeleted(ctx context.Context, payload []byte) error

	// New processors for Exam domain
	ProcessExamCreated(ctx context.Context, payload []byte) error
	ProcessExamUpdated(ctx context.Context, payload []byte) error
	ProcessExamDeleted(ctx context.Context, payload []byte) error
	ProcessExamScheduleCreated(ctx context.Context, payload []byte) error
	ProcessExamScheduleDeleted(ctx context.Context, payload []byte) error
	ProcessExamResultCreated(ctx context.Context, payload []byte) error
	ProcessExamResultDeleted(ctx context.Context, payload []byte) error
	ProcessExamGradeCreated(ctx context.Context, payload []byte) error
	ProcessExamGradeDeleted(ctx context.Context, payload []byte) error

	// New processors for Fee domain
	ProcessFeeStructureCreated(ctx context.Context, payload []byte) error
	ProcessFeeStructureUpdated(ctx context.Context, payload []byte) error
	ProcessFeeStructureDeleted(ctx context.Context, payload []byte) error
	ProcessFeeInvoiceCreated(ctx context.Context, payload []byte) error
	ProcessFeePaymentCreated(ctx context.Context, payload []byte) error
	ProcessFeeDiscountCreated(ctx context.Context, payload []byte) error
	ProcessFeeDiscountUpdated(ctx context.Context, payload []byte) error
	ProcessFeeDiscountDeleted(ctx context.Context, payload []byte) error
	ProcessFeePenaltyCreated(ctx context.Context, payload []byte) error
	ProcessFeePenaltyUpdated(ctx context.Context, payload []byte) error
	ProcessFeeReceiptGenerated(ctx context.Context, payload []byte) error

	// New processors for Grading domain
	ProcessGradingPolicyCreated(ctx context.Context, payload []byte) error
	ProcessGradingPolicyDeleted(ctx context.Context, payload []byte) error
	ProcessGradeBoundaryCreated(ctx context.Context, payload []byte) error
	ProcessGradeBoundaryDeleted(ctx context.Context, payload []byte) error

	// New processors for Guardian domain
	ProcessGuardianCreated(ctx context.Context, payload []byte) error
	ProcessGuardianUpdated(ctx context.Context, payload []byte) error
	ProcessGuardianDeleted(ctx context.Context, payload []byte) error
	ProcessGuardianPrimarySet(ctx context.Context, payload []byte) error

	// New processors for Library domain
	ProcessLibraryCategoryCreated(ctx context.Context, payload []byte) error
	ProcessLibraryCategoryDeleted(ctx context.Context, payload []byte) error
	ProcessLibraryBookCreated(ctx context.Context, payload []byte) error
	ProcessLibraryBookDeleted(ctx context.Context, payload []byte) error
	ProcessLibraryCopyCreated(ctx context.Context, payload []byte) error
	ProcessLibraryCopyDeleted(ctx context.Context, payload []byte) error
	ProcessLibraryBookIssued(ctx context.Context, payload []byte) error
	ProcessLibraryBookReturned(ctx context.Context, payload []byte) error
	ProcessLibraryFineCreated(ctx context.Context, payload []byte) error
	ProcessLibraryFinePaid(ctx context.Context, payload []byte) error

	// ===================== New interface methods =====================
	// Add these to the existing AnalyticsService interface

	// Room
	GetRoomMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.RoomMetrics, error)
	ListRoomMetrics(ctx context.Context, limit, offset int) ([]*models.RoomMetrics, error)
	RefreshRoomMetrics(ctx context.Context, academicYearID uuid.UUID) error
	ProcessRoomCreated(ctx context.Context, payload []byte) error
	ProcessRoomUpdated(ctx context.Context, payload []byte) error
	ProcessRoomActivated(ctx context.Context, payload []byte) error
	ProcessRoomDeactivated(ctx context.Context, payload []byte) error
	ProcessRoomDeleted(ctx context.Context, payload []byte) error

	// Section
	GetSectionMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.SectionMetrics, error)
	ListSectionMetrics(ctx context.Context, limit, offset int) ([]*models.SectionMetrics, error)
	RefreshSectionMetrics(ctx context.Context, academicYearID uuid.UUID) error
	ProcessSectionCreated(ctx context.Context, payload []byte) error
	ProcessSectionUpdated(ctx context.Context, payload []byte) error
	ProcessSectionActivated(ctx context.Context, payload []byte) error
	ProcessSectionDeactivated(ctx context.Context, payload []byte) error
	ProcessSectionDeleted(ctx context.Context, payload []byte) error

	// Student
	GetStudentMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.StudentMetrics, error)
	ListStudentMetrics(ctx context.Context, limit, offset int) ([]*models.StudentMetrics, error)
	RefreshStudentMetrics(ctx context.Context, academicYearID uuid.UUID) error
	ProcessStudentCreated(ctx context.Context, payload []byte) error
	ProcessStudentUpdated(ctx context.Context, payload []byte) error
	ProcessStudentActivated(ctx context.Context, payload []byte) error
	ProcessStudentDeactivated(ctx context.Context, payload []byte) error
	ProcessStudentDeleted(ctx context.Context, payload []byte) error

	// Subject
	GetSubjectMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.SubjectMetrics, error)
	ListSubjectMetrics(ctx context.Context, limit, offset int) ([]*models.SubjectMetrics, error)
	RefreshSubjectMetrics(ctx context.Context, academicYearID uuid.UUID) error
	ProcessSubjectCreated(ctx context.Context, payload []byte) error
	ProcessSubjectUpdated(ctx context.Context, payload []byte) error
	ProcessSubjectActivated(ctx context.Context, payload []byte) error
	ProcessSubjectDeactivated(ctx context.Context, payload []byte) error
	ProcessSubjectDeleted(ctx context.Context, payload []byte) error

	// Submission
	GetSubmissionMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.SubmissionMetrics, error)
	ListSubmissionMetrics(ctx context.Context, limit, offset int) ([]*models.SubmissionMetrics, error)
	RefreshSubmissionMetrics(ctx context.Context, academicYearID uuid.UUID) error
	ProcessSubmissionCreated(ctx context.Context, payload []byte) error
	ProcessSubmissionUpdated(ctx context.Context, payload []byte) error
	ProcessSubmissionDeleted(ctx context.Context, payload []byte) error
	ProcessSubmissionGraded(ctx context.Context, payload []byte) error

	// Teacher
	GetTeacherMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.TeacherMetrics, error)
	ListTeacherMetrics(ctx context.Context, limit, offset int) ([]*models.TeacherMetrics, error)
	RefreshTeacherMetrics(ctx context.Context, academicYearID uuid.UUID) error
	ProcessTeacherCreated(ctx context.Context, payload []byte) error
	ProcessTeacherUpdated(ctx context.Context, payload []byte) error
	ProcessTeacherActivated(ctx context.Context, payload []byte) error
	ProcessTeacherDeactivated(ctx context.Context, payload []byte) error
	ProcessTeacherDeleted(ctx context.Context, payload []byte) error

	// Timetable
	GetTimetableMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.TimetableMetrics, error)
	ListTimetableMetrics(ctx context.Context, limit, offset int) ([]*models.TimetableMetrics, error)
	RefreshTimetableMetrics(ctx context.Context, academicYearID uuid.UUID) error
	ProcessTimetableCreated(ctx context.Context, payload []byte) error
	ProcessTimetableUpdated(ctx context.Context, payload []byte) error
	ProcessTimetableDeleted(ctx context.Context, payload []byte) error
	ProcessTimetableSlotAdded(ctx context.Context, payload []byte) error
	ProcessTimetableSlotUpdated(ctx context.Context, payload []byte) error
	ProcessTimetableSlotDeleted(ctx context.Context, payload []byte) error
	ProcessTimetableEntryAdded(ctx context.Context, payload []byte) error
	ProcessTimetableEntryUpdated(ctx context.Context, payload []byte) error
	ProcessTimetableEntryDeleted(ctx context.Context, payload []byte) error
	ProcessTimetableChangeAdded(ctx context.Context, payload []byte) error

	// Transport
	GetTransportMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.TransportMetrics, error)
	ListTransportMetrics(ctx context.Context, limit, offset int) ([]*models.TransportMetrics, error)
	RefreshTransportMetrics(ctx context.Context, academicYearID uuid.UUID) error
	ProcessTransportRouteCreated(ctx context.Context, payload []byte) error
	ProcessTransportRouteUpdated(ctx context.Context, payload []byte) error
	ProcessTransportRouteDeleted(ctx context.Context, payload []byte) error
	ProcessTransportStopCreated(ctx context.Context, payload []byte) error
	ProcessTransportStopUpdated(ctx context.Context, payload []byte) error
	ProcessTransportStopDeleted(ctx context.Context, payload []byte) error
	ProcessTransportVehicleCreated(ctx context.Context, payload []byte) error
	ProcessTransportVehicleUpdated(ctx context.Context, payload []byte) error
	ProcessTransportVehicleDeleted(ctx context.Context, payload []byte) error
	ProcessTransportDriverAssignmentCreated(ctx context.Context, payload []byte) error
	ProcessTransportDriverAssignmentUpdated(ctx context.Context, payload []byte) error
	ProcessTransportDriverAssignmentDeleted(ctx context.Context, payload []byte) error
	ProcessTransportStudentAssignmentCreated(ctx context.Context, payload []byte) error
	ProcessTransportStudentAssignmentUpdated(ctx context.Context, payload []byte) error
	ProcessTransportStudentAssignmentDeleted(ctx context.Context, payload []byte) error
}

type analyticsService struct {
	repo             repository.AnalyticsRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewAnalyticsService(
	repo repository.AnalyticsRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) AnalyticsService {
	return &analyticsService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("analytics_service"),
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// =============================================================================
// Read operations for new metrics
// =============================================================================

// GetExamMetrics returns exam metrics for a given academic year.
func (s *analyticsService) GetExamMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.ExamMetrics, error) {
	var metrics models.ExamMetrics
	query := `SELECT academic_year_id, total_exams, total_schedules, total_results, total_grades, last_updated
	          FROM analytics.exam_metrics WHERE academic_year_id = $1`
	err := s.pgClient.DB.QueryRowContext(ctx, query, academicYearID).Scan(
		&metrics.AcademicYearID, &metrics.TotalExams, &metrics.TotalSchedules,
		&metrics.TotalResults, &metrics.TotalGrades, &metrics.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get exam metrics: %w", err)
	}
	return &metrics, nil
}

// ListExamMetrics returns paginated exam metrics.
func (s *analyticsService) ListExamMetrics(ctx context.Context, limit, offset int) ([]*models.ExamMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_exams, total_schedules, total_results, total_grades, last_updated
	          FROM analytics.exam_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list exam metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.ExamMetrics
	for rows.Next() {
		var m models.ExamMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalExams, &m.TotalSchedules,
			&m.TotalResults, &m.TotalGrades, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

// GetFeeMetrics returns fee metrics for a given academic year.
func (s *analyticsService) GetFeeMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.FeeMetrics, error) {
	var metrics models.FeeMetrics
	query := `SELECT academic_year_id, total_fee_structures, total_invoices, total_payments,
	          total_discounts, total_penalties, total_receipts,
	          total_invoice_amount, total_paid_amount, total_discount_amount, total_penalty_amount,
	          last_updated
	          FROM analytics.fee_metrics WHERE academic_year_id = $1`
	err := s.pgClient.DB.QueryRowContext(ctx, query, academicYearID).Scan(
		&metrics.AcademicYearID, &metrics.TotalFeeStructures, &metrics.TotalInvoices,
		&metrics.TotalPayments, &metrics.TotalDiscounts, &metrics.TotalPenalties,
		&metrics.TotalReceipts, &metrics.TotalInvoiceAmount, &metrics.TotalPaidAmount,
		&metrics.TotalDiscountAmount, &metrics.TotalPenaltyAmount, &metrics.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get fee metrics: %w", err)
	}
	return &metrics, nil
}

// ListFeeMetrics returns paginated fee metrics.
func (s *analyticsService) ListFeeMetrics(ctx context.Context, limit, offset int) ([]*models.FeeMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_fee_structures, total_invoices, total_payments,
	          total_discounts, total_penalties, total_receipts,
	          total_invoice_amount, total_paid_amount, total_discount_amount, total_penalty_amount,
	          last_updated
	          FROM analytics.fee_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list fee metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.FeeMetrics
	for rows.Next() {
		var m models.FeeMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalFeeStructures, &m.TotalInvoices,
			&m.TotalPayments, &m.TotalDiscounts, &m.TotalPenalties, &m.TotalReceipts,
			&m.TotalInvoiceAmount, &m.TotalPaidAmount, &m.TotalDiscountAmount,
			&m.TotalPenaltyAmount, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

// GetGradingMetrics returns grading metrics for a given academic year.
func (s *analyticsService) GetGradingMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.GradingMetrics, error) {
	var metrics models.GradingMetrics
	query := `SELECT academic_year_id, total_policies, total_boundaries, last_updated
	          FROM analytics.grading_metrics WHERE academic_year_id = $1`
	err := s.pgClient.DB.QueryRowContext(ctx, query, academicYearID).Scan(
		&metrics.AcademicYearID, &metrics.TotalPolicies, &metrics.TotalBoundaries, &metrics.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get grading metrics: %w", err)
	}
	return &metrics, nil
}

// ListGradingMetrics returns paginated grading metrics.
func (s *analyticsService) ListGradingMetrics(ctx context.Context, limit, offset int) ([]*models.GradingMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_policies, total_boundaries, last_updated
	          FROM analytics.grading_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list grading metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.GradingMetrics
	for rows.Next() {
		var m models.GradingMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalPolicies, &m.TotalBoundaries, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

// GetGuardianMetrics returns guardian metrics for a given academic year.
func (s *analyticsService) GetGuardianMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.GuardianMetrics, error) {
	var metrics models.GuardianMetrics
	query := `SELECT academic_year_id, total_guardians, total_primary_guardians, last_updated
	          FROM analytics.guardian_metrics WHERE academic_year_id = $1`
	err := s.pgClient.DB.QueryRowContext(ctx, query, academicYearID).Scan(
		&metrics.AcademicYearID, &metrics.TotalGuardians, &metrics.TotalPrimaryGuardians, &metrics.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get guardian metrics: %w", err)
	}
	return &metrics, nil
}

// ListGuardianMetrics returns paginated guardian metrics.
func (s *analyticsService) ListGuardianMetrics(ctx context.Context, limit, offset int) ([]*models.GuardianMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_guardians, total_primary_guardians, last_updated
	          FROM analytics.guardian_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list guardian metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.GuardianMetrics
	for rows.Next() {
		var m models.GuardianMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalGuardians, &m.TotalPrimaryGuardians, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

// GetLibraryMetrics returns library metrics for a given academic year.
func (s *analyticsService) GetLibraryMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.LibraryMetrics, error) {
	var metrics models.LibraryMetrics
	query := `SELECT academic_year_id, total_categories, total_books, total_copies,
	          total_issues, total_returns, total_fines, total_fine_amount, last_updated
	          FROM analytics.library_metrics WHERE academic_year_id = $1`
	err := s.pgClient.DB.QueryRowContext(ctx, query, academicYearID).Scan(
		&metrics.AcademicYearID, &metrics.TotalCategories, &metrics.TotalBooks, &metrics.TotalCopies,
		&metrics.TotalIssues, &metrics.TotalReturns, &metrics.TotalFines, &metrics.TotalFineAmount,
		&metrics.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get library metrics: %w", err)
	}
	return &metrics, nil
}

// ListLibraryMetrics returns paginated library metrics.
func (s *analyticsService) ListLibraryMetrics(ctx context.Context, limit, offset int) ([]*models.LibraryMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_categories, total_books, total_copies,
	          total_issues, total_returns, total_fines, total_fine_amount, last_updated
	          FROM analytics.library_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list library metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.LibraryMetrics
	for rows.Next() {
		var m models.LibraryMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalCategories, &m.TotalBooks, &m.TotalCopies,
			&m.TotalIssues, &m.TotalReturns, &m.TotalFines, &m.TotalFineAmount, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

// =============================================================================
// Existing academic year metrics (unchanged)
// =============================================================================

func (s *analyticsService) GetAcademicYearMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.AcademicYearMetrics, error) {
	metrics, err := s.repo.GetAcademicYearMetrics(ctx, s.pgClient.DB, academicYearID)
	if err != nil {
		s.logger.Error("failed to get academic year metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("get academic year metrics: %w", err)
	}
	return metrics, nil
}

func (s *analyticsService) ListAcademicYearMetrics(ctx context.Context, limit, offset int) ([]*models.AcademicYearMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	metrics, err := s.repo.ListAcademicYearMetrics(ctx, s.pgClient.DB, limit, offset)
	if err != nil {
		s.logger.Error("failed to list academic year metrics",
			zap.Int("limit", limit),
			zap.Int("offset", offset),
			zap.Error(err))
		return nil, fmt.Errorf("list academic year metrics: %w", err)
	}
	return metrics, nil
}

func (s *analyticsService) RefreshAcademicYearMetrics(ctx context.Context, academicYearID uuid.UUID) error {
	logger := s.logger.With(zap.String("academic_year_id", academicYearID.String()))
	idempotencyKey := fmt.Sprintf("refresh:year:%s", academicYearID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		logger.Info("refresh already performed, skipping")
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.RefreshAcademicYearMetrics(ctx, tx, academicYearID); err != nil {
		logger.Error("failed to refresh metrics", zap.Error(err))
		return fmt.Errorf("refresh academic year metrics: %w", err)
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"academic_year_id": academicYearID,
			"operation":        "refresh",
		}
		if err := s.auditService.LogAction(ctx, tx, nil, "analytics", "refresh", "academic_year_metrics",
			&academicYearID, "system", nil, nil, nil, metadata); err != nil {
			logger.Warn("failed to log audit", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("refreshed academic year metrics")
	return nil
}

func (s *analyticsService) RefreshAllAcademicYearMetrics(ctx context.Context) error {
	rows, err := s.pgClient.DB.QueryContext(ctx, `
		SELECT academic_year_id
		FROM academics.academic_year
		WHERE deleted_at IS NULL
	`)
	if err != nil {
		return fmt.Errorf("fetch academic years: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan academic year ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows iteration: %w", err)
	}
	for _, id := range ids {
		if err := s.RefreshAcademicYearMetrics(ctx, id); err != nil {
			s.logger.Error("failed to refresh metrics for year",
				zap.String("id", id.String()),
				zap.Error(err))
		}
	}
	s.logger.Info("refreshed all academic year metrics", zap.Int("years_count", len(ids)))
	return nil
}

// =============================================================================
// Existing event processors (unchanged, but we keep them for completeness)
// =============================================================================

func (s *analyticsService) ProcessAdmissionCreated(ctx context.Context, payload []byte) error {
	var admission models.Admission
	if err := json.Unmarshal(payload, &admission); err != nil {
		return fmt.Errorf("unmarshal admission: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:  admission.AcademicYearID,
		DeltaTotalAdm:   1,
		DeltaPendingAdm: 1,
	}
	return s.applyAcademicUpdate(ctx, update, "admission.created", admission.AdmissionID)
}

func (s *analyticsService) ProcessAdmissionStatusUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		AdmissionID    uuid.UUID `json:"admission_id"`
		StudentID      uuid.UUID `json:"student_id"`
		AcademicYearID uuid.UUID `json:"academic_year_id"`
		OldStatus      string    `json:"old_status"`
		NewStatus      string    `json:"new_status"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal status update: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID: data.AcademicYearID,
	}
	switch data.OldStatus {
	case "pending":
		update.DeltaPendingAdm = -1
	case "approved":
		update.DeltaApprovedAdm = -1
	case "rejected":
		update.DeltaRejectedAdm = -1
	}
	switch data.NewStatus {
	case "pending":
		update.DeltaPendingAdm += 1
	case "approved":
		update.DeltaApprovedAdm += 1
	case "rejected":
		update.DeltaRejectedAdm += 1
	}
	return s.applyAcademicUpdate(ctx, update, "admission.status_updated", data.AdmissionID)
}

func (s *analyticsService) ProcessTermCreated(ctx context.Context, payload []byte) error {
	var term models.Term
	if err := json.Unmarshal(payload, &term); err != nil {
		return fmt.Errorf("unmarshal term: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID: term.AcademicYearID,
		DeltaTerms:     1,
	}
	return s.applyAcademicUpdate(ctx, update, "term.created", term.TermID)
}

func (s *analyticsService) ProcessAssignmentCreated(ctx context.Context, payload []byte) error {
	var assignment models.Assignment
	if err := json.Unmarshal(payload, &assignment); err != nil {
		return fmt.Errorf("unmarshal assignment: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSection(ctx, assignment.SectionID)
	if err != nil {
		return fmt.Errorf("get academic year for section: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:        academicYearID,
		DeltaTotalAssignments: 1,
	}
	if assignment.IsPublished {
		update.DeltaPublishedAssignments = 1
	}
	return s.applyAcademicUpdate(ctx, update, "assignment.created", assignment.AssignmentID)
}

func (s *analyticsService) ProcessAssignmentUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Assignment `json:"old"`
		New models.Assignment `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal assignment update: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSection(ctx, data.New.SectionID)
	if err != nil {
		return fmt.Errorf("get academic year for section: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID: academicYearID,
	}
	if !data.Old.IsPublished && data.New.IsPublished {
		update.DeltaPublishedAssignments = 1
	} else if data.Old.IsPublished && !data.New.IsPublished {
		update.DeltaPublishedAssignments = -1
	}
	return s.applyAcademicUpdate(ctx, update, "assignment.updated", data.New.AssignmentID)
}

func (s *analyticsService) ProcessAssignmentDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		AssignmentID uuid.UUID  `json:"assignment_id"`
		DeletedBy    *uuid.UUID `json:"deleted_by"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal assignment delete: %w", err)
	}
	academicYearID, isPublished, err := s.getAssignmentInfo(ctx, data.AssignmentID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Warn("assignment not found for delete event", zap.String("assignment_id", data.AssignmentID.String()))
			return nil
		}
		return fmt.Errorf("get assignment info: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:        academicYearID,
		DeltaTotalAssignments: -1,
	}
	if isPublished {
		update.DeltaPublishedAssignments = -1
	}
	return s.applyAcademicUpdate(ctx, update, "assignment.deleted", data.AssignmentID)
}

func (s *analyticsService) ProcessAssignmentPublished(ctx context.Context, payload []byte) error {
	var data struct {
		AssignmentID uuid.UUID  `json:"assignment_id"`
		Published    bool       `json:"published"`
		UpdatedBy    *uuid.UUID `json:"updated_by"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal assignment publish: %w", err)
	}
	academicYearID, err := s.getAcademicYearForAssignment(ctx, data.AssignmentID)
	if err != nil {
		return fmt.Errorf("get academic year for assignment: %w", err)
	}
	delta := 0
	if data.Published {
		delta = 1
	} else {
		delta = -1
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:            academicYearID,
		DeltaPublishedAssignments: delta,
	}
	return s.applyAcademicUpdate(ctx, update, "assignment.published", data.AssignmentID)
}

func (s *analyticsService) ProcessAttendanceMarked(ctx context.Context, payload []byte) error {
	var attendance models.StudentAttendance
	if err := json.Unmarshal(payload, &attendance); err != nil {
		return fmt.Errorf("unmarshal attendance: %w", err)
	}
	academicYearID, err := s.getAcademicYearIDFromEnrollment(ctx, attendance.EnrollmentID)
	if err != nil {
		return fmt.Errorf("get academic year from enrollment: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:         academicYearID,
		DeltaAttendanceRecords: 1,
	}
	switch attendance.Status {
	case models.StatusAbsent:
		update.DeltaAbsentRecords = 1
	case models.StatusLate:
		update.DeltaLateRecords = 1
	case models.StatusHalfDay:
		update.DeltaHalfDayRecords = 1
	}
	return s.applyAcademicUpdate(ctx, update, "attendance.marked", attendance.AttendanceID)
}

func (s *analyticsService) ProcessAttendanceBulkMarked(ctx context.Context, payload []byte) error {
	var data struct {
		Count         int            `json:"count"`
		EnrollmentIDs []uuid.UUID    `json:"enrollment_ids"`
		StatusCounts  map[string]int `json:"status_counts"`
		CreatedBy     *uuid.UUID     `json:"created_by"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal bulk attendance: %w", err)
	}
	if data.Count == 0 {
		return nil
	}
	academicYearID, err := s.getAcademicYearIDFromEnrollment(ctx, data.EnrollmentIDs[0])
	if err != nil {
		return fmt.Errorf("get academic year from enrollment: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:         academicYearID,
		DeltaAttendanceRecords: data.Count,
		DeltaAbsentRecords:     data.StatusCounts["absent"],
		DeltaLateRecords:       data.StatusCounts["late"],
		DeltaHalfDayRecords:    data.StatusCounts["half-day"],
	}
	return s.applyAcademicUpdate(ctx, update, "attendance.bulk_marked", uuid.Nil)
}

func (s *analyticsService) ProcessAttendanceExemptionCreated(ctx context.Context, payload []byte) error {
	var exemption models.StudentAttendanceExemption
	if err := json.Unmarshal(payload, &exemption); err != nil {
		return fmt.Errorf("unmarshal exemption: %w", err)
	}
	academicYearID, err := s.getAcademicYearForExemption(ctx, exemption.StudentID, exemption.FromDate)
	if err != nil {
		s.logger.Warn("could not determine academic year for exemption",
			zap.String("student_id", exemption.StudentID.String()),
			zap.Time("from_date", exemption.FromDate),
			zap.Error(err))
		return nil
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:  academicYearID,
		DeltaExemptions: 1,
	}
	return s.applyAcademicUpdate(ctx, update, "attendance.exemption_created", exemption.ExemptionID)
}

func (s *analyticsService) ProcessAttendanceExemptionDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		ExemptionID uuid.UUID `json:"exemption_id"`
		StudentID   uuid.UUID `json:"student_id"`
		FromDate    string    `json:"from_date"`
		DeletedBy   *uuid.UUID
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal exemption delete: %w", err)
	}
	fromDate, _ := time.Parse(time.RFC3339, data.FromDate)
	academicYearID, err := s.getAcademicYearForExemption(ctx, data.StudentID, fromDate)
	if err != nil {
		s.logger.Warn("could not determine academic year for deleted exemption", zap.Error(err))
		return nil
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:  academicYearID,
		DeltaExemptions: -1,
	}
	return s.applyAcademicUpdate(ctx, update, "attendance.exemption_deleted", data.ExemptionID)
}

func (s *analyticsService) ProcessSubjectAssigned(ctx context.Context, payload []byte) error {
	var mapping models.SubjectCourseMapping
	if err := json.Unmarshal(payload, &mapping); err != nil {
		return fmt.Errorf("unmarshal subject mapping: %w", err)
	}
	academicYearID, err := s.getAcademicYearForCourse(ctx, mapping.CourseID)
	if err != nil {
		return fmt.Errorf("get academic year for course: %w", err)
	}
	return s.RefreshAcademicYearMetrics(ctx, academicYearID)
}

func (s *analyticsService) ProcessSubjectUnassigned(ctx context.Context, payload []byte) error {
	var mapping models.SubjectCourseMapping
	if err := json.Unmarshal(payload, &mapping); err != nil {
		return fmt.Errorf("unmarshal subject mapping: %w", err)
	}
	academicYearID, err := s.getAcademicYearForCourse(ctx, mapping.CourseID)
	if err != nil {
		return fmt.Errorf("get academic year for course: %w", err)
	}
	return s.RefreshAcademicYearMetrics(ctx, academicYearID)
}

func (s *analyticsService) ProcessEnrollmentCreated(ctx context.Context, payload []byte) error {
	var enrollment models.Enrollment
	if err := json.Unmarshal(payload, &enrollment); err != nil {
		return fmt.Errorf("unmarshal enrollment: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:         enrollment.AcademicYearID,
		DeltaTotalEnrollments:  1,
		DeltaActiveEnrollments: 1,
	}
	return s.applyAcademicUpdate(ctx, update, "enrollment.created", enrollment.EnrollmentID)
}

func (s *analyticsService) ProcessEnrollmentUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Enrollment `json:"old"`
		New models.Enrollment `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal enrollment update: %w", err)
	}
	if data.Old.Status == data.New.Status {
		return nil
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID: data.New.AcademicYearID,
	}
	switch data.Old.Status {
	case "active":
		update.DeltaActiveEnrollments = -1
	case "completed":
		update.DeltaCompletedEnrollments = -1
	case "withdrawn":
		update.DeltaWithdrawnEnrollments = -1
	}
	switch data.New.Status {
	case "active":
		update.DeltaActiveEnrollments += 1
	case "completed":
		update.DeltaCompletedEnrollments += 1
	case "withdrawn":
		update.DeltaWithdrawnEnrollments += 1
	}
	return s.applyAcademicUpdate(ctx, update, "enrollment.updated", data.New.EnrollmentID)
}

func (s *analyticsService) ProcessEnrollmentDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		EnrollmentID uuid.UUID  `json:"enrollment_id"`
		Status       string     `json:"status"`
		DeletedBy    *uuid.UUID `json:"deleted_by"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal enrollment delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForEnrollment(ctx, data.EnrollmentID)
	if err != nil {
		return fmt.Errorf("get academic year for enrollment: %w", err)
	}
	update := &models.AcademicYearMetricsUpdate{
		AcademicYearID:        academicYearID,
		DeltaTotalEnrollments: -1,
	}
	switch data.Status {
	case "active":
		update.DeltaActiveEnrollments = -1
	case "completed":
		update.DeltaCompletedEnrollments = -1
	case "withdrawn":
		update.DeltaWithdrawnEnrollments = -1
	}
	return s.applyAcademicUpdate(ctx, update, "enrollment.deleted", data.EnrollmentID)
}

// =============================================================================
// New event processors for Exam domain
// =============================================================================

func (s *analyticsService) ProcessExamCreated(ctx context.Context, payload []byte) error {
	var exam models.Exam
	if err := json.Unmarshal(payload, &exam); err != nil {
		return fmt.Errorf("unmarshal exam: %w", err)
	}
	update := &models.ExamMetricsUpdate{
		AcademicYearID: exam.AcademicYearID,
		DeltaExams:     1,
	}
	return s.applyExamUpdate(ctx, update, "exam.created", exam.ExamID)
}

func (s *analyticsService) ProcessExamUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Exam `json:"old"`
		New models.Exam `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal exam update: %w", err)
	}
	if data.Old.AcademicYearID == data.New.AcademicYearID {
		return nil
	}
	if err := s.applyExamUpdate(ctx, &models.ExamMetricsUpdate{
		AcademicYearID: data.Old.AcademicYearID,
		DeltaExams:     -1,
	}, "exam.updated.old", data.New.ExamID); err != nil {
		return err
	}
	return s.applyExamUpdate(ctx, &models.ExamMetricsUpdate{
		AcademicYearID: data.New.AcademicYearID,
		DeltaExams:     1,
	}, "exam.updated.new", data.New.ExamID)
}

func (s *analyticsService) ProcessExamDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		ExamID    uuid.UUID `json:"exam_id"`
		DeletedBy *uuid.UUID
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal exam delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForExam(ctx, data.ExamID)
	if err != nil {
		return fmt.Errorf("get academic year for exam: %w", err)
	}
	update := &models.ExamMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaExams:     -1,
	}
	return s.applyExamUpdate(ctx, update, "exam.deleted", data.ExamID)
}

func (s *analyticsService) ProcessExamScheduleCreated(ctx context.Context, payload []byte) error {
	var schedule models.ExamSchedule
	if err := json.Unmarshal(payload, &schedule); err != nil {
		return fmt.Errorf("unmarshal schedule: %w", err)
	}
	academicYearID, err := s.getAcademicYearForExam(ctx, schedule.ExamID)
	if err != nil {
		return fmt.Errorf("get academic year for exam: %w", err)
	}
	update := &models.ExamMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaSchedules: 1,
	}
	return s.applyExamUpdate(ctx, update, "exam_schedule.created", schedule.ScheduleID)
}

func (s *analyticsService) ProcessExamScheduleDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		ScheduleID uuid.UUID `json:"schedule_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal schedule delete: %w", err)
	}
	var examID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT exam_id FROM academics.exam_schedules WHERE schedule_id = $1
	`, data.ScheduleID).Scan(&examID)
	if err != nil {
		return fmt.Errorf("get exam for schedule: %w", err)
	}
	academicYearID, err := s.getAcademicYearForExam(ctx, examID)
	if err != nil {
		return fmt.Errorf("get academic year for exam: %w", err)
	}
	update := &models.ExamMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaSchedules: -1,
	}
	return s.applyExamUpdate(ctx, update, "exam_schedule.deleted", data.ScheduleID)
}

func (s *analyticsService) ProcessExamResultCreated(ctx context.Context, payload []byte) error {
	var result models.ExamResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return fmt.Errorf("unmarshal result: %w", err)
	}
	academicYearID, err := s.getAcademicYearForExam(ctx, result.ExamID)
	if err != nil {
		return fmt.Errorf("get academic year for exam: %w", err)
	}
	update := &models.ExamMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaResults:   1,
	}
	return s.applyExamUpdate(ctx, update, "exam_result.created", result.ResultID)
}

func (s *analyticsService) ProcessExamResultDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		ResultID uuid.UUID `json:"result_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal result delete: %w", err)
	}
	var examID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT exam_id FROM academics.exam_results WHERE result_id = $1
	`, data.ResultID).Scan(&examID)
	if err != nil {
		return fmt.Errorf("get exam for result: %w", err)
	}
	academicYearID, err := s.getAcademicYearForExam(ctx, examID)
	if err != nil {
		return fmt.Errorf("get academic year for exam: %w", err)
	}
	update := &models.ExamMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaResults:   -1,
	}
	return s.applyExamUpdate(ctx, update, "exam_result.deleted", data.ResultID)
}

func (s *analyticsService) ProcessExamGradeCreated(ctx context.Context, payload []byte) error {
	var grade models.ExamGrade
	if err := json.Unmarshal(payload, &grade); err != nil {
		return fmt.Errorf("unmarshal grade: %w", err)
	}
	academicYearID, err := s.getAcademicYearForExam(ctx, grade.ExamID)
	if err != nil {
		return fmt.Errorf("get academic year for exam: %w", err)
	}
	update := &models.ExamMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaGrades:    1,
	}
	return s.applyExamUpdate(ctx, update, "exam_grade.created", grade.GradeID)
}

func (s *analyticsService) ProcessExamGradeDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		GradeID uuid.UUID `json:"grade_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal grade delete: %w", err)
	}
	var examID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT exam_id FROM academics.exam_grades WHERE grade_id = $1
	`, data.GradeID).Scan(&examID)
	if err != nil {
		return fmt.Errorf("get exam for grade: %w", err)
	}
	academicYearID, err := s.getAcademicYearForExam(ctx, examID)
	if err != nil {
		return fmt.Errorf("get academic year for exam: %w", err)
	}
	update := &models.ExamMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaGrades:    -1,
	}
	return s.applyExamUpdate(ctx, update, "exam_grade.deleted", data.GradeID)
}

// =============================================================================
// New event processors for Fee domain
// =============================================================================

func (s *analyticsService) ProcessFeeStructureCreated(ctx context.Context, payload []byte) error {
	var fs models.FeeStructure
	if err := json.Unmarshal(payload, &fs); err != nil {
		return fmt.Errorf("unmarshal fee structure: %w", err)
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID:     fs.AcademicYearID,
		DeltaFeeStructures: 1,
	}
	return s.applyFeeUpdate(ctx, update, "fee_structure.created", fs.FeeStructureID)
}

func (s *analyticsService) ProcessFeeStructureUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.FeeStructure `json:"old"`
		New models.FeeStructure `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal fee structure update: %w", err)
	}
	if data.Old.AcademicYearID == data.New.AcademicYearID {
		return nil
	}
	if err := s.applyFeeUpdate(ctx, &models.FeeMetricsUpdate{
		AcademicYearID:     data.Old.AcademicYearID,
		DeltaFeeStructures: -1,
	}, "fee_structure.updated.old", data.New.FeeStructureID); err != nil {
		return err
	}
	return s.applyFeeUpdate(ctx, &models.FeeMetricsUpdate{
		AcademicYearID:     data.New.AcademicYearID,
		DeltaFeeStructures: 1,
	}, "fee_structure.updated.new", data.New.FeeStructureID)
}

func (s *analyticsService) ProcessFeeStructureDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		FeeStructureID uuid.UUID `json:"fee_structure_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal fee structure delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForFeeStructure(ctx, data.FeeStructureID)
	if err != nil {
		return fmt.Errorf("get academic year for fee structure: %w", err)
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID:     academicYearID,
		DeltaFeeStructures: -1,
	}
	return s.applyFeeUpdate(ctx, update, "fee_structure.deleted", data.FeeStructureID)
}

func (s *analyticsService) ProcessFeeInvoiceCreated(ctx context.Context, payload []byte) error {
	var inv models.StudentFeeInvoice
	if err := json.Unmarshal(payload, &inv); err != nil {
		return fmt.Errorf("unmarshal invoice: %w", err)
	}
	// Determine academic year from student's active enrollment
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT e.academic_year_id
		FROM academics.enrollments e
		WHERE e.student_id = $1 AND e.status = 'active'
		LIMIT 1
	`, inv.StudentID).Scan(&academicYearID)
	if err != nil {
		// Fallback: get from fee structure
		var fs models.FeeStructure
		if fs, err = s.getFeeStructureByID(ctx, inv.FeeStructureID); err == nil {
			academicYearID = fs.AcademicYearID
		} else {
			return fmt.Errorf("could not determine academic year for invoice: %w", err)
		}
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID:     academicYearID,
		DeltaInvoices:      1,
		DeltaInvoiceAmount: inv.TotalAmount,
	}
	return s.applyFeeUpdate(ctx, update, "fee_invoice.created", inv.InvoiceID)
}

func (s *analyticsService) ProcessFeePaymentCreated(ctx context.Context, payload []byte) error {
	var payment models.StudentFeePayment
	if err := json.Unmarshal(payload, &payment); err != nil {
		return fmt.Errorf("unmarshal payment: %w", err)
	}
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT e.academic_year_id
		FROM academics.student_fee_invoices inv
		JOIN academics.enrollments e ON e.student_id = inv.student_id
		WHERE inv.invoice_id = $1
		LIMIT 1
	`, payment.InvoiceID).Scan(&academicYearID)
	if err != nil {
		return fmt.Errorf("get academic year for payment: %w", err)
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID:  academicYearID,
		DeltaPayments:   1,
		DeltaPaidAmount: payment.Amount,
	}
	return s.applyFeeUpdate(ctx, update, "fee_payment.created", payment.PaymentID)
}

func (s *analyticsService) ProcessFeeDiscountCreated(ctx context.Context, payload []byte) error {
	var discount models.FeeDiscount
	if err := json.Unmarshal(payload, &discount); err != nil {
		return fmt.Errorf("unmarshal discount: %w", err)
	}
	academicYearID, err := s.getAcademicYearForGuardian(ctx, discount.StudentID)
	if err != nil {
		return fmt.Errorf("get academic year for discount: %w", err)
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID:      academicYearID,
		DeltaDiscounts:      1,
		DeltaDiscountAmount: discount.DiscountValue,
	}
	return s.applyFeeUpdate(ctx, update, "fee_discount.created", discount.DiscountID)
}

func (s *analyticsService) ProcessFeeDiscountUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.FeeDiscount `json:"old"`
		New models.FeeDiscount `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal discount update: %w", err)
	}
	amountDelta := data.New.DiscountValue - data.Old.DiscountValue
	if amountDelta == 0 {
		return nil
	}
	academicYearID, err := s.getAcademicYearForGuardian(ctx, data.New.StudentID)
	if err != nil {
		return fmt.Errorf("get academic year for discount: %w", err)
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID:      academicYearID,
		DeltaDiscountAmount: amountDelta,
	}
	return s.applyFeeUpdate(ctx, update, "fee_discount.updated", data.New.DiscountID)
}

func (s *analyticsService) ProcessFeeDiscountDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		DiscountID    uuid.UUID `json:"discount_id"`
		DiscountValue float64   `json:"discount_value"`
		StudentID     uuid.UUID `json:"student_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal discount delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForGuardian(ctx, data.StudentID)
	if err != nil {
		return fmt.Errorf("get academic year for discount: %w", err)
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID:      academicYearID,
		DeltaDiscounts:      -1,
		DeltaDiscountAmount: -data.DiscountValue,
	}
	return s.applyFeeUpdate(ctx, update, "fee_discount.deleted", data.DiscountID)
}

func (s *analyticsService) ProcessFeePenaltyCreated(ctx context.Context, payload []byte) error {
	var penalty models.FeePenalty
	if err := json.Unmarshal(payload, &penalty); err != nil {
		return fmt.Errorf("unmarshal penalty: %w", err)
	}
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT e.academic_year_id
		FROM academics.student_fee_invoices inv
		JOIN academics.enrollments e ON e.student_id = inv.student_id
		WHERE inv.invoice_id = $1
		LIMIT 1
	`, penalty.InvoiceID).Scan(&academicYearID)
	if err != nil {
		return fmt.Errorf("get academic year for penalty: %w", err)
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID:     academicYearID,
		DeltaPenalties:     1,
		DeltaPenaltyAmount: penalty.Amount,
	}
	return s.applyFeeUpdate(ctx, update, "fee_penalty.created", penalty.PenaltyID)
}

func (s *analyticsService) ProcessFeePenaltyUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.FeePenalty `json:"old"`
		New models.FeePenalty `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal penalty update: %w", err)
	}
	amountDelta := data.New.Amount - data.Old.Amount
	if amountDelta == 0 {
		return nil
	}
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT e.academic_year_id
		FROM academics.student_fee_invoices inv
		JOIN academics.enrollments e ON e.student_id = inv.student_id
		WHERE inv.invoice_id = $1
		LIMIT 1
	`, data.New.InvoiceID).Scan(&academicYearID)
	if err != nil {
		return fmt.Errorf("get academic year for penalty: %w", err)
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID:     academicYearID,
		DeltaPenaltyAmount: amountDelta,
	}
	return s.applyFeeUpdate(ctx, update, "fee_penalty.updated", data.New.PenaltyID)
}

func (s *analyticsService) ProcessFeeReceiptGenerated(ctx context.Context, payload []byte) error {
	var receipt models.FeeReceipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		return fmt.Errorf("unmarshal receipt: %w", err)
	}
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT e.academic_year_id
		FROM academics.student_fee_payments p
		JOIN academics.student_fee_invoices inv ON inv.invoice_id = p.invoice_id
		JOIN academics.enrollments e ON e.student_id = inv.student_id
		WHERE p.payment_id = $1
		LIMIT 1
	`, receipt.PaymentID).Scan(&academicYearID)
	if err != nil {
		return fmt.Errorf("get academic year for receipt: %w", err)
	}
	update := &models.FeeMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaReceipts:  1,
	}
	return s.applyFeeUpdate(ctx, update, "fee_receipt.generated", receipt.ReceiptID)
}

// =============================================================================
// New event processors for Grading domain
// =============================================================================

func (s *analyticsService) ProcessGradingPolicyCreated(ctx context.Context, payload []byte) error {
	var policy models.GradingPolicy
	if err := json.Unmarshal(payload, &policy); err != nil {
		return fmt.Errorf("unmarshal grading policy: %w", err)
	}
	academicYearID, err := s.getAcademicYearForGradingPolicy(ctx, policy.PolicyID)
	if err != nil || academicYearID == uuid.Nil {
		// No academic year associated – nothing to update
		s.logger.Debug("skipping grading policy metrics: no academic year found",
			zap.String("policy_id", policy.PolicyID.String()))
		return nil
	}
	update := &models.GradingMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaPolicies:  1,
	}
	return s.applyGradingUpdate(ctx, update, "grading_policy.created", policy.PolicyID)
}

func (s *analyticsService) ProcessGradingPolicyDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		PolicyID uuid.UUID `json:"policy_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal policy delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForGradingPolicy(ctx, data.PolicyID)
	if err != nil || academicYearID == uuid.Nil {
		return nil // skip
	}
	update := &models.GradingMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaPolicies:  -1,
	}
	return s.applyGradingUpdate(ctx, update, "grading_policy.deleted", data.PolicyID)
}
func (s *analyticsService) ProcessGradeBoundaryCreated(ctx context.Context, payload []byte) error {
	var boundary models.GradeBoundary
	if err := json.Unmarshal(payload, &boundary); err != nil {
		return fmt.Errorf("unmarshal grade boundary: %w", err)
	}
	academicYearID, err := s.getAcademicYearForGradingPolicy(ctx, boundary.PolicyID)
	if err != nil {
		return nil
	}
	update := &models.GradingMetricsUpdate{
		AcademicYearID:  academicYearID,
		DeltaBoundaries: 1,
	}
	return s.applyGradingUpdate(ctx, update, "grade_boundary.created", boundary.BoundaryID)
}

func (s *analyticsService) ProcessGradeBoundaryDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		BoundaryID uuid.UUID `json:"boundary_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal boundary delete: %w", err)
	}
	var policyID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT policy_id FROM academics.grade_boundaries WHERE boundary_id = $1
	`, data.BoundaryID).Scan(&policyID)
	if err != nil {
		return fmt.Errorf("get policy for boundary: %w", err)
	}
	academicYearID, err := s.getAcademicYearForGradingPolicy(ctx, policyID)
	if err != nil {
		return nil
	}
	update := &models.GradingMetricsUpdate{
		AcademicYearID:  academicYearID,
		DeltaBoundaries: -1,
	}
	return s.applyGradingUpdate(ctx, update, "grade_boundary.deleted", data.BoundaryID)
}

// =============================================================================
// New event processors for Guardian domain
// =============================================================================

func (s *analyticsService) ProcessGuardianCreated(ctx context.Context, payload []byte) error {
	var guardian models.Guardian
	if err := json.Unmarshal(payload, &guardian); err != nil {
		return fmt.Errorf("unmarshal guardian: %w", err)
	}
	academicYearID, err := s.getAcademicYearForGuardian(ctx, guardian.StudentID)
	if err != nil {
		return nil
	}
	update := &models.GuardianMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaGuardians: 1,
	}
	if guardian.IsPrimary {
		update.DeltaPrimaryGuardians = 1
	}
	return s.applyGuardianUpdate(ctx, update, "guardian.created", guardian.GuardianID)
}

func (s *analyticsService) ProcessGuardianUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Guardian `json:"old"`
		New models.Guardian `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal guardian update: %w", err)
	}
	if data.Old.IsPrimary == data.New.IsPrimary {
		return nil
	}
	academicYearID, err := s.getAcademicYearForGuardian(ctx, data.New.StudentID)
	if err != nil {
		return nil
	}
	deltaPrimary := 0
	if data.New.IsPrimary && !data.Old.IsPrimary {
		deltaPrimary = 1
	} else if !data.New.IsPrimary && data.Old.IsPrimary {
		deltaPrimary = -1
	}
	update := &models.GuardianMetricsUpdate{
		AcademicYearID:        academicYearID,
		DeltaPrimaryGuardians: deltaPrimary,
	}
	return s.applyGuardianUpdate(ctx, update, "guardian.updated", data.New.GuardianID)
}

func (s *analyticsService) ProcessGuardianDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		GuardianID uuid.UUID `json:"guardian_id"`
		IsPrimary  bool      `json:"is_primary"`
		StudentID  uuid.UUID `json:"student_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal guardian delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForGuardian(ctx, data.StudentID)
	if err != nil {
		return nil
	}
	update := &models.GuardianMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaGuardians: -1,
	}
	if data.IsPrimary {
		update.DeltaPrimaryGuardians = -1
	}
	return s.applyGuardianUpdate(ctx, update, "guardian.deleted", data.GuardianID)
}

func (s *analyticsService) ProcessGuardianPrimarySet(ctx context.Context, payload []byte) error {
	var data struct {
		StudentID  uuid.UUID `json:"student_id"`
		GuardianID uuid.UUID `json:"guardian_id"`
		UpdatedBy  *uuid.UUID
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal primary set: %w", err)
	}
	// Find old primary guardian
	var oldPrimaryID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT guardian_id FROM academics.student_guardians
		WHERE student_id = $1 AND is_primary = true AND guardian_id != $2
	`, data.StudentID, data.GuardianID).Scan(&oldPrimaryID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("query old primary: %w", err)
	}
	academicYearID, err := s.getAcademicYearForGuardian(ctx, data.StudentID)
	if err != nil {
		return nil
	}
	if oldPrimaryID != uuid.Nil {
		update := &models.GuardianMetricsUpdate{
			AcademicYearID:        academicYearID,
			DeltaPrimaryGuardians: -1,
		}
		if err := s.applyGuardianUpdate(ctx, update, "guardian.primary_set.old", oldPrimaryID); err != nil {
			return err
		}
	}
	update := &models.GuardianMetricsUpdate{
		AcademicYearID:        academicYearID,
		DeltaPrimaryGuardians: 1,
	}
	return s.applyGuardianUpdate(ctx, update, "guardian.primary_set.new", data.GuardianID)
}

// =============================================================================
// New event processors for Library domain
// =============================================================================

func (s *analyticsService) ProcessLibraryCategoryCreated(ctx context.Context, payload []byte) error {
	var cat models.LibraryCategory
	if err := json.Unmarshal(payload, &cat); err != nil {
		return fmt.Errorf("unmarshal category: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, cat.CreatedAt)
	if err != nil {
		return nil
	}
	update := &models.LibraryMetricsUpdate{
		AcademicYearID:  academicYearID,
		DeltaCategories: 1,
	}
	return s.applyLibraryUpdate(ctx, update, "library_category.created", cat.CategoryID)
}

func (s *analyticsService) ProcessLibraryCategoryDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		CategoryID uuid.UUID `json:"category_id"`
		DeletedAt  time.Time `json:"deleted_at"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal category delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, data.DeletedAt)
	if err != nil {
		return nil
	}
	update := &models.LibraryMetricsUpdate{
		AcademicYearID:  academicYearID,
		DeltaCategories: -1,
	}
	return s.applyLibraryUpdate(ctx, update, "library_category.deleted", data.CategoryID)
}

func (s *analyticsService) ProcessLibraryBookCreated(ctx context.Context, payload []byte) error {
	var book models.LibraryBook
	if err := json.Unmarshal(payload, &book); err != nil {
		return fmt.Errorf("unmarshal book: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, book.CreatedAt)
	if err != nil {
		return nil
	}
	update := &models.LibraryMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaBooks:     1,
	}
	return s.applyLibraryUpdate(ctx, update, "library_book.created", book.BookID)
}

func (s *analyticsService) ProcessLibraryBookDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		BookID    uuid.UUID `json:"book_id"`
		DeletedAt time.Time `json:"deleted_at"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal book delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, data.DeletedAt)
	if err != nil {
		return nil
	}
	update := &models.LibraryMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaBooks:     -1,
	}
	return s.applyLibraryUpdate(ctx, update, "library_book.deleted", data.BookID)
}

func (s *analyticsService) ProcessLibraryCopyCreated(ctx context.Context, payload []byte) error {
	var copy models.LibraryBookCopy
	if err := json.Unmarshal(payload, &copy); err != nil {
		return fmt.Errorf("unmarshal copy: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, copy.CreatedAt)
	if err != nil {
		return nil
	}
	update := &models.LibraryMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaCopies:    1,
	}
	return s.applyLibraryUpdate(ctx, update, "library_copy.created", copy.CopyID)
}

func (s *analyticsService) ProcessLibraryCopyDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		CopyID    uuid.UUID `json:"copy_id"`
		DeletedAt time.Time `json:"deleted_at"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal copy delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, data.DeletedAt)
	if err != nil {
		return nil
	}
	update := &models.LibraryMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaCopies:    -1,
	}
	return s.applyLibraryUpdate(ctx, update, "library_copy.deleted", data.CopyID)
}

func (s *analyticsService) ProcessLibraryBookIssued(ctx context.Context, payload []byte) error {
	var issue models.LibraryIssue
	if err := json.Unmarshal(payload, &issue); err != nil {
		return fmt.Errorf("unmarshal issue: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, issue.IssueDate)
	if err != nil {
		return nil
	}
	update := &models.LibraryMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaIssues:    1,
	}
	return s.applyLibraryUpdate(ctx, update, "library_book.issued", issue.IssueID)
}

func (s *analyticsService) ProcessLibraryBookReturned(ctx context.Context, payload []byte) error {
	var returnRecord models.LibraryReturn
	if err := json.Unmarshal(payload, &returnRecord); err != nil {
		return fmt.Errorf("unmarshal return: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, returnRecord.ReturnDate)
	if err != nil {
		return nil
	}
	update := &models.LibraryMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaReturns:   1,
	}
	return s.applyLibraryUpdate(ctx, update, "library_book.returned", returnRecord.ReturnID)
}

func (s *analyticsService) ProcessLibraryFineCreated(ctx context.Context, payload []byte) error {
	var fine models.LibraryFine
	if err := json.Unmarshal(payload, &fine); err != nil {
		return fmt.Errorf("unmarshal fine: %w", err)
	}
	// Use issue date to determine academic year
	var issueDate time.Time
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT issue_date FROM academics.library_issues WHERE issue_id = $1
	`, fine.IssueID).Scan(&issueDate)
	if err != nil {
		return fmt.Errorf("get issue date: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, issueDate)
	if err != nil {
		return nil
	}
	update := &models.LibraryMetricsUpdate{
		AcademicYearID:  academicYearID,
		DeltaFines:      1,
		DeltaFineAmount: fine.FineAmount,
	}
	return s.applyLibraryUpdate(ctx, update, "library_fine.created", fine.FineID)
}

func (s *analyticsService) ProcessLibraryFinePaid(ctx context.Context, payload []byte) error {
	// We don't track fine payment in library metrics currently; could be added if needed.
	return nil
}

// =============================================================================
// Helper functions for academic year resolution
// =============================================================================

func (s *analyticsService) getAcademicYearForSection(ctx context.Context, sectionID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT t.academic_year_id
		FROM academics.section s
		JOIN academics.term t ON t.term_id = s.term_id
		WHERE s.section_id = $1 AND s.deleted_at IS NULL
	`, sectionID).Scan(&academicYearID)
	return academicYearID, err
}

func (s *analyticsService) getAcademicYearForAssignment(ctx context.Context, assignmentID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT t.academic_year_id
		FROM academics.assignments a
		JOIN academics.section s ON s.section_id = a.section_id
		JOIN academics.term t ON t.term_id = s.term_id
		WHERE a.assignment_id = $1 AND a.deleted_at IS NULL
	`, assignmentID).Scan(&academicYearID)
	return academicYearID, err
}

func (s *analyticsService) getAssignmentInfo(ctx context.Context, assignmentID uuid.UUID) (academicYearID uuid.UUID, isPublished bool, err error) {
	err = s.pgClient.DB.QueryRowContext(ctx, `
		SELECT t.academic_year_id, a.is_published
		FROM academics.assignments a
		JOIN academics.section s ON s.section_id = a.section_id
		JOIN academics.term t ON t.term_id = s.term_id
		WHERE a.assignment_id = $1
	`, assignmentID).Scan(&academicYearID, &isPublished)
	if err != nil {
		return uuid.Nil, false, err
	}
	return academicYearID, isPublished, nil
}

func (s *analyticsService) getAcademicYearIDFromEnrollment(ctx context.Context, enrollmentID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT academic_year_id FROM academics.enrollments
		WHERE enrollment_id = $1
	`, enrollmentID).Scan(&academicYearID)
	return academicYearID, err
}

func (s *analyticsService) getAcademicYearForExemption(ctx context.Context, studentID uuid.UUID, date time.Time) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT e.academic_year_id
		FROM academics.enrollments e
		WHERE e.student_id = $1
		  AND e.status = 'active'
		  AND e.academic_year_id = (
		      SELECT academic_year_id FROM academics.academic_year
		      WHERE $2 BETWEEN start_date AND end_date
		        AND deleted_at IS NULL
		  )
		LIMIT 1
	`, studentID, date).Scan(&academicYearID)
	return academicYearID, err
}

func (s *analyticsService) getAcademicYearForCourse(ctx context.Context, courseID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT t.academic_year_id
		FROM academics.section s
		JOIN academics.term t ON t.term_id = s.term_id
		WHERE s.course_id = $1
		  AND s.deleted_at IS NULL
		LIMIT 1
	`, courseID).Scan(&academicYearID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("course %s not used in any active section", courseID)
	}
	return academicYearID, nil
}

func (s *analyticsService) getAcademicYearForEnrollment(ctx context.Context, enrollmentID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT academic_year_id FROM academics.enrollments
		WHERE enrollment_id = $1
	`, enrollmentID).Scan(&academicYearID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("enrollment %s not found", enrollmentID)
	}
	return academicYearID, nil
}

// New helpers for domain‑specific resolution

func (s *analyticsService) getAcademicYearForExam(ctx context.Context, examID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT academic_year_id FROM academics.exams WHERE exam_id = $1 AND deleted_at IS NULL
	`, examID).Scan(&academicYearID)
	return academicYearID, err
}

func (s *analyticsService) getAcademicYearForFeeStructure(ctx context.Context, feeStructureID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT academic_year_id FROM academics.fee_structures WHERE fee_structure_id = $1 AND deleted_at IS NULL
	`, feeStructureID).Scan(&academicYearID)
	return academicYearID, err
}

func (s *analyticsService) getFeeStructureByID(ctx context.Context, id uuid.UUID) (models.FeeStructure, error) {
	var fs models.FeeStructure
	query := `SELECT fee_structure_id, academic_year_id, fee_structure_name FROM academics.fee_structures WHERE fee_structure_id = $1`
	err := s.pgClient.DB.QueryRowContext(ctx, query, id).Scan(&fs.FeeStructureID, &fs.AcademicYearID, &fs.FeeStructureName)
	return fs, err
}

func (s *analyticsService) getAcademicYearForGradingPolicy(ctx context.Context, policyID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
        SELECT t.academic_year_id
        FROM academics.grading_policies p
        LEFT JOIN academics.course c ON c.company_id = p.company_id
        LEFT JOIN academics.section s ON s.course_id = c.course_id
        LEFT JOIN academics.term t ON t.term_id = s.term_id
        WHERE p.policy_id = $1
        LIMIT 1
    `, policyID).Scan(&academicYearID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, nil // not an error, just no association
		}
		return uuid.Nil, err
	}
	return academicYearID, nil
}
func (s *analyticsService) getAcademicYearForGuardian(ctx context.Context, studentID uuid.UUID) (uuid.UUID, error) {
	// Return the academic year of the student's most recent active enrollment
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT academic_year_id FROM academics.enrollments
		WHERE student_id = $1 AND status = 'active'
		ORDER BY created_at DESC LIMIT 1
	`, studentID).Scan(&academicYearID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("no active enrollment for student %s", studentID)
	}
	return academicYearID, nil
}

func (s *analyticsService) getAcademicYearForDate(ctx context.Context, date time.Time) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
		SELECT academic_year_id FROM academics.academic_year
		WHERE $1 BETWEEN start_date AND end_date AND deleted_at IS NULL
		LIMIT 1
	`, date).Scan(&academicYearID)
	return academicYearID, err
}

// =============================================================================
// Apply update helpers with idempotency
// =============================================================================

func (s *analyticsService) applyAcademicUpdate(ctx context.Context, update *models.AcademicYearMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:academic:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		s.logger.Debug("skipping duplicate event", zap.String("key", idempotencyKey))
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateAcademicYearMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		if err := s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "academic_year_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata); err != nil {
			s.logger.Warn("failed to log audit", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	s.logger.Debug("applied academic incremental update",
		zap.String("event_type", eventType),
		zap.String("academic_year_id", update.AcademicYearID.String()))
	return nil
}

func (s *analyticsService) applyExamUpdate(ctx context.Context, update *models.ExamMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:exam:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		s.logger.Debug("skipping duplicate event", zap.String("key", idempotencyKey))
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateExamMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		if err := s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "exam_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata); err != nil {
			s.logger.Warn("failed to log audit", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	s.logger.Debug("applied exam incremental update",
		zap.String("event_type", eventType),
		zap.String("academic_year_id", update.AcademicYearID.String()))
	return nil
}

func (s *analyticsService) applyFeeUpdate(ctx context.Context, update *models.FeeMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:fee:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		s.logger.Debug("skipping duplicate event", zap.String("key", idempotencyKey))
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateFeeMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		if err := s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "fee_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata); err != nil {
			s.logger.Warn("failed to log audit", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	s.logger.Debug("applied fee incremental update",
		zap.String("event_type", eventType),
		zap.String("academic_year_id", update.AcademicYearID.String()))
	return nil
}

func (s *analyticsService) applyGradingUpdate(ctx context.Context, update *models.GradingMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:grading:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		s.logger.Debug("skipping duplicate event", zap.String("key", idempotencyKey))
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateGradingMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		if err := s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "grading_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata); err != nil {
			s.logger.Warn("failed to log audit", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	s.logger.Debug("applied grading incremental update",
		zap.String("event_type", eventType),
		zap.String("academic_year_id", update.AcademicYearID.String()))
	return nil
}

func (s *analyticsService) applyGuardianUpdate(ctx context.Context, update *models.GuardianMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:guardian:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		s.logger.Debug("skipping duplicate event", zap.String("key", idempotencyKey))
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateGuardianMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		if err := s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "guardian_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata); err != nil {
			s.logger.Warn("failed to log audit", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	s.logger.Debug("applied guardian incremental update",
		zap.String("event_type", eventType),
		zap.String("academic_year_id", update.AcademicYearID.String()))
	return nil
}

func (s *analyticsService) applyLibraryUpdate(ctx context.Context, update *models.LibraryMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:library:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		s.logger.Debug("skipping duplicate event", zap.String("key", idempotencyKey))
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateLibraryMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		if err := s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "library_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata); err != nil {
			s.logger.Warn("failed to log audit", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	s.logger.Debug("applied library incremental update",
		zap.String("event_type", eventType),
		zap.String("academic_year_id", update.AcademicYearID.String()))
	return nil
}

// ===================== Implementations =====================

// ---------------------------------------------------------------------
// Room metrics
// ---------------------------------------------------------------------

func (s *analyticsService) GetRoomMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.RoomMetrics, error) {
	return s.repo.GetRoomMetrics(ctx, s.pgClient.DB, academicYearID)
}

func (s *analyticsService) ListRoomMetrics(ctx context.Context, limit, offset int) ([]*models.RoomMetrics, error) {
	return s.repo.ListRoomMetrics(ctx, s.pgClient.DB, limit, offset)
}

func (s *analyticsService) RefreshRoomMetrics(ctx context.Context, academicYearID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("refresh:room:%s", academicYearID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		s.logger.Info("room metrics refresh already performed", zap.String("year", academicYearID.String()))
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.RefreshRoomMetrics(ctx, tx, academicYearID); err != nil {
		return err
	}

	if s.auditService != nil {
		metadata := map[string]interface{}{
			"academic_year_id": academicYearID,
			"operation":        "refresh",
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "refresh", "room_metrics",
			&academicYearID, "system", nil, nil, nil, metadata)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) ProcessRoomCreated(ctx context.Context, payload []byte) error {
	var room models.Room
	if err := json.Unmarshal(payload, &room); err != nil {
		return fmt.Errorf("unmarshal room: %w", err)
	}
	// Determine academic year – a room belongs to a company; we need to find which academic years use this room.
	// Since rooms are used in timetables, we can look up the academic years where this room appears in timetable entries.
	// For simplicity, we may update metrics for all academic years that include this room. However, to keep it incremental,
	// we can increment counts for each academic year where the room is used. But that would require a complex lookup.
	// Alternative: only maintain counts per company? The metrics are per academic year.
	// Let's implement a helper that finds all academic years that have timetables using this room.
	academicYears, err := s.getAcademicYearsForRoom(ctx, room.RoomID)
	if err != nil {
		s.logger.Error("failed to get academic years for room", zap.Error(err))
		return nil // non-fatal, skip
	}
	for _, ayID := range academicYears {
		update := &models.RoomMetricsUpdate{
			AcademicYearID: ayID,
			DeltaRooms:     1,
			DeltaActive:    0,
		}
		if room.IsActive {
			update.DeltaActive = 1
		}
		if err := s.applyRoomUpdate(ctx, update, "room.created", room.RoomID); err != nil {
			s.logger.Error("failed to apply room update", zap.Error(err))
			// continue to other years
		}
	}
	return nil
}

func (s *analyticsService) ProcessRoomUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Room `json:"old"`
		New models.Room `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal room update: %w", err)
	}
	academicYears, err := s.getAcademicYearsForRoom(ctx, data.New.RoomID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		deltaActive := 0
		if data.New.IsActive && !data.Old.IsActive {
			deltaActive = 1
		} else if !data.New.IsActive && data.Old.IsActive {
			deltaActive = -1
		}
		if deltaActive != 0 {
			update := &models.RoomMetricsUpdate{
				AcademicYearID: ayID,
				DeltaActive:    deltaActive,
			}
			if err := s.applyRoomUpdate(ctx, update, "room.updated", data.New.RoomID); err != nil {
				s.logger.Error("failed to apply room update", zap.Error(err))
			}
		}
	}
	return nil
}

func (s *analyticsService) ProcessRoomActivated(ctx context.Context, payload []byte) error {
	var data struct {
		RoomID uuid.UUID `json:"room_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal room activation: %w", err)
	}
	academicYears, err := s.getAcademicYearsForRoom(ctx, data.RoomID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.RoomMetricsUpdate{
			AcademicYearID: ayID,
			DeltaActive:    1,
		}
		if err := s.applyRoomUpdate(ctx, update, "room.activated", data.RoomID); err != nil {
			s.logger.Error("failed to apply room activation", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessRoomDeactivated(ctx context.Context, payload []byte) error {
	var data struct {
		RoomID uuid.UUID `json:"room_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal room deactivation: %w", err)
	}
	academicYears, err := s.getAcademicYearsForRoom(ctx, data.RoomID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.RoomMetricsUpdate{
			AcademicYearID: ayID,
			DeltaActive:    -1,
		}
		if err := s.applyRoomUpdate(ctx, update, "room.deactivated", data.RoomID); err != nil {
			s.logger.Error("failed to apply room deactivation", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessRoomDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		RoomID uuid.UUID `json:"room_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal room delete: %w", err)
	}
	academicYears, err := s.getAcademicYearsForRoom(ctx, data.RoomID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.RoomMetricsUpdate{
			AcademicYearID: ayID,
			DeltaRooms:     -1,
			DeltaActive:    -1, // deletion removes from both total and active
		}
		if err := s.applyRoomUpdate(ctx, update, "room.deleted", data.RoomID); err != nil {
			s.logger.Error("failed to apply room deletion", zap.Error(err))
		}
	}
	return nil
}

// Helper: get academic years where a room is used (via timetable entries)
func (s *analyticsService) getAcademicYearsForRoom(ctx context.Context, roomID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pgClient.DB.QueryContext(ctx, `
        SELECT DISTINCT t.academic_year_id
        FROM academics.timetable_entries te
        JOIN academics.timetable_slots ts ON ts.slot_id = te.slot_id
        JOIN academics.timetables tt ON tt.timetable_id = ts.timetable_id
        JOIN academics.term t ON t.term_id = tt.term_id
        WHERE te.room_id = $1
    `, roomID)
	if err != nil {
		return nil, fmt.Errorf("query academic years for room: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *analyticsService) applyRoomUpdate(ctx context.Context, update *models.RoomMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:room:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateRoomMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "room_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Section metrics
// ---------------------------------------------------------------------

func (s *analyticsService) GetSectionMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.SectionMetrics, error) {
	return s.repo.GetSectionMetrics(ctx, s.pgClient.DB, academicYearID)
}

func (s *analyticsService) ListSectionMetrics(ctx context.Context, limit, offset int) ([]*models.SectionMetrics, error) {
	return s.repo.ListSectionMetrics(ctx, s.pgClient.DB, limit, offset)
}

func (s *analyticsService) RefreshSectionMetrics(ctx context.Context, academicYearID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("refresh:section:%s", academicYearID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.RefreshSectionMetrics(ctx, tx, academicYearID); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"academic_year_id": academicYearID,
			"operation":        "refresh",
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "refresh", "section_metrics",
			&academicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) ProcessSectionCreated(ctx context.Context, payload []byte) error {
	var section models.Section
	if err := json.Unmarshal(payload, &section); err != nil {
		return fmt.Errorf("unmarshal section: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSection(ctx, section.SectionID)
	if err != nil {
		return fmt.Errorf("get academic year for section: %w", err)
	}
	update := &models.SectionMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaSections:  1,
		DeltaActive:    0,
	}
	if section.IsActive {
		update.DeltaActive = 1
	}
	// DeltaTotalCap, DeltaUsedCap may be computed later – we'll set them 0 for now
	return s.applySectionUpdate(ctx, update, "section.created", section.SectionID)
}

func (s *analyticsService) ProcessSectionUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Section `json:"old"`
		New models.Section `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal section update: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSection(ctx, data.New.SectionID)
	if err != nil {
		return fmt.Errorf("get academic year for section: %w", err)
	}
	deltaActive := 0
	if data.New.IsActive && !data.Old.IsActive {
		deltaActive = 1
	} else if !data.New.IsActive && data.Old.IsActive {
		deltaActive = -1
	}
	if deltaActive != 0 {
		update := &models.SectionMetricsUpdate{
			AcademicYearID: academicYearID,
			DeltaActive:    deltaActive,
		}
		return s.applySectionUpdate(ctx, update, "section.updated", data.New.SectionID)
	}
	return nil
}

func (s *analyticsService) ProcessSectionActivated(ctx context.Context, payload []byte) error {
	var data struct {
		SectionID uuid.UUID `json:"section_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal section activation: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSection(ctx, data.SectionID)
	if err != nil {
		return err
	}
	update := &models.SectionMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaActive:    1,
	}
	return s.applySectionUpdate(ctx, update, "section.activated", data.SectionID)
}

func (s *analyticsService) ProcessSectionDeactivated(ctx context.Context, payload []byte) error {
	var data struct {
		SectionID uuid.UUID `json:"section_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal section deactivation: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSection(ctx, data.SectionID)
	if err != nil {
		return err
	}
	update := &models.SectionMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaActive:    -1,
	}
	return s.applySectionUpdate(ctx, update, "section.deactivated", data.SectionID)
}

func (s *analyticsService) ProcessSectionDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		SectionID uuid.UUID `json:"section_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal section delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSection(ctx, data.SectionID)
	if err != nil {
		return err
	}
	update := &models.SectionMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaSections:  -1,
		DeltaActive:    -1, // deletion removes from both
	}
	return s.applySectionUpdate(ctx, update, "section.deleted", data.SectionID)
}

func (s *analyticsService) applySectionUpdate(ctx context.Context, update *models.SectionMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:section:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateSectionMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "section_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Student metrics
// ---------------------------------------------------------------------

func (s *analyticsService) GetStudentMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.StudentMetrics, error) {
	return s.repo.GetStudentMetrics(ctx, s.pgClient.DB, academicYearID)
}

func (s *analyticsService) ListStudentMetrics(ctx context.Context, limit, offset int) ([]*models.StudentMetrics, error) {
	return s.repo.ListStudentMetrics(ctx, s.pgClient.DB, limit, offset)
}

func (s *analyticsService) RefreshStudentMetrics(ctx context.Context, academicYearID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("refresh:student:%s", academicYearID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.RefreshStudentMetrics(ctx, tx, academicYearID); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"academic_year_id": academicYearID,
			"operation":        "refresh",
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "refresh", "student_metrics",
			&academicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) ProcessStudentCreated(ctx context.Context, payload []byte) error {
	var student models.Student
	if err := json.Unmarshal(payload, &student); err != nil {
		return fmt.Errorf("unmarshal student: %w", err)
	}
	// Students belong to a company; we need to find which academic years they are enrolled in.
	// We'll look up enrollments for this student.
	academicYears, err := s.getAcademicYearsForStudent(ctx, student.StudentID)
	if err != nil {
		return nil // non-fatal
	}
	for _, ayID := range academicYears {
		update := &models.StudentMetricsUpdate{
			AcademicYearID: ayID,
			DeltaTotal:     1,
			DeltaActive:    0,
			DeltaMale:      0,
			DeltaFemale:    0,
		}
		if student.Status == models.StudentActive {
			update.DeltaActive = 1
		}
		if student.Gender == "male" {
			update.DeltaMale = 1
		} else if student.Gender == "female" {
			update.DeltaFemale = 1
		}
		if err := s.applyStudentUpdate(ctx, update, "student.created", student.StudentID); err != nil {
			s.logger.Error("failed to apply student update", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessStudentUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Student `json:"old"`
		New models.Student `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal student update: %w", err)
	}
	academicYears, err := s.getAcademicYearsForStudent(ctx, data.New.StudentID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		deltaActive := 0
		if data.New.Status == models.StudentActive && data.Old.Status != models.StudentActive {
			deltaActive = 1
		} else if data.New.Status != models.StudentActive && data.Old.Status == models.StudentActive {
			deltaActive = -1
		}
		deltaMale := 0
		if data.New.Gender != data.Old.Gender {
			if data.New.Gender == "male" && data.Old.Gender != "male" {
				deltaMale = 1
			} else if data.New.Gender != "male" && data.Old.Gender == "male" {
				deltaMale = -1
			}
		}
		deltaFemale := 0
		if data.New.Gender != data.Old.Gender {
			if data.New.Gender == "female" && data.Old.Gender != "female" {
				deltaFemale = 1
			} else if data.New.Gender != "female" && data.Old.Gender == "female" {
				deltaFemale = -1
			}
		}
		if deltaActive != 0 || deltaMale != 0 || deltaFemale != 0 {
			update := &models.StudentMetricsUpdate{
				AcademicYearID: ayID,
				DeltaActive:    deltaActive,
				DeltaMale:      deltaMale,
				DeltaFemale:    deltaFemale,
			}
			if err := s.applyStudentUpdate(ctx, update, "student.updated", data.New.StudentID); err != nil {
				s.logger.Error("failed to apply student update", zap.Error(err))
			}
		}
	}
	return nil
}

func (s *analyticsService) ProcessStudentActivated(ctx context.Context, payload []byte) error {
	var data struct {
		StudentID uuid.UUID `json:"student_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal student activation: %w", err)
	}
	academicYears, err := s.getAcademicYearsForStudent(ctx, data.StudentID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.StudentMetricsUpdate{
			AcademicYearID: ayID,
			DeltaActive:    1,
		}
		if err := s.applyStudentUpdate(ctx, update, "student.activated", data.StudentID); err != nil {
			s.logger.Error("failed to apply student activation", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessStudentDeactivated(ctx context.Context, payload []byte) error {
	var data struct {
		StudentID uuid.UUID `json:"student_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal student deactivation: %w", err)
	}
	academicYears, err := s.getAcademicYearsForStudent(ctx, data.StudentID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.StudentMetricsUpdate{
			AcademicYearID: ayID,
			DeltaActive:    -1,
		}
		if err := s.applyStudentUpdate(ctx, update, "student.deactivated", data.StudentID); err != nil {
			s.logger.Error("failed to apply student deactivation", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessStudentDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		StudentID uuid.UUID `json:"student_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal student delete: %w", err)
	}
	academicYears, err := s.getAcademicYearsForStudent(ctx, data.StudentID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		// For deletion, we need to know the gender and status before delete. We can query from DB or rely on the payload.
		// Since the payload may not contain old data, we'll rely on a helper that fetches the student's details.
		student, err := s.getStudentByID(ctx, data.StudentID)
		if err != nil {
			s.logger.Error("failed to fetch student for deletion", zap.Error(err))
			continue
		}
		update := &models.StudentMetricsUpdate{
			AcademicYearID: ayID,
			DeltaTotal:     -1,
			DeltaActive:    0,
			DeltaMale:      0,
			DeltaFemale:    0,
		}
		if student.Status == models.StudentActive {
			update.DeltaActive = -1
		}
		if student.Gender == "male" {
			update.DeltaMale = -1
		} else if student.Gender == "female" {
			update.DeltaFemale = -1
		}
		if err := s.applyStudentUpdate(ctx, update, "student.deleted", data.StudentID); err != nil {
			s.logger.Error("failed to apply student deletion", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) applyStudentUpdate(ctx context.Context, update *models.StudentMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:student:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateStudentMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "student_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Helper: get academic years where a student is enrolled
func (s *analyticsService) getAcademicYearsForStudent(ctx context.Context, studentID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pgClient.DB.QueryContext(ctx, `
		SELECT DISTINCT academic_year_id FROM academics.enrollments
		WHERE student_id = $1
	`, studentID)
	if err != nil {
		return nil, fmt.Errorf("query academic years for student: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *analyticsService) getStudentByID(ctx context.Context, studentID uuid.UUID) (*models.Student, error) {
	var student models.Student
	query := `SELECT student_id, status, gender FROM academics.students WHERE student_id = $1 AND deleted_at IS NULL`
	err := s.pgClient.DB.QueryRowContext(ctx, query, studentID).Scan(&student.StudentID, &student.Status, &student.Gender)
	if err != nil {
		return nil, err
	}
	return &student, nil
}

// ---------------------------------------------------------------------
// Subject metrics
// ---------------------------------------------------------------------

func (s *analyticsService) GetSubjectMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.SubjectMetrics, error) {
	return s.repo.GetSubjectMetrics(ctx, s.pgClient.DB, academicYearID)
}

func (s *analyticsService) ListSubjectMetrics(ctx context.Context, limit, offset int) ([]*models.SubjectMetrics, error) {
	return s.repo.ListSubjectMetrics(ctx, s.pgClient.DB, limit, offset)
}

func (s *analyticsService) RefreshSubjectMetrics(ctx context.Context, academicYearID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("refresh:subject:%s", academicYearID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.RefreshSubjectMetrics(ctx, tx, academicYearID); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"academic_year_id": academicYearID,
			"operation":        "refresh",
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "refresh", "subject_metrics",
			&academicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) ProcessSubjectCreated(ctx context.Context, payload []byte) error {
	var subject models.Subject
	if err := json.Unmarshal(payload, &subject); err != nil {
		return fmt.Errorf("unmarshal subject: %w", err)
	}
	// Subjects are company‑wide, not directly tied to an academic year.
	// We need to find academic years where this subject is used (via subject‑course mappings).
	academicYears, err := s.getAcademicYearsForSubject(ctx, subject.SubjectID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.SubjectMetricsUpdate{
			AcademicYearID: ayID,
			DeltaTotal:     1,
			DeltaActive:    0,
			DeltaCredits:   subject.Credits,
		}
		if subject.IsActive {
			update.DeltaActive = 1
		}
		if err := s.applySubjectUpdate(ctx, update, "subject.created", subject.SubjectID); err != nil {
			s.logger.Error("failed to apply subject update", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessSubjectUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Subject `json:"old"`
		New models.Subject `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal subject update: %w", err)
	}
	academicYears, err := s.getAcademicYearsForSubject(ctx, data.New.SubjectID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		deltaActive := 0
		if data.New.IsActive && !data.Old.IsActive {
			deltaActive = 1
		} else if !data.New.IsActive && data.Old.IsActive {
			deltaActive = -1
		}
		deltaCredits := data.New.Credits - data.Old.Credits
		if deltaActive != 0 || deltaCredits != 0 {
			update := &models.SubjectMetricsUpdate{
				AcademicYearID: ayID,
				DeltaActive:    deltaActive,
				DeltaCredits:   deltaCredits,
			}
			if err := s.applySubjectUpdate(ctx, update, "subject.updated", data.New.SubjectID); err != nil {
				s.logger.Error("failed to apply subject update", zap.Error(err))
			}
		}
	}
	return nil
}

func (s *analyticsService) ProcessSubjectActivated(ctx context.Context, payload []byte) error {
	var data struct {
		SubjectID uuid.UUID `json:"subject_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal subject activation: %w", err)
	}
	academicYears, err := s.getAcademicYearsForSubject(ctx, data.SubjectID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.SubjectMetricsUpdate{
			AcademicYearID: ayID,
			DeltaActive:    1,
		}
		if err := s.applySubjectUpdate(ctx, update, "subject.activated", data.SubjectID); err != nil {
			s.logger.Error("failed to apply subject activation", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessSubjectDeactivated(ctx context.Context, payload []byte) error {
	var data struct {
		SubjectID uuid.UUID `json:"subject_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal subject deactivation: %w", err)
	}
	academicYears, err := s.getAcademicYearsForSubject(ctx, data.SubjectID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.SubjectMetricsUpdate{
			AcademicYearID: ayID,
			DeltaActive:    -1,
		}
		if err := s.applySubjectUpdate(ctx, update, "subject.deactivated", data.SubjectID); err != nil {
			s.logger.Error("failed to apply subject deactivation", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessSubjectDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		SubjectID uuid.UUID `json:"subject_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal subject delete: %w", err)
	}
	// Need to know the subject's details (is_active, credits) before deletion.
	subject, err := s.getSubjectByID(ctx, data.SubjectID)
	if err != nil {
		return fmt.Errorf("get subject for deletion: %w", err)
	}
	academicYears, err := s.getAcademicYearsForSubject(ctx, data.SubjectID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.SubjectMetricsUpdate{
			AcademicYearID: ayID,
			DeltaTotal:     -1,
			DeltaActive:    0,
			DeltaCredits:   -subject.Credits,
		}
		if subject.IsActive {
			update.DeltaActive = -1
		}
		if err := s.applySubjectUpdate(ctx, update, "subject.deleted", data.SubjectID); err != nil {
			s.logger.Error("failed to apply subject deletion", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) applySubjectUpdate(ctx context.Context, update *models.SubjectMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:subject:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateSubjectMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "subject_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Helper: get academic years where a subject is used (via subject‑course mappings and sections)
func (s *analyticsService) getAcademicYearsForSubject(ctx context.Context, subjectID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pgClient.DB.QueryContext(ctx, `
        SELECT DISTINCT t.academic_year_id
        FROM academics.subject_course_mapping scm
        JOIN academics.section s ON s.course_id = scm.course_id
        JOIN academics.term t ON t.term_id = s.term_id
        WHERE scm.subject_id = $1 AND s.deleted_at IS NULL
    `, subjectID)
	if err != nil {
		return nil, fmt.Errorf("query academic years for subject: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *analyticsService) getSubjectByID(ctx context.Context, subjectID uuid.UUID) (*models.Subject, error) {
	var subject models.Subject
	query := `SELECT subject_id, is_active, credits FROM academics.subject WHERE subject_id = $1 AND deleted_at IS NULL`
	err := s.pgClient.DB.QueryRowContext(ctx, query, subjectID).Scan(&subject.SubjectID, &subject.IsActive, &subject.Credits)
	if err != nil {
		return nil, err
	}
	return &subject, nil
}

// ---------------------------------------------------------------------
// Submission metrics
// ---------------------------------------------------------------------

func (s *analyticsService) GetSubmissionMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.SubmissionMetrics, error) {
	return s.repo.GetSubmissionMetrics(ctx, s.pgClient.DB, academicYearID)
}

func (s *analyticsService) ListSubmissionMetrics(ctx context.Context, limit, offset int) ([]*models.SubmissionMetrics, error) {
	return s.repo.ListSubmissionMetrics(ctx, s.pgClient.DB, limit, offset)
}

func (s *analyticsService) RefreshSubmissionMetrics(ctx context.Context, academicYearID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("refresh:submission:%s", academicYearID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.RefreshSubmissionMetrics(ctx, tx, academicYearID); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"academic_year_id": academicYearID,
			"operation":        "refresh",
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "refresh", "submission_metrics",
			&academicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) ProcessSubmissionCreated(ctx context.Context, payload []byte) error {
	var sub models.AssignmentSubmission
	if err := json.Unmarshal(payload, &sub); err != nil {
		return fmt.Errorf("unmarshal submission: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSubmission(ctx, sub.SubmissionID)
	if err != nil {
		return fmt.Errorf("get academic year for submission: %w", err)
	}
	update := &models.SubmissionMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaTotal:     1,
		DeltaLate:      0,
		DeltaGraded:    0,
	}
	if sub.Status == models.SubmissionLate {
		update.DeltaLate = 1
	}
	return s.applySubmissionUpdate(ctx, update, "submission.created", sub.SubmissionID)
}

func (s *analyticsService) ProcessSubmissionUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.AssignmentSubmission `json:"old"`
		New models.AssignmentSubmission `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal submission update: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSubmission(ctx, data.New.SubmissionID)
	if err != nil {
		return fmt.Errorf("get academic year for submission: %w", err)
	}
	// We only care about status changes (late, graded)
	deltaLate := 0
	deltaGraded := 0
	if data.New.Status == models.SubmissionLate && data.Old.Status != models.SubmissionLate {
		deltaLate = 1
	} else if data.New.Status != models.SubmissionLate && data.Old.Status == models.SubmissionLate {
		deltaLate = -1
	}
	if data.New.Status == models.SubmissionGraded && data.Old.Status != models.SubmissionGraded {
		deltaGraded = 1
	} else if data.New.Status != models.SubmissionGraded && data.Old.Status == models.SubmissionGraded {
		deltaGraded = -1
	}
	if deltaLate != 0 || deltaGraded != 0 {
		update := &models.SubmissionMetricsUpdate{
			AcademicYearID: academicYearID,
			DeltaLate:      deltaLate,
			DeltaGraded:    deltaGraded,
		}
		return s.applySubmissionUpdate(ctx, update, "submission.updated", data.New.SubmissionID)
	}
	return nil
}

func (s *analyticsService) ProcessSubmissionDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		SubmissionID uuid.UUID `json:"submission_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal submission delete: %w", err)
	}
	// Need to know the submission's details before deletion
	sub, err := s.getSubmissionByID(ctx, data.SubmissionID)
	if err != nil {
		return fmt.Errorf("get submission for deletion: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSubmission(ctx, data.SubmissionID)
	if err != nil {
		return fmt.Errorf("get academic year for submission: %w", err)
	}
	update := &models.SubmissionMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaTotal:     -1,
		DeltaLate:      0,
		DeltaGraded:    0,
	}
	if sub.Status == models.SubmissionLate {
		update.DeltaLate = -1
	}
	if sub.Status == models.SubmissionGraded {
		update.DeltaGraded = -1
	}
	return s.applySubmissionUpdate(ctx, update, "submission.deleted", data.SubmissionID)
}

func (s *analyticsService) ProcessSubmissionGraded(ctx context.Context, payload []byte) error {
	var data struct {
		SubmissionID uuid.UUID `json:"submission_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal submission graded: %w", err)
	}
	academicYearID, err := s.getAcademicYearForSubmission(ctx, data.SubmissionID)
	if err != nil {
		return fmt.Errorf("get academic year for submission: %w", err)
	}
	update := &models.SubmissionMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaGraded:    1,
	}
	return s.applySubmissionUpdate(ctx, update, "submission.graded", data.SubmissionID)
}

func (s *analyticsService) applySubmissionUpdate(ctx context.Context, update *models.SubmissionMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:submission:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateSubmissionMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "submission_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Helper: get academic year for a submission via its assignment and section
func (s *analyticsService) getAcademicYearForSubmission(ctx context.Context, submissionID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
        SELECT t.academic_year_id
        FROM academics.assignment_submissions sub   -- ← changed from assignment_submission
        JOIN academics.assignments a ON a.assignment_id = sub.assignment_id
        JOIN academics.section s ON s.section_id = a.section_id
        JOIN academics.term t ON t.term_id = s.term_id
        WHERE sub.submission_id = $1
    `, submissionID).Scan(&academicYearID)
	return academicYearID, err
}
func (s *analyticsService) getSubmissionByID(ctx context.Context, submissionID uuid.UUID) (*models.AssignmentSubmission, error) {
	var sub models.AssignmentSubmission
	query := `SELECT submission_id, status FROM academics.assignment_submissions WHERE submission_id = $1` // ← changed
	err := s.pgClient.DB.QueryRowContext(ctx, query, submissionID).Scan(&sub.SubmissionID, &sub.Status)
	if err != nil {
		return nil, err
	}
	return &sub, nil
}

// ---------------------------------------------------------------------
// Teacher metrics
// ---------------------------------------------------------------------

func (s *analyticsService) GetTeacherMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.TeacherMetrics, error) {
	return s.repo.GetTeacherMetrics(ctx, s.pgClient.DB, academicYearID)
}

func (s *analyticsService) ListTeacherMetrics(ctx context.Context, limit, offset int) ([]*models.TeacherMetrics, error) {
	return s.repo.ListTeacherMetrics(ctx, s.pgClient.DB, limit, offset)
}

func (s *analyticsService) RefreshTeacherMetrics(ctx context.Context, academicYearID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("refresh:teacher:%s", academicYearID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.RefreshTeacherMetrics(ctx, tx, academicYearID); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"academic_year_id": academicYearID,
			"operation":        "refresh",
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "refresh", "teacher_metrics",
			&academicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) ProcessTeacherCreated(ctx context.Context, payload []byte) error {
	var teacher models.Teacher
	if err := json.Unmarshal(payload, &teacher); err != nil {
		return fmt.Errorf("unmarshal teacher: %w", err)
	}
	// Teachers belong to a company; they are active across academic years if they are teaching.
	// We need to find academic years where this teacher is assigned to sections.
	academicYears, err := s.getAcademicYearsForTeacher(ctx, teacher.TeacherID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TeacherMetricsUpdate{
			AcademicYearID: ayID,
			DeltaTotal:     1,
			DeltaActive:    0,
		}
		if teacher.Status == models.TeacherActive {
			update.DeltaActive = 1
		}
		if err := s.applyTeacherUpdate(ctx, update, "teacher.created", teacher.TeacherID); err != nil {
			s.logger.Error("failed to apply teacher update", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessTeacherUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Teacher `json:"old"`
		New models.Teacher `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal teacher update: %w", err)
	}
	academicYears, err := s.getAcademicYearsForTeacher(ctx, data.New.TeacherID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		deltaActive := 0
		if data.New.Status == models.TeacherActive && data.Old.Status != models.TeacherActive {
			deltaActive = 1
		} else if data.New.Status != models.TeacherActive && data.Old.Status == models.TeacherActive {
			deltaActive = -1
		}
		if deltaActive != 0 {
			update := &models.TeacherMetricsUpdate{
				AcademicYearID: ayID,
				DeltaActive:    deltaActive,
			}
			if err := s.applyTeacherUpdate(ctx, update, "teacher.updated", data.New.TeacherID); err != nil {
				s.logger.Error("failed to apply teacher update", zap.Error(err))
			}
		}
	}
	return nil
}

func (s *analyticsService) ProcessTeacherActivated(ctx context.Context, payload []byte) error {
	var data struct {
		TeacherID uuid.UUID `json:"teacher_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal teacher activation: %w", err)
	}
	academicYears, err := s.getAcademicYearsForTeacher(ctx, data.TeacherID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TeacherMetricsUpdate{
			AcademicYearID: ayID,
			DeltaActive:    1,
		}
		if err := s.applyTeacherUpdate(ctx, update, "teacher.activated", data.TeacherID); err != nil {
			s.logger.Error("failed to apply teacher activation", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessTeacherDeactivated(ctx context.Context, payload []byte) error {
	var data struct {
		TeacherID uuid.UUID `json:"teacher_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal teacher deactivation: %w", err)
	}
	academicYears, err := s.getAcademicYearsForTeacher(ctx, data.TeacherID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TeacherMetricsUpdate{
			AcademicYearID: ayID,
			DeltaActive:    -1,
		}
		if err := s.applyTeacherUpdate(ctx, update, "teacher.deactivated", data.TeacherID); err != nil {
			s.logger.Error("failed to apply teacher deactivation", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessTeacherDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		TeacherID uuid.UUID `json:"teacher_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal teacher delete: %w", err)
	}
	teacher, err := s.getTeacherByID(ctx, data.TeacherID)
	if err != nil {
		return fmt.Errorf("get teacher for deletion: %w", err)
	}
	academicYears, err := s.getAcademicYearsForTeacher(ctx, data.TeacherID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TeacherMetricsUpdate{
			AcademicYearID: ayID,
			DeltaTotal:     -1,
			DeltaActive:    0,
		}
		if teacher.Status == models.TeacherActive {
			update.DeltaActive = -1
		}
		if err := s.applyTeacherUpdate(ctx, update, "teacher.deleted", data.TeacherID); err != nil {
			s.logger.Error("failed to apply teacher deletion", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) applyTeacherUpdate(ctx context.Context, update *models.TeacherMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:teacher:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateTeacherMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "teacher_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Helper: get academic years where a teacher is assigned (via teacher-section or teacher-subject assignments)
func (s *analyticsService) getAcademicYearsForTeacher(ctx context.Context, teacherID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pgClient.DB.QueryContext(ctx, `
        SELECT DISTINCT t.academic_year_id
        FROM academics.teacher_sections ts
        JOIN academics.section s ON s.section_id = ts.section_id
        JOIN academics.term t ON t.term_id = s.term_id
        WHERE ts.teacher_id = $1
        UNION
        SELECT DISTINCT t.academic_year_id
        FROM academics.teacher_subjects tsub
        JOIN academics.subject_course_mapping scm ON scm.subject_id = tsub.subject_id
        JOIN academics.section s ON s.course_id = scm.course_id
        JOIN academics.term t ON t.term_id = s.term_id
        WHERE tsub.teacher_id = $1
    `, teacherID)
	if err != nil {
		return nil, fmt.Errorf("query academic years for teacher: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *analyticsService) getTeacherByID(ctx context.Context, teacherID uuid.UUID) (*models.Teacher, error) {
	var teacher models.Teacher
	query := `SELECT teacher_id, status FROM academics.teacher WHERE teacher_id = $1 AND deleted_at IS NULL`
	err := s.pgClient.DB.QueryRowContext(ctx, query, teacherID).Scan(&teacher.TeacherID, &teacher.Status)
	if err != nil {
		return nil, err
	}
	return &teacher, nil
}

// ---------------------------------------------------------------------
// Timetable metrics
// ---------------------------------------------------------------------

func (s *analyticsService) GetTimetableMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.TimetableMetrics, error) {
	return s.repo.GetTimetableMetrics(ctx, s.pgClient.DB, academicYearID)
}

func (s *analyticsService) ListTimetableMetrics(ctx context.Context, limit, offset int) ([]*models.TimetableMetrics, error) {
	return s.repo.ListTimetableMetrics(ctx, s.pgClient.DB, limit, offset)
}

func (s *analyticsService) RefreshTimetableMetrics(ctx context.Context, academicYearID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("refresh:timetable:%s", academicYearID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.RefreshTimetableMetrics(ctx, tx, academicYearID); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"academic_year_id": academicYearID,
			"operation":        "refresh",
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "refresh", "timetable_metrics",
			&academicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) ProcessTimetableCreated(ctx context.Context, payload []byte) error {
	var tt models.Timetable
	if err := json.Unmarshal(payload, &tt); err != nil {
		return fmt.Errorf("unmarshal timetable: %w", err)
	}
	update := &models.TimetableMetricsUpdate{
		AcademicYearID:  tt.AcademicYearID,
		DeltaTimetables: 1,
		DeltaActive:     0,
	}
	if tt.IsActive {
		update.DeltaActive = 1
	}
	return s.applyTimetableUpdate(ctx, update, "timetable.created", tt.TimetableID)
}

func (s *analyticsService) ProcessTimetableUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.Timetable `json:"old"`
		New models.Timetable `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal timetable update: %w", err)
	}
	// If academic year changed, we need to adjust both years. But that is rare; we'll handle if needed.
	if data.Old.AcademicYearID != data.New.AcademicYearID {
		// Remove from old year
		removeUpdate := &models.TimetableMetricsUpdate{
			AcademicYearID:  data.Old.AcademicYearID,
			DeltaTimetables: -1,
			DeltaActive:     0,
		}
		if data.Old.IsActive {
			removeUpdate.DeltaActive = -1
		}
		if err := s.applyTimetableUpdate(ctx, removeUpdate, "timetable.updated.old", data.New.TimetableID); err != nil {
			return err
		}
		// Add to new year
		addUpdate := &models.TimetableMetricsUpdate{
			AcademicYearID:  data.New.AcademicYearID,
			DeltaTimetables: 1,
			DeltaActive:     0,
		}
		if data.New.IsActive {
			addUpdate.DeltaActive = 1
		}
		return s.applyTimetableUpdate(ctx, addUpdate, "timetable.updated.new", data.New.TimetableID)
	}
	// Same academic year: check active flag change
	if data.Old.IsActive != data.New.IsActive {
		deltaActive := 0
		if data.New.IsActive {
			deltaActive = 1
		} else {
			deltaActive = -1
		}
		update := &models.TimetableMetricsUpdate{
			AcademicYearID: data.New.AcademicYearID,
			DeltaActive:    deltaActive,
		}
		return s.applyTimetableUpdate(ctx, update, "timetable.updated", data.New.TimetableID)
	}
	return nil
}

func (s *analyticsService) ProcessTimetableDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		TimetableID uuid.UUID `json:"timetable_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal timetable delete: %w", err)
	}
	tt, err := s.getTimetableByID(ctx, data.TimetableID)
	if err != nil {
		return fmt.Errorf("get timetable for deletion: %w", err)
	}
	update := &models.TimetableMetricsUpdate{
		AcademicYearID:  tt.AcademicYearID,
		DeltaTimetables: -1,
		DeltaActive:     0,
	}
	if tt.IsActive {
		update.DeltaActive = -1
	}
	return s.applyTimetableUpdate(ctx, update, "timetable.deleted", data.TimetableID)
}

func (s *analyticsService) ProcessTimetableSlotAdded(ctx context.Context, payload []byte) error {
	var slot models.TimetableSlot
	if err := json.Unmarshal(payload, &slot); err != nil {
		return fmt.Errorf("unmarshal slot: %w", err)
	}
	academicYearID, err := s.getAcademicYearForTimetableSlot(ctx, slot.SlotID)
	if err != nil {
		return err
	}
	update := &models.TimetableMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaSlots:     1,
	}
	return s.applyTimetableUpdate(ctx, update, "slot.added", slot.SlotID)
}

func (s *analyticsService) ProcessTimetableSlotUpdated(ctx context.Context, payload []byte) error {
	// Slot updates don't change counts, so ignore.
	return nil
}

func (s *analyticsService) ProcessTimetableSlotDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		SlotID uuid.UUID `json:"slot_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal slot delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForTimetableSlot(ctx, data.SlotID)
	if err != nil {
		return err
	}
	update := &models.TimetableMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaSlots:     -1,
	}
	return s.applyTimetableUpdate(ctx, update, "slot.deleted", data.SlotID)
}

func (s *analyticsService) ProcessTimetableEntryAdded(ctx context.Context, payload []byte) error {
	var entry models.TimetableEntry
	if err := json.Unmarshal(payload, &entry); err != nil {
		return fmt.Errorf("unmarshal entry: %w", err)
	}
	academicYearID, err := s.getAcademicYearForTimetableEntry(ctx, entry.EntryID)
	if err != nil {
		return err
	}
	update := &models.TimetableMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaEntries:   1,
	}
	return s.applyTimetableUpdate(ctx, update, "entry.added", entry.EntryID)
}

func (s *analyticsService) ProcessTimetableEntryUpdated(ctx context.Context, payload []byte) error {
	// Entry updates don't change counts, ignore.
	return nil
}

func (s *analyticsService) ProcessTimetableEntryDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		EntryID uuid.UUID `json:"entry_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal entry delete: %w", err)
	}
	academicYearID, err := s.getAcademicYearForTimetableEntry(ctx, data.EntryID)
	if err != nil {
		return err
	}
	update := &models.TimetableMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaEntries:   -1,
	}
	return s.applyTimetableUpdate(ctx, update, "entry.deleted", data.EntryID)
}

func (s *analyticsService) ProcessTimetableChangeAdded(ctx context.Context, payload []byte) error {
	var change models.TimetableChange
	if err := json.Unmarshal(payload, &change); err != nil {
		return fmt.Errorf("unmarshal change: %w", err)
	}
	academicYearID, err := s.getAcademicYearForTimetableChange(ctx, change.ChangeID)
	if err != nil {
		return err
	}
	update := &models.TimetableMetricsUpdate{
		AcademicYearID: academicYearID,
		DeltaChanges:   1,
	}
	return s.applyTimetableUpdate(ctx, update, "change.added", change.ChangeID)
}

func (s *analyticsService) applyTimetableUpdate(ctx context.Context, update *models.TimetableMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:timetable:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateTimetableMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "timetable_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) getTimetableByID(ctx context.Context, timetableID uuid.UUID) (*models.Timetable, error) {
	var tt models.Timetable
	query := `SELECT timetable_id, academic_year_id, is_active FROM academics.timetables WHERE timetable_id = $1 AND deleted_at IS NULL`
	err := s.pgClient.DB.QueryRowContext(ctx, query, timetableID).Scan(&tt.TimetableID, &tt.AcademicYearID, &tt.IsActive)
	if err != nil {
		return nil, err
	}
	return &tt, nil
}
func (s *analyticsService) getAcademicYearForTimetableSlot(ctx context.Context, slotID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
        SELECT t.academic_year_id
        FROM academics.timetable_slots ts
        JOIN academics.timetables tt ON tt.timetable_id = ts.timetable_id
        WHERE ts.slot_id = $1
    `, slotID).Scan(&academicYearID)
	return academicYearID, err
}
func (s *analyticsService) getAcademicYearForTimetableEntry(ctx context.Context, entryID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
        SELECT t.academic_year_id
        FROM academics.timetable_entries te
        JOIN academics.timetable_slots ts ON ts.slot_id = te.slot_id
        JOIN academics.timetables tt ON tt.timetable_id = ts.timetable_id
        WHERE te.entry_id = $1
    `, entryID).Scan(&academicYearID)
	return academicYearID, err
}
func (s *analyticsService) getAcademicYearForTimetableChange(ctx context.Context, changeID uuid.UUID) (uuid.UUID, error) {
	var academicYearID uuid.UUID
	err := s.pgClient.DB.QueryRowContext(ctx, `
        SELECT t.academic_year_id
        FROM academics.timetable_changes tc
        JOIN academics.timetable_entries te ON te.entry_id = tc.entry_id
        JOIN academics.timetable_slots ts ON ts.slot_id = te.slot_id
        JOIN academics.timetables tt ON tt.timetable_id = ts.timetable_id
        WHERE tc.change_id = $1
    `, changeID).Scan(&academicYearID)
	return academicYearID, err
}

// ---------------------------------------------------------------------
// Transport metrics
// ---------------------------------------------------------------------

func (s *analyticsService) GetTransportMetrics(ctx context.Context, academicYearID uuid.UUID) (*models.TransportMetrics, error) {
	return s.repo.GetTransportMetrics(ctx, s.pgClient.DB, academicYearID)
}

func (s *analyticsService) ListTransportMetrics(ctx context.Context, limit, offset int) ([]*models.TransportMetrics, error) {
	return s.repo.ListTransportMetrics(ctx, s.pgClient.DB, limit, offset)
}

func (s *analyticsService) RefreshTransportMetrics(ctx context.Context, academicYearID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("refresh:transport:%s", academicYearID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.RefreshTransportMetrics(ctx, tx, academicYearID); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"academic_year_id": academicYearID,
			"operation":        "refresh",
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "refresh", "transport_metrics",
			&academicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) ProcessTransportRouteCreated(ctx context.Context, payload []byte) error {
	var route models.TransportRoute
	if err := json.Unmarshal(payload, &route); err != nil {
		return fmt.Errorf("unmarshal route: %w", err)
	}
	// Routes belong to a company; we need to find which academic years have sections using this route.
	academicYears, err := s.getAcademicYearsForTransportRoute(ctx, route.RouteID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TransportMetricsUpdate{
			AcademicYearID: ayID,
			DeltaRoutes:    1,
		}
		if err := s.applyTransportUpdate(ctx, update, "route.created", route.RouteID); err != nil {
			s.logger.Error("failed to apply route update", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessTransportRouteUpdated(ctx context.Context, payload []byte) error {
	// Route updates don't affect counts, ignore.
	return nil
}

func (s *analyticsService) ProcessTransportRouteDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		RouteID uuid.UUID `json:"route_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal route delete: %w", err)
	}
	academicYears, err := s.getAcademicYearsForTransportRoute(ctx, data.RouteID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TransportMetricsUpdate{
			AcademicYearID: ayID,
			DeltaRoutes:    -1,
		}
		if err := s.applyTransportUpdate(ctx, update, "route.deleted", data.RouteID); err != nil {
			s.logger.Error("failed to apply route deletion", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessTransportStopCreated(ctx context.Context, payload []byte) error {
	var stop models.TransportStop
	if err := json.Unmarshal(payload, &stop); err != nil {
		return fmt.Errorf("unmarshal stop: %w", err)
	}
	academicYears, err := s.getAcademicYearsForTransportStop(ctx, stop.StopID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TransportMetricsUpdate{
			AcademicYearID: ayID,
			DeltaStops:     1,
		}
		if err := s.applyTransportUpdate(ctx, update, "stop.created", stop.StopID); err != nil {
			s.logger.Error("failed to apply stop update", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessTransportStopUpdated(ctx context.Context, payload []byte) error {
	// Ignore
	return nil
}

func (s *analyticsService) ProcessTransportStopDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		StopID uuid.UUID `json:"stop_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal stop delete: %w", err)
	}
	academicYears, err := s.getAcademicYearsForTransportStop(ctx, data.StopID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TransportMetricsUpdate{
			AcademicYearID: ayID,
			DeltaStops:     -1,
		}
		if err := s.applyTransportUpdate(ctx, update, "stop.deleted", data.StopID); err != nil {
			s.logger.Error("failed to apply stop deletion", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessTransportVehicleCreated(ctx context.Context, payload []byte) error {
	var vehicle models.TransportVehicle
	if err := json.Unmarshal(payload, &vehicle); err != nil {
		return fmt.Errorf("unmarshal vehicle: %w", err)
	}
	// Vehicles belong to a company; they are used in driver assignments, which are tied to academic years via the assignments' dates.
	// We'll need to find academic years where this vehicle was assigned to a driver during that year.
	academicYears, err := s.getAcademicYearsForTransportVehicle(ctx, vehicle.VehicleID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TransportMetricsUpdate{
			AcademicYearID:      ayID,
			DeltaVehicles:       1,
			DeltaActiveVehicles: 0,
		}
		if vehicle.IsActive {
			update.DeltaActiveVehicles = 1
		}
		if err := s.applyTransportUpdate(ctx, update, "vehicle.created", vehicle.VehicleID); err != nil {
			s.logger.Error("failed to apply vehicle update", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessTransportVehicleUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.TransportVehicle `json:"old"`
		New models.TransportVehicle `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal vehicle update: %w", err)
	}
	academicYears, err := s.getAcademicYearsForTransportVehicle(ctx, data.New.VehicleID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		deltaActive := 0
		if data.New.IsActive && !data.Old.IsActive {
			deltaActive = 1
		} else if !data.New.IsActive && data.Old.IsActive {
			deltaActive = -1
		}
		if deltaActive != 0 {
			update := &models.TransportMetricsUpdate{
				AcademicYearID:      ayID,
				DeltaActiveVehicles: deltaActive,
			}
			if err := s.applyTransportUpdate(ctx, update, "vehicle.updated", data.New.VehicleID); err != nil {
				s.logger.Error("failed to apply vehicle update", zap.Error(err))
			}
		}
	}
	return nil
}

func (s *analyticsService) ProcessTransportVehicleDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		VehicleID uuid.UUID `json:"vehicle_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal vehicle delete: %w", err)
	}
	vehicle, err := s.getTransportVehicleByID(ctx, data.VehicleID)
	if err != nil {
		return fmt.Errorf("get vehicle for deletion: %w", err)
	}
	academicYears, err := s.getAcademicYearsForTransportVehicle(ctx, data.VehicleID)
	if err != nil {
		return nil
	}
	for _, ayID := range academicYears {
		update := &models.TransportMetricsUpdate{
			AcademicYearID:      ayID,
			DeltaVehicles:       -1,
			DeltaActiveVehicles: 0,
		}
		if vehicle.IsActive {
			update.DeltaActiveVehicles = -1
		}
		if err := s.applyTransportUpdate(ctx, update, "vehicle.deleted", data.VehicleID); err != nil {
			s.logger.Error("failed to apply vehicle deletion", zap.Error(err))
		}
	}
	return nil
}

func (s *analyticsService) ProcessTransportDriverAssignmentCreated(ctx context.Context, payload []byte) error {
	var da models.TransportDriverAssignment
	if err := json.Unmarshal(payload, &da); err != nil {
		return fmt.Errorf("unmarshal driver assignment: %w", err)
	}
	// Determine academic year based on assignment date
	academicYearID, err := s.getAcademicYearForDate(ctx, da.AssignmentDate)
	if err != nil {
		return nil
	}
	update := &models.TransportMetricsUpdate{
		AcademicYearID:         academicYearID,
		DeltaDriverAssignments: 1,
	}
	return s.applyTransportUpdate(ctx, update, "driver_assignment.created", da.AssignmentID)
}

func (s *analyticsService) ProcessTransportDriverAssignmentUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.TransportDriverAssignment `json:"old"`
		New models.TransportDriverAssignment `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal driver assignment update: %w", err)
	}
	// If assignment date changes, we might need to adjust years. For simplicity, ignore.
	return nil
}

func (s *analyticsService) ProcessTransportDriverAssignmentDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		AssignmentID uuid.UUID `json:"assignment_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal driver assignment delete: %w", err)
	}
	da, err := s.getDriverAssignmentByID(ctx, data.AssignmentID)
	if err != nil {
		return fmt.Errorf("get driver assignment for deletion: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, da.AssignmentDate)
	if err != nil {
		return nil
	}
	update := &models.TransportMetricsUpdate{
		AcademicYearID:         academicYearID,
		DeltaDriverAssignments: -1,
	}
	return s.applyTransportUpdate(ctx, update, "driver_assignment.deleted", data.AssignmentID)
}

func (s *analyticsService) ProcessTransportStudentAssignmentCreated(ctx context.Context, payload []byte) error {
	var sa models.StudentTransportAssignment
	if err := json.Unmarshal(payload, &sa); err != nil {
		return fmt.Errorf("unmarshal student assignment: %w", err)
	}
	// Determine academic year based on effective_from date
	academicYearID, err := s.getAcademicYearForDate(ctx, sa.EffectiveFrom)
	if err != nil {
		return nil
	}
	update := &models.TransportMetricsUpdate{
		AcademicYearID:          academicYearID,
		DeltaStudentAssignments: 1,
	}
	return s.applyTransportUpdate(ctx, update, "student_assignment.created", sa.AssignmentID)
}

func (s *analyticsService) ProcessTransportStudentAssignmentUpdated(ctx context.Context, payload []byte) error {
	var data struct {
		Old models.StudentTransportAssignment `json:"old"`
		New models.StudentTransportAssignment `json:"new"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal student assignment update: %w", err)
	}
	// If effective_from changed, we might need to adjust counts. For simplicity, ignore.
	return nil
}

func (s *analyticsService) ProcessTransportStudentAssignmentDeleted(ctx context.Context, payload []byte) error {
	var data struct {
		AssignmentID uuid.UUID `json:"assignment_id"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal student assignment delete: %w", err)
	}
	sa, err := s.getStudentAssignmentByID(ctx, data.AssignmentID)
	if err != nil {
		return fmt.Errorf("get student assignment for deletion: %w", err)
	}
	academicYearID, err := s.getAcademicYearForDate(ctx, sa.EffectiveFrom)
	if err != nil {
		return nil
	}
	update := &models.TransportMetricsUpdate{
		AcademicYearID:          academicYearID,
		DeltaStudentAssignments: -1,
	}
	return s.applyTransportUpdate(ctx, update, "student_assignment.deleted", data.AssignmentID)
}

func (s *analyticsService) applyTransportUpdate(ctx context.Context, update *models.TransportMetricsUpdate, eventType string, entityID uuid.UUID) error {
	idempotencyKey := fmt.Sprintf("analytics:transport:%s:%s:%s", eventType, update.AcademicYearID.String(), entityID.String())
	exists, err := s.idempotencyStore.Exists(ctx, nil, idempotencyKey)
	if err != nil {
		s.logger.Warn("idempotency check failed", zap.Error(err))
	}
	if exists {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.repo.UpdateTransportMetrics(ctx, tx, update); err != nil {
		return err
	}
	if s.auditService != nil {
		metadata := map[string]interface{}{
			"event_type": eventType,
			"entity_id":  entityID,
			"deltas":     update,
		}
		_ = s.auditService.LogAction(ctx, tx, nil, "analytics", "incremental_update", "transport_metrics",
			&update.AcademicYearID, "system", nil, nil, nil, metadata)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		s.logger.Warn("failed to store idempotency key", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *analyticsService) getAcademicYearsForTransportRoute(ctx context.Context, routeID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pgClient.DB.QueryContext(ctx, `
        SELECT DISTINCT ay.academic_year_id
        FROM academics.student_transport_assignments sta
        JOIN academics.academic_year ay ON sta.effective_from BETWEEN ay.start_date AND ay.end_date
        WHERE sta.route_id = $1
    `, routeID)
	if err != nil {
		return nil, fmt.Errorf("query academic years for route: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *analyticsService) getAcademicYearsForTransportStop(ctx context.Context, stopID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pgClient.DB.QueryContext(ctx, `
        SELECT DISTINCT ay.academic_year_id
        FROM academics.student_transport_assignments sta
        JOIN academics.academic_year ay ON sta.effective_from BETWEEN ay.start_date AND ay.end_date
        WHERE sta.stop_id = $1
    `, stopID)
	if err != nil {
		return nil, fmt.Errorf("query academic years for stop: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *analyticsService) getAcademicYearsForTransportVehicle(ctx context.Context, vehicleID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pgClient.DB.QueryContext(ctx, `
        SELECT DISTINCT ay.academic_year_id
        FROM academics.transport_driver_assignments da
        JOIN academics.academic_year ay ON da.assignment_date BETWEEN ay.start_date AND ay.end_date
        WHERE da.vehicle_id = $1
    `, vehicleID)
	if err != nil {
		return nil, fmt.Errorf("query academic years for vehicle: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *analyticsService) getTransportVehicleByID(ctx context.Context, vehicleID uuid.UUID) (*models.TransportVehicle, error) {
	var v models.TransportVehicle
	query := `SELECT vehicle_id, is_active FROM academics.transport_vehicle WHERE vehicle_id = $1 AND deleted_at IS NULL`
	err := s.pgClient.DB.QueryRowContext(ctx, query, vehicleID).Scan(&v.VehicleID, &v.IsActive)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *analyticsService) getDriverAssignmentByID(ctx context.Context, assignmentID uuid.UUID) (*models.TransportDriverAssignment, error) {
	var da models.TransportDriverAssignment
	query := `SELECT assignment_id, assignment_date FROM academics.transport_driver_assignments WHERE assignment_id = $1 AND deleted_at IS NULL`
	err := s.pgClient.DB.QueryRowContext(ctx, query, assignmentID).Scan(&da.AssignmentID, &da.AssignmentDate)
	if err != nil {
		return nil, err
	}
	return &da, nil
}

func (s *analyticsService) getStudentAssignmentByID(ctx context.Context, assignmentID uuid.UUID) (*models.StudentTransportAssignment, error) {
	var sa models.StudentTransportAssignment
	query := `SELECT assignment_id, effective_from FROM academics.student_transport_assignments WHERE assignment_id = $1 AND deleted_at IS NULL`
	err := s.pgClient.DB.QueryRowContext(ctx, query, assignmentID).Scan(&sa.AssignmentID, &sa.EffectiveFrom)
	if err != nil {
		return nil, err
	}
	return &sa, nil
}
