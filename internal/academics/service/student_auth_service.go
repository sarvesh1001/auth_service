package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// --- Errors -----------------------------------------------------------------
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked")
	ErrNoPasswordSet      = errors.New("no password set")
)

// --- Request/Response ------------------------------------------------------
type LoginRequest struct {
	Identifier string // phone or email
	Password   string
	CompanyID  uuid.UUID // optional – if not provided, we might need to search across all companies? Usually it's known.
}

type LoginResponse struct {
	Student *models.Student
	Auth    *models.StudentAuth
}

// --- Service Interface ------------------------------------------------------
type StudentAuthService interface {
	Login(ctx context.Context, req LoginRequest) (*LoginResponse, error)
	SetPassword(ctx context.Context, studentID uuid.UUID, password string, updatedBy *uuid.UUID) error
	VerifyPassword(ctx context.Context, studentID uuid.UUID, password string) (bool, error)
	HasPassword(ctx context.Context, studentID uuid.UUID) (bool, error)
	ResetPassword(ctx context.Context, studentID uuid.UUID, newPassword string, updatedBy *uuid.UUID) error
	ChangePassword(ctx context.Context, studentID uuid.UUID, oldPassword, newPassword string, updatedBy *uuid.UUID) error
}

// --- Implementation ---------------------------------------------------------
type studentAuthService struct {
	studentRepo repository.StudentRepository
	authRepo    repository.StudentAuthRepository
	pgClient    *client.PostgresClient
	logger      *zap.Logger
	notifSvc    NotificationService // optional
}

func NewStudentAuthService(
	studentRepo repository.StudentRepository,
	authRepo repository.StudentAuthRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notifSvc NotificationService,
) StudentAuthService {
	return &studentAuthService{
		studentRepo: studentRepo,
		authRepo:    authRepo,
		pgClient:    pgClient,
		logger:      logger.Named("student_auth_service"),
		notifSvc:    notifSvc,
	}
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------
func (s *studentAuthService) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	logger := s.logger.With(
		zap.String("identifier", req.Identifier),
		zap.String("company_id", req.CompanyID.String()),
	)

	// 1. Find student by identifier (phone or email)
	var student *models.Student
	var err error
	if strings.Contains(req.Identifier, "@") {
		student, err = s.studentRepo.GetByEmail(ctx, s.pgClient.DB, req.CompanyID, req.Identifier)
	} else {
		student, err = s.studentRepo.GetByPhone(ctx, s.pgClient.DB, req.CompanyID, req.Identifier)
	}
	if err != nil {
		logger.Error("failed to find student", zap.Error(err))
		return nil, fmt.Errorf("find student: %w", err)
	}
	if student == nil {
		return nil, ErrInvalidCredentials // don't reveal existence
	}

	// 2. Check if account is locked
	locked, err := s.authRepo.IsLocked(ctx, s.pgClient.DB, student.StudentID)
	if err != nil {
		return nil, fmt.Errorf("check locked: %w", err)
	}
	if locked {
		return nil, ErrAccountLocked
	}

	// 3. Verify password
	valid, err := s.authRepo.VerifyPassword(ctx, s.pgClient.DB, student.StudentID, req.Password)
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !valid {
		// Increment login attempts
		auth, getErr := s.authRepo.GetByStudentID(ctx, s.pgClient.DB, student.StudentID)
		if getErr == nil && auth != nil {
			newAttempts := auth.LoginAttempts + 1
			if err := s.authRepo.UpdateLoginAttempts(ctx, s.pgClient.DB, student.StudentID, &newAttempts); err != nil {
				logger.Error("failed to increment login attempts", zap.Error(err))
			}
			// Lock after 5 failed attempts
			if newAttempts >= 5 {
				if err := s.authRepo.LockAccount(ctx, s.pgClient.DB, student.StudentID, nil); err != nil {
					logger.Error("failed to lock account", zap.Error(err))
				}
			}
		} else {
			// No auth record yet – can't increment attempts. Possibly the student has no password set.
			// In that case, we return invalid credentials as well.
		}
		return nil, ErrInvalidCredentials
	}

	// 4. Success: reset attempts, update last login
	if err := s.authRepo.RecordLoginSuccess(ctx, s.pgClient.DB, student.StudentID); err != nil {
		logger.Error("failed to record login success", zap.Error(err))
		// continue anyway
	}

	// 5. Retrieve full auth record (optional)
	auth, _ := s.authRepo.GetByStudentID(ctx, s.pgClient.DB, student.StudentID)

	// (Optional) Send login notification
	if s.notifSvc != nil {
		title := "New Login"
		message := fmt.Sprintf("Your account was accessed on %s", time.Now().Format(time.RFC3339))
		s.sendNotification(ctx, student.StudentID, student.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityLow, nil)
	}

	return &LoginResponse{
		Student: student,
		Auth:    auth,
	}, nil
}

// ---------------------------------------------------------------------------
// Password Management (delegated to repository)
// ---------------------------------------------------------------------------
func (s *studentAuthService) SetPassword(ctx context.Context, studentID uuid.UUID, password string, updatedBy *uuid.UUID) error {
	return s.authRepo.SetPassword(ctx, s.pgClient.DB, studentID, password, updatedBy)
}

func (s *studentAuthService) VerifyPassword(ctx context.Context, studentID uuid.UUID, password string) (bool, error) {
	return s.authRepo.VerifyPassword(ctx, s.pgClient.DB, studentID, password)
}

func (s *studentAuthService) HasPassword(ctx context.Context, studentID uuid.UUID) (bool, error) {
	return s.authRepo.HasPassword(ctx, s.pgClient.DB, studentID)
}

func (s *studentAuthService) ResetPassword(ctx context.Context, studentID uuid.UUID, newPassword string, updatedBy *uuid.UUID) error {
	return s.authRepo.ResetPassword(ctx, s.pgClient.DB, studentID, newPassword, updatedBy)
}

func (s *studentAuthService) ChangePassword(ctx context.Context, studentID uuid.UUID, oldPassword, newPassword string, updatedBy *uuid.UUID) error {
	// Verify old password
	valid, err := s.authRepo.VerifyPassword(ctx, s.pgClient.DB, studentID, oldPassword)
	if err != nil {
		return fmt.Errorf("verify old password: %w", err)
	}
	if !valid {
		return ErrInvalidCredentials
	}
	// Set new password
	return s.authRepo.SetPassword(ctx, s.pgClient.DB, studentID, newPassword, updatedBy)
}

// ---------------------------------------------------------------------------
// Helper: send notification (if service is provided)
// ---------------------------------------------------------------------------
func (s *studentAuthService) sendNotification(ctx context.Context, studentID, companyID uuid.UUID, title, message string, notifType models.NotificationType, priority models.NotificationPriority, createdBy *uuid.UUID) {
	if s.notifSvc == nil {
		return
	}
	targets := []NotificationTargetInput{
		{
			TargetType:     models.TargetStudent,
			TargetEntityID: studentID,
		},
	}
	req := CreateNotificationRequest{
		CompanyID: companyID,
		Title:     title,
		Message:   message,
		Type:      notifType,
		Priority:  priority,
		Targets:   targets,
		CreatedBy: createdBy,
	}
	// Use background context to avoid cancellation
	_, err := s.notifSvc.Create(context.Background(), req, "")
	if err != nil {
		s.logger.Error("failed to send auth notification",
			zap.String("student_id", studentID.String()),
			zap.String("title", title),
			zap.Error(err))
	}
}
