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
	ErrStudentNotFound    = errors.New("student not found")
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

	// 1. Try admission number (plaintext, reliable)
	student, err := s.studentRepo.GetByAdmissionNumber(ctx, s.pgClient.DB, req.CompanyID, req.Identifier)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		logger.Error("failed to find student by admission number", zap.Error(err))
	}
	if student != nil {
		logger.Debug("student found by admission number")
		goto verify
	}

	// 2. Try email (encrypted – may fail until deterministic hash, but keep for future)
	if strings.Contains(req.Identifier, "@") {
		student, err = s.studentRepo.GetByEmail(ctx, s.pgClient.DB, req.CompanyID, req.Identifier)
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			logger.Error("failed to find student by email", zap.Error(err))
		}
		if student != nil {
			logger.Debug("student found by email")
			goto verify
		}
	}

	// 3. Try phone (encrypted – may fail until deterministic hash)
	student, err = s.studentRepo.GetByPhone(ctx, s.pgClient.DB, req.CompanyID, req.Identifier)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		logger.Error("failed to find student by phone", zap.Error(err))
	}
	if student == nil {
		logger.Info("no student found for identifier", zap.String("identifier", req.Identifier))
		return nil, ErrInvalidCredentials
	}
	logger.Debug("student found by phone")

verify:
	// 4. Check if account is locked
	locked, err := s.authRepo.IsLocked(ctx, s.pgClient.DB, student.StudentID)
	if err != nil {
		// If no auth record exists, treat as not locked
		if !errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("check locked: %w", err)
		}
		locked = false
	}
	if locked {
		return nil, ErrAccountLocked
	}

	// 5. Verify password
	valid, err := s.authRepo.VerifyPassword(ctx, s.pgClient.DB, student.StudentID, req.Password)
	if err != nil {
		// If no auth record, treat as invalid password
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !valid {
		// Increment login attempts (only if auth record exists)
		auth, getErr := s.authRepo.GetByStudentID(ctx, s.pgClient.DB, student.StudentID)
		if getErr == nil && auth != nil {
			newAttempts := auth.LoginAttempts + 1
			if err := s.authRepo.UpdateLoginAttempts(ctx, s.pgClient.DB, student.StudentID, &newAttempts); err != nil {
				logger.Error("failed to increment login attempts", zap.Error(err))
			}
			if newAttempts >= 5 {
				if err := s.authRepo.LockAccount(ctx, s.pgClient.DB, student.StudentID, nil); err != nil {
					logger.Error("failed to lock account", zap.Error(err))
				}
			}
		}
		return nil, ErrInvalidCredentials
	}

	// 6. Success: reset attempts, update last login
	if err := s.authRepo.RecordLoginSuccess(ctx, s.pgClient.DB, student.StudentID); err != nil {
		// If no auth record, create one (this should not happen because password exists)
		if errors.Is(err, repository.ErrNotFound) {
			if setErr := s.authRepo.SetPassword(ctx, s.pgClient.DB, student.StudentID, req.Password, nil); setErr != nil {
				logger.Error("failed to create auth record on success", zap.Error(setErr))
			}
		} else {
			logger.Error("failed to record login success", zap.Error(err))
		}
	}

	// 7. Retrieve full auth record (optional)
	auth, _ := s.authRepo.GetByStudentID(ctx, s.pgClient.DB, student.StudentID)

	// 8. Send login notification (optional)
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
// Password Management (with student existence check)
// ---------------------------------------------------------------------------

// SetPassword sets or updates a student's password.
// It first verifies that the student exists in the students table.
func (s *studentAuthService) SetPassword(ctx context.Context, studentID uuid.UUID, password string, updatedBy *uuid.UUID) error {
	// 1. Check that the student actually exists
	student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, studentID)
	if err != nil {
		return fmt.Errorf("check student existence: %w", err)
	}
	if student == nil {
		return ErrStudentNotFound
	}

	// 2. Delegate to auth repository (insert or update)
	return s.authRepo.SetPassword(ctx, s.pgClient.DB, studentID, password, updatedBy)
}

// VerifyPassword checks if the provided password matches the stored one.
// It does NOT check student existence because if there's no auth record, it will return false.
func (s *studentAuthService) VerifyPassword(ctx context.Context, studentID uuid.UUID, password string) (bool, error) {
	// Optionally check student existence first, but not strictly required.
	// If student doesn't exist, VerifyPassword will likely return false because no auth record.
	return s.authRepo.VerifyPassword(ctx, s.pgClient.DB, studentID, password)
}

// HasPassword returns true if the student has a password set (i.e., an auth record with a non-empty password).
// It does not check student existence; if student has no auth record, returns false.
func (s *studentAuthService) HasPassword(ctx context.Context, studentID uuid.UUID) (bool, error) {
	return s.authRepo.HasPassword(ctx, s.pgClient.DB, studentID)
}

// ResetPassword is an admin‑only operation that directly sets a new password.
// It checks student existence before proceeding.
func (s *studentAuthService) ResetPassword(ctx context.Context, studentID uuid.UUID, newPassword string, updatedBy *uuid.UUID) error {
	// 1. Check student exists
	student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, studentID)
	if err != nil {
		return fmt.Errorf("check student existence: %w", err)
	}
	if student == nil {
		return ErrStudentNotFound
	}

	// 2. Set new password
	return s.authRepo.ResetPassword(ctx, s.pgClient.DB, studentID, newPassword, updatedBy)
}

// ChangePassword allows a student to change their own password after verifying the old one.
// It checks student existence before verifying the old password.
func (s *studentAuthService) ChangePassword(ctx context.Context, studentID uuid.UUID, oldPassword, newPassword string, updatedBy *uuid.UUID) error {
	// 1. Check student exists
	student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, studentID)
	if err != nil {
		return fmt.Errorf("check student existence: %w", err)
	}
	if student == nil {
		return ErrStudentNotFound
	}

	// 2. Verify old password
	valid, err := s.authRepo.VerifyPassword(ctx, s.pgClient.DB, studentID, oldPassword)
	if err != nil {
		// If no auth record, treat as invalid
		if errors.Is(err, repository.ErrNotFound) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("verify old password: %w", err)
	}
	if !valid {
		return ErrInvalidCredentials
	}

	// 3. Set new password
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
