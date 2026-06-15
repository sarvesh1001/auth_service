package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	salesErrors "auth-service/internal/sales/errors"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/repository"
)

// =============================================================================
// Request/Response DTOs (assumed to be defined elsewhere)
// =============================================================================

// =============================================================================
// Service Interface
// =============================================================================
type PaymentTermService interface {
	CreatePaymentTerm(ctx context.Context, req *CreatePaymentTermRequest) (*models.PaymentTerm, error)
	UpdatePaymentTerm(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, req *UpdatePaymentTermRequest) (*models.PaymentTerm, error)
	DeletePaymentTerm(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, deletedBy uuid.UUID) error
	GetPaymentTermByID(ctx context.Context, companyID uuid.UUID, termID uuid.UUID) (*models.PaymentTerm, error)
	GetPaymentTermByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.PaymentTerm, error)
	GetPaymentTermByName(ctx context.Context, companyID uuid.UUID, termName string) (*models.PaymentTerm, error)
	ListPaymentTerms(ctx context.Context, filter PaymentTermListFilter, p Pagination, s Sort) ([]*models.PaymentTerm, int64, error)
	SearchPaymentTerms(ctx context.Context, companyID uuid.UUID, query string, limit int, offset int) ([]*models.PaymentTerm, int64, error)
	GetActivePaymentTerms(ctx context.Context, companyID uuid.UUID) ([]*models.PaymentTerm, error)
	ActivatePaymentTerm(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, updatedBy uuid.UUID) error
	DeactivatePaymentTerm(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, updatedBy uuid.UUID) error
	IsPaymentTermActive(ctx context.Context, companyID uuid.UUID, termID uuid.UUID) (bool, error)
	CalculateDueDate(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, invoiceDate time.Time) (time.Time, error)
	CalculateEarlyPaymentDiscount(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, invoiceAmount decimal.Decimal, paymentDate, invoiceDate time.Time) (decimal.Decimal, error)
	AssignPaymentTermToCustomer(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, termID uuid.UUID, updatedBy uuid.UUID) error
	RemovePaymentTermFromCustomer(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, updatedBy uuid.UUID) error
	ValidatePaymentTerm(ctx context.Context, term *models.PaymentTerm) error
	PaymentTermExists(ctx context.Context, companyID uuid.UUID, termID uuid.UUID) (bool, error)
	PaymentTermCodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
}

// =============================================================================
// Implementation
// =============================================================================
type paymentTermService struct {
	repo             repository.PaymentTermRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewPaymentTermService(
	repo repository.PaymentTermRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) PaymentTermService {
	return &paymentTermService{
		repo:             repo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("payment_term_service"),
	}
}

// -----------------------------------------------------------------------------
// Idempotency helper
// -----------------------------------------------------------------------------
func (s *paymentTermService) getAndCheckIdempotencyKey(ctx context.Context) string {
	key, ok := ctx.Value("idempotency_key").(string)
	if !ok || key == "" {
		s.logger.Warn("idempotency key not found in context, generating fallback key")
		key = uuid.New().String()
	}
	return key
}

// -----------------------------------------------------------------------------
// CreatePaymentTerm (idempotent, uses tx)
// -----------------------------------------------------------------------------
func (s *paymentTermService) CreatePaymentTerm(ctx context.Context, req *CreatePaymentTermRequest) (*models.PaymentTerm, error) {
	logger := s.logger.With(zap.String("method", "CreatePaymentTerm"))

	if err := s.validateCreateRequest(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := s.getAndCheckIdempotencyKey(ctx)

	var cached *models.PaymentTerm
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached payment term")
		return cached, nil
	}

	// Check duplicate code
	exists, err := s.repo.ExistsByCode(ctx, tx, req.CompanyID, req.Code)
	if err != nil {
		return nil, fmt.Errorf("check code existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: code %s already exists", salesErrors.ErrDuplicate, req.Code)
	}

	// Check duplicate term_name
	nameExists, err := s.repo.ExistsByName(ctx, tx, req.CompanyID, req.TermName)
	if err != nil {
		return nil, fmt.Errorf("check term_name existence: %w", err)
	}
	if nameExists {
		return nil, fmt.Errorf("%w: term_name %s already exists", salesErrors.ErrDuplicate, req.TermName)
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	term := &models.PaymentTerm{
		TermID:          uuid.New(),
		CompanyID:       req.CompanyID,
		Code:            req.Code,
		TermName:        req.TermName,
		Description:     req.Description,
		DueDays:         req.DueDays,
		DiscountPercent: req.DiscountPercent,
		DiscountDays:    req.DiscountDays,
		IsActive:        isActive,
		CreatedBy:       req.CreatedBy,
		UpdatedBy:       req.CreatedBy,
	}

	if err := s.repo.Create(ctx, tx, term); err != nil {
		return nil, fmt.Errorf("create payment term: %w", err)
	}

	if err := s.emitEvent(ctx, tx, term, salesEvents.EventPaymentTermCreated); err != nil {
		logger.Warn("failed to emit created event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, term); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_payment_term", "payment_term", &term.TermID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
			"code": term.Code,
			"name": term.TermName,
		})
	}

	return term, nil
}

func (s *paymentTermService) validateCreateRequest(req *CreatePaymentTermRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.Code == "" {
		return fmt.Errorf("%w: code required", salesErrors.ErrInvalidInput)
	}
	if req.TermName == "" {
		return fmt.Errorf("%w: term_name required", salesErrors.ErrInvalidInput)
	}
	if req.DueDays <= 0 {
		return fmt.Errorf("%w: due_days must be > 0", salesErrors.ErrInvalidInput)
	}
	if req.DiscountPercent.LessThan(decimal.Zero) || req.DiscountPercent.GreaterThan(decimal.NewFromInt(100)) {
		return fmt.Errorf("%w: discount_percent must be between 0 and 100", salesErrors.ErrInvalidInput)
	}
	if req.DiscountDays < 0 {
		return fmt.Errorf("%w: discount_days cannot be negative", salesErrors.ErrInvalidInput)
	}
	if req.DiscountDays > req.DueDays {
		return fmt.Errorf("%w: discount_days (%d) cannot exceed due_days (%d)", salesErrors.ErrInvalidInput, req.DiscountDays, req.DueDays)
	}
	return nil
}

// -----------------------------------------------------------------------------
// UpdatePaymentTerm (idempotent, uses tx)
// -----------------------------------------------------------------------------
func (s *paymentTermService) UpdatePaymentTerm(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, req *UpdatePaymentTermRequest) (*models.PaymentTerm, error) {
	logger := s.logger.With(zap.String("method", "UpdatePaymentTerm"))

	if companyID == uuid.Nil || termID == uuid.Nil {
		return nil, salesErrors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := s.getAndCheckIdempotencyKey(ctx)

	var cached *models.PaymentTerm
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached payment term")
		return cached, nil
	}

	term, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, termID)
	if err != nil {
		return nil, err
	}
	if term.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}

	changes := make(map[string]interface{})

	// Validate and apply term_name change (must be unique)
	if req.TermName != nil && *req.TermName != term.TermName {
		nameExists, err := s.repo.ExistsByName(ctx, tx, companyID, *req.TermName)
		if err != nil {
			return nil, fmt.Errorf("check term_name existence: %w", err)
		}
		if nameExists {
			return nil, fmt.Errorf("%w: term_name %s already exists", salesErrors.ErrDuplicate, *req.TermName)
		}
		changes["term_name"] = map[string]string{"old": term.TermName, "new": *req.TermName}
		term.TermName = *req.TermName
	}
	if req.Description != nil {
		changes["description"] = map[string]*string{"old": term.Description, "new": req.Description}
		term.Description = req.Description
	}
	if req.DueDays != nil && *req.DueDays != term.DueDays {
		changes["due_days"] = map[string]int{"old": term.DueDays, "new": *req.DueDays}
		term.DueDays = *req.DueDays
	}
	if req.DiscountPercent != nil && !req.DiscountPercent.Equal(term.DiscountPercent) {
		changes["discount_percent"] = map[string]string{"old": term.DiscountPercent.String(), "new": req.DiscountPercent.String()}
		term.DiscountPercent = *req.DiscountPercent
	}
	if req.DiscountDays != nil && *req.DiscountDays != term.DiscountDays {
		dueDays := term.DueDays
		if req.DueDays != nil {
			dueDays = *req.DueDays
		}
		if *req.DiscountDays > dueDays {
			return nil, fmt.Errorf("%w: discount_days (%d) cannot exceed due_days (%d)", salesErrors.ErrInvalidInput, *req.DiscountDays, dueDays)
		}
		changes["discount_days"] = map[string]int{"old": term.DiscountDays, "new": *req.DiscountDays}
		term.DiscountDays = *req.DiscountDays
	}
	if req.IsActive != nil && *req.IsActive != term.IsActive {
		changes["is_active"] = map[string]bool{"old": term.IsActive, "new": *req.IsActive}
		term.IsActive = *req.IsActive
	}

	term.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, term); err != nil {
		return nil, fmt.Errorf("update payment term: %w", err)
	}

	if err := s.emitEvent(ctx, tx, term, salesEvents.EventPaymentTermUpdated); err != nil {
		logger.Warn("failed to emit updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, term); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_payment_term", "payment_term", &termID, "user", req.UpdatedBy, nil, nil, changes)
	}

	return term, nil
}

// -----------------------------------------------------------------------------
// DeletePaymentTerm (soft delete or deactivate, uses tx)
// -----------------------------------------------------------------------------
func (s *paymentTermService) DeletePaymentTerm(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeletePaymentTerm"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := s.getAndCheckIdempotencyKey(ctx)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}

	term, err := s.repo.GetByID(ctx, tx, companyID, termID)
	if err != nil {
		return err
	}
	if term.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}

	// Check if term is referenced by any customer
	var customerCount int
	query := `SELECT COUNT(*) FROM sales.customers WHERE company_id = $1 AND payment_term_id = $2`
	err = tx.QueryRowContext(ctx, query, companyID, termID).Scan(&customerCount)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("check customer references: %w", err)
	}

	if customerCount > 0 {
		// Soft deactivate instead of hard delete
		if term.IsActive {
			if err := s.repo.SetActiveStatus(ctx, tx, companyID, termID, false, &deletedBy); err != nil {
				return fmt.Errorf("deactivate payment term: %w", err)
			}
			logger.Info("payment term has customer references, deactivated instead of deleted")
		}
	} else {
		if err := s.repo.Delete(ctx, tx, companyID, termID); err != nil {
			return fmt.Errorf("delete payment term: %w", err)
		}
	}

	if err := s.emitEvent(ctx, tx, term, salesEvents.EventPaymentTermDeleted); err != nil {
		logger.Warn("failed to emit delete event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_payment_term", "payment_term", &termID, "user", &deletedBy, nil, nil, nil)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Read methods – NOW USING s.pgClient.DB (no more nil)
// -----------------------------------------------------------------------------
func (s *paymentTermService) GetPaymentTermByID(ctx context.Context, companyID uuid.UUID, termID uuid.UUID) (*models.PaymentTerm, error) {
	return s.repo.GetByID(ctx, s.pgClient.DB, companyID, termID)
}

func (s *paymentTermService) GetPaymentTermByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.PaymentTerm, error) {
	return s.repo.GetByCode(ctx, s.pgClient.DB, companyID, code)
}

func (s *paymentTermService) GetPaymentTermByName(ctx context.Context, companyID uuid.UUID, termName string) (*models.PaymentTerm, error) {
	return s.repo.GetByName(ctx, s.pgClient.DB, companyID, termName)
}

func (s *paymentTermService) ListPaymentTerms(ctx context.Context, filter PaymentTermListFilter, p Pagination, srt Sort) ([]*models.PaymentTerm, int64, error) {
	repoFilter := repository.PaymentTermFilter{
		CompanyID:  filter.CompanyID,
		IsActive:   filter.IsActive,
		DueDaysMin: filter.MinDueDays,
		DueDaysMax: filter.MaxDueDays,
	}
	return s.repo.List(ctx, s.pgClient.DB, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *paymentTermService) SearchPaymentTerms(ctx context.Context, companyID uuid.UUID, query string, limit int, offset int) ([]*models.PaymentTerm, int64, error) {
	return s.repo.Search(ctx, s.pgClient.DB, companyID, query, limit, offset)
}

func (s *paymentTermService) GetActivePaymentTerms(ctx context.Context, companyID uuid.UUID) ([]*models.PaymentTerm, error) {
	return s.repo.GetActiveTerms(ctx, s.pgClient.DB, companyID)
}

func (s *paymentTermService) IsPaymentTermActive(ctx context.Context, companyID uuid.UUID, termID uuid.UUID) (bool, error) {
	return s.repo.IsActive(ctx, s.pgClient.DB, companyID, termID)
}

// -----------------------------------------------------------------------------
// Business logic calculations (read-only)
// -----------------------------------------------------------------------------
func (s *paymentTermService) CalculateDueDate(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, invoiceDate time.Time) (time.Time, error) {
	return s.repo.CalculateDueDate(ctx, s.pgClient.DB, companyID, termID, invoiceDate)
}

func (s *paymentTermService) CalculateEarlyPaymentDiscount(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, invoiceAmount decimal.Decimal, paymentDate, invoiceDate time.Time) (decimal.Decimal, error) {
	return s.repo.CalculateEarlyPaymentDiscount(ctx, s.pgClient.DB, companyID, termID, invoiceAmount, paymentDate, invoiceDate)
}

// -----------------------------------------------------------------------------
// Activate / Deactivate (idempotent, use tx)
// -----------------------------------------------------------------------------
func (s *paymentTermService) ActivatePaymentTerm(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, updatedBy uuid.UUID) error {
	return s.setActiveStatus(ctx, companyID, termID, true, updatedBy, salesEvents.EventPaymentTermActivated)
}

func (s *paymentTermService) DeactivatePaymentTerm(ctx context.Context, companyID uuid.UUID, termID uuid.UUID, updatedBy uuid.UUID) error {
	return s.setActiveStatus(ctx, companyID, termID, false, updatedBy, salesEvents.EventPaymentTermDeactivated)
}

func (s *paymentTermService) setActiveStatus(ctx context.Context, companyID, termID uuid.UUID, active bool, updatedBy uuid.UUID, eventType string) error {
	logger := s.logger.With(zap.String("method", "setActiveStatus"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := s.getAndCheckIdempotencyKey(ctx)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – status already updated")
		return nil
	}

	if err := s.repo.SetActiveStatus(ctx, tx, companyID, termID, active, &updatedBy); err != nil {
		return err
	}

	term, _ := s.repo.GetByID(ctx, tx, companyID, termID)
	if term != nil {
		_ = s.emitEvent(ctx, tx, term, eventType)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		action := "activate_payment_term"
		if !active {
			action = "deactivate_payment_term"
		}
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", action, "payment_term", &termID, "user", &updatedBy, nil, nil, nil)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Customer assignment (idempotent, uses tx)
// -----------------------------------------------------------------------------
func (s *paymentTermService) AssignPaymentTermToCustomer(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, termID uuid.UUID, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "AssignPaymentTermToCustomer"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := s.getAndCheckIdempotencyKey(ctx)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – assignment already performed")
		return nil
	}

	// Verify term exists and is active
	term, err := s.repo.GetByID(ctx, tx, companyID, termID)
	if err != nil {
		return err
	}
	if !term.IsActive {
		return salesErrors.ErrPaymentTermInactive
	}

	if err := s.repo.ApplyToCustomer(ctx, tx, companyID, customerID, termID, &updatedBy); err != nil {
		return err
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "assign_payment_term", "customer", &customerID, "user", &updatedBy, nil, nil, map[string]interface{}{
			"payment_term_id": termID.String(),
		})
	}
	return nil
}

func (s *paymentTermService) RemovePaymentTermFromCustomer(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemovePaymentTermFromCustomer"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := s.getAndCheckIdempotencyKey(ctx)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – removal already performed")
		return nil
	}

	query := `UPDATE sales.customers SET payment_term_id = NULL, updated_at = NOW(), updated_by = $3 WHERE company_id = $1 AND customer_id = $2`
	_, err = tx.ExecContext(ctx, query, companyID, customerID, updatedBy)
	if err != nil {
		return fmt.Errorf("remove payment term from customer: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "remove_payment_term", "customer", &customerID, "user", &updatedBy, nil, nil, nil)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Validation & existence (read-only, use DB)
// -----------------------------------------------------------------------------
func (s *paymentTermService) ValidatePaymentTerm(ctx context.Context, term *models.PaymentTerm) error {
	if term.Code == "" {
		return fmt.Errorf("%w: code required", salesErrors.ErrInvalidInput)
	}
	if term.TermName == "" {
		return fmt.Errorf("%w: term_name required", salesErrors.ErrInvalidInput)
	}
	if term.DueDays <= 0 {
		return fmt.Errorf("%w: due_days must be > 0", salesErrors.ErrInvalidInput)
	}
	if term.DiscountPercent.LessThan(decimal.Zero) || term.DiscountPercent.GreaterThan(decimal.NewFromInt(100)) {
		return fmt.Errorf("%w: discount_percent must be between 0 and 100", salesErrors.ErrInvalidInput)
	}
	if term.DiscountDays < 0 {
		return fmt.Errorf("%w: discount_days cannot be negative", salesErrors.ErrInvalidInput)
	}
	if term.DiscountDays > term.DueDays {
		return fmt.Errorf("%w: discount_days (%d) cannot exceed due_days (%d)", salesErrors.ErrInvalidInput, term.DiscountDays, term.DueDays)
	}
	return nil
}

func (s *paymentTermService) PaymentTermExists(ctx context.Context, companyID uuid.UUID, termID uuid.UUID) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, termID)
}

func (s *paymentTermService) PaymentTermCodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	return s.repo.ExistsByCode(ctx, s.pgClient.DB, companyID, code)
}

// -----------------------------------------------------------------------------
// Event emission helper (uses tx)
// -----------------------------------------------------------------------------
func (s *paymentTermService) emitEvent(ctx context.Context, tx repository.DBTX, term *models.PaymentTerm, eventType string) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}

	payload := salesEvents.PaymentTermPayload{
		TermID:          term.TermID.String(),
		CompanyID:       term.CompanyID.String(),
		Code:            term.Code,
		TermName:        term.TermName,
		DueDays:         term.DueDays,
		DiscountPercent: term.DiscountPercent.String(),
		DiscountDays:    term.DiscountDays,
		IsActive:        term.IsActive,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "payment_term",
		AggregateID:   term.TermID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}
