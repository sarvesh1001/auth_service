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
	"auth-service/internal/encryption"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	salesErrors "auth-service/internal/sales/errors"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/repository"
)

// SalesRepService defines the interface for sales representative operations.
// All mutating methods are idempotent using a key extracted from the context.
type SalesRepService interface {
	CreateSalesRep(ctx context.Context, req *CreateSalesRepRequest) (*models.SalesRep, error)
	UpdateSalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, req *UpdateSalesRepRequest) (*models.SalesRep, error)
	DeleteSalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, deletedBy uuid.UUID) error
	GetSalesRepByID(ctx context.Context, companyID, salesRepID uuid.UUID) (*models.SalesRep, error)
	GetSalesRepByUserID(ctx context.Context, companyID, userID uuid.UUID) (*models.SalesRep, error)
	GetSalesRepByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.SalesRep, error)
	ListSalesReps(ctx context.Context, filter SalesRepListFilter, p Pagination, s Sort) ([]*models.SalesRep, int64, error)
	SearchSalesReps(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.SalesRep, int64, error)
	GetActiveSalesReps(ctx context.Context, companyID uuid.UUID) ([]*models.SalesRep, error)
	ActivateSalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, updatedBy uuid.UUID) error
	DeactivateSalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, updatedBy uuid.UUID) error
	IsSalesRepActive(ctx context.Context, companyID, salesRepID uuid.UUID) (bool, error)
	AssignOrder(ctx context.Context, companyID, salesRepID, orderID uuid.UUID, assignedBy uuid.UUID) error
	RemoveOrderAssignment(ctx context.Context, companyID, salesRepID, orderID uuid.UUID, removedBy uuid.UUID) error
	GetAssignedOrders(ctx context.Context, companyID, salesRepID uuid.UUID, p Pagination, s Sort) ([]*models.Order, int64, error)
	AssignQuote(ctx context.Context, companyID, salesRepID, quoteID uuid.UUID, assignedBy uuid.UUID) error
	RemoveQuoteAssignment(ctx context.Context, companyID, salesRepID, quoteID uuid.UUID, removedBy uuid.UUID) error
	GetAssignedQuotes(ctx context.Context, companyID, salesRepID uuid.UUID, p Pagination, s Sort) ([]*models.Quote, int64, error)
	AssignInvoice(ctx context.Context, companyID, salesRepID, invoiceID uuid.UUID, assignedBy uuid.UUID) error
	RemoveInvoiceAssignment(ctx context.Context, companyID, salesRepID, invoiceID uuid.UUID, removedBy uuid.UUID) error
	GetAssignedInvoices(ctx context.Context, companyID, salesRepID uuid.UUID, p Pagination, s Sort) ([]*models.Invoice, int64, error)
	AssignCustomer(ctx context.Context, companyID, salesRepID, customerID uuid.UUID, assignedBy uuid.UUID) error
	RemoveCustomerAssignment(ctx context.Context, companyID, salesRepID, customerID uuid.UUID, removedBy uuid.UUID) error
	GetAssignedCustomers(ctx context.Context, companyID, salesRepID uuid.UUID, p Pagination, s Sort) ([]*models.Customer, int64, error)
	GetCustomerSalesRep(ctx context.Context, companyID, customerID uuid.UUID) (*models.SalesRep, error)
	SetCommissionPlan(ctx context.Context, companyID, salesRepID, commissionPlanID uuid.UUID, updatedBy uuid.UUID) error
	CalculateCommission(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetEarnedCommission(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetSalesRevenue(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetCollectedRevenue(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetAverageDealSize(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetConversionRate(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTopSalesReps(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.SalesRep, error)
	GetSalesRepLeaderboard(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*SalesRepLeaderboardEntry, error)
	SetSalesTarget(ctx context.Context, companyID, salesRepID uuid.UUID, req *SetSalesTargetRequest, updatedBy uuid.UUID) error
	GetSalesTarget(ctx context.Context, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time) (*models.SalesTarget, error)
	ValidateSalesRep(ctx context.Context, rep *models.SalesRep) error
	ValidateAssignment(ctx context.Context, companyID, salesRepID uuid.UUID, entityType string, entityID uuid.UUID) error
	CanManageCustomer(ctx context.Context, companyID, salesRepID, customerID uuid.UUID) (bool, error)
	SalesRepExists(ctx context.Context, companyID, salesRepID uuid.UUID) (bool, error)
	SalesRepCodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
	UserAlreadyLinked(ctx context.Context, companyID, userID uuid.UUID) (bool, error)
}

type salesRepService struct {
	repRepo          repository.SalesRepRepository
	orderRepo        repository.OrderRepository
	quoteRepo        repository.QuoteRepository
	invoiceRepo      repository.InvoiceRepository
	commissionRepo   repository.SalesRepCommissionRepository
	targetRepo       repository.SalesTargetRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	encryptionMgr    *encryption.EncryptionManager
	logger           *zap.Logger
}

func NewSalesRepService(
	repRepo repository.SalesRepRepository,
	orderRepo repository.OrderRepository,
	quoteRepo repository.QuoteRepository,
	invoiceRepo repository.InvoiceRepository,
	commissionRepo repository.SalesRepCommissionRepository,
	targetRepo repository.SalesTargetRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	encryptionMgr *encryption.EncryptionManager,
	logger *zap.Logger,
) SalesRepService {
	return &salesRepService{
		repRepo:          repRepo,
		orderRepo:        orderRepo,
		quoteRepo:        quoteRepo,
		invoiceRepo:      invoiceRepo,
		commissionRepo:   commissionRepo,
		targetRepo:       targetRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		encryptionMgr:    encryptionMgr,
		logger:           logger.Named("sales_rep_service"),
	}
}

// Helper to get idempotency key from context, generating a fallback if missing.
func (s *salesRepService) getIdempotencyKey(ctx context.Context) string {
	key, _ := ctx.Value("idempotency_key").(string)
	if key == "" {
		key = uuid.New().String()
	}
	return key
}

// ----------------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------------

func (s *salesRepService) validateCreateSalesRep(req *CreateSalesRepRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.Code == "" {
		return fmt.Errorf("%w: code required", salesErrors.ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name required", salesErrors.ErrInvalidInput)
	}
	if req.UserID == uuid.Nil {
		return fmt.Errorf("%w: user_id required", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *salesRepService) validateSalesRepInput(name string, email *string) error {
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: name must not exceed %d characters", salesErrors.ErrInvalidInput, maxNameLen)
	}
	if email != nil && *email != "" {
		if len(*email) > maxEmailLen {
			return fmt.Errorf("%w: email must not exceed %d characters", salesErrors.ErrInvalidInput, maxEmailLen)
		}
		if !isValidEmail(*email) {
			return fmt.Errorf("%w: invalid email format", salesErrors.ErrInvalidInput)
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Encryption helpers
// ----------------------------------------------------------------------------

func (s *salesRepService) encryptField(ctx context.Context, plainText *string, fieldName string) (encrypted, dek, keyID *string, err error) {
	if plainText == nil || *plainText == "" {
		return nil, nil, nil, nil
	}
	enc, err := s.encryptionMgr.EncryptField(ctx, *plainText, fieldName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encrypt %s: %w", fieldName, err)
	}
	return &enc.EncryptedValue, &enc.EncryptedDEK, &enc.KeyID, nil
}

func (s *salesRepService) decryptField(ctx context.Context, encrypted, dek, keyID *string) (string, error) {
	if encrypted == nil || *encrypted == "" || dek == nil || keyID == nil {
		return "", nil
	}
	encData := &encryption.EncryptedData{
		EncryptedValue: *encrypted,
		EncryptedDEK:   *dek,
		KeyID:          *keyID,
	}
	return s.encryptionMgr.DecryptField(ctx, encData)
}

func (s *salesRepService) decryptSalesRep(ctx context.Context, rep *models.SalesRep) error {
	if rep == nil {
		return nil
	}
	if rep.EmailEncrypted != nil && rep.EmailDEK != nil && rep.EmailKeyID != nil {
		plain, err := s.decryptField(ctx, rep.EmailEncrypted, rep.EmailDEK, rep.EmailKeyID)
		if err != nil {
			return fmt.Errorf("decrypt email: %w", err)
		}
		if plain != "" {
			rep.Email = &plain
		}
	}
	if rep.PhoneEncrypted != nil && rep.PhoneDEK != nil && rep.PhoneKeyID != nil {
		plain, err := s.decryptField(ctx, rep.PhoneEncrypted, rep.PhoneDEK, rep.PhoneKeyID)
		if err != nil {
			return fmt.Errorf("decrypt phone: %w", err)
		}
		if plain != "" {
			rep.Phone = &plain
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// CRUD operations (idempotent) – unchanged
// ----------------------------------------------------------------------------

func (s *salesRepService) CreateSalesRep(ctx context.Context, req *CreateSalesRepRequest) (*models.SalesRep, error) {
	logger := s.logger.With(zap.String("method", "CreateSalesRep"))
	if err := s.validateCreateSalesRep(req); err != nil {
		return nil, err
	}
	if err := s.validateSalesRepInput(req.Name, req.Email); err != nil {
		return nil, err
	}

	idempotencyKey := s.getIdempotencyKey(ctx)
	logger = logger.With(zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.SalesRep
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		if cached.SalesRepID != uuid.Nil {
			logger.Info("idempotent – returning cached sales rep")
			_ = s.decryptSalesRep(ctx, cached)
			return cached, nil
		}
		logger.Warn("idempotent cache returned zero object – continuing")
	}

	userExists, err := s.repRepo.UserExists(ctx, tx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("check user existence: %w", err)
	}
	if !userExists {
		return nil, fmt.Errorf("%w: user_id does not exist", salesErrors.ErrInvalidInput)
	}

	codeExists, err := s.repRepo.ExistsByCode(ctx, tx, req.CompanyID, req.Code)
	if err != nil {
		return nil, fmt.Errorf("check code existence: %w", err)
	}
	if codeExists {
		return nil, fmt.Errorf("%w: code %s already exists", salesErrors.ErrDuplicate, req.Code)
	}

	linked, err := s.repRepo.ExistsByUserID(ctx, tx, req.CompanyID, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("check user linked: %w", err)
	}
	if linked {
		return nil, fmt.Errorf("%w: user %s already linked to a sales rep", salesErrors.ErrDuplicate, req.UserID)
	}

	var emailHash *string
	if req.Email != nil && *req.Email != "" {
		hash := hashEmail(*req.Email)
		hashExists, err := s.repRepo.ExistsByEmailHash(ctx, tx, req.CompanyID, hash)
		if err != nil {
			return nil, fmt.Errorf("check email hash: %w", err)
		}
		if hashExists {
			return nil, fmt.Errorf("%w: email already in use", salesErrors.ErrDuplicate)
		}
		emailHash = &hash
	}

	emailEncrypted, emailDEK, emailKeyID, err := s.encryptField(ctx, req.Email, "sales_rep_email")
	if err != nil {
		return nil, err
	}
	phoneEncrypted, phoneDEK, phoneKeyID, err := s.encryptField(ctx, req.Phone, "sales_rep_phone")
	if err != nil {
		return nil, err
	}

	rep := &models.SalesRep{
		SalesRepID:     uuid.New(),
		CompanyID:      req.CompanyID,
		UserID:         req.UserID,
		Code:           req.Code,
		Name:           req.Name,
		EmailEncrypted: emailEncrypted,
		EmailDEK:       emailDEK,
		EmailKeyID:     emailKeyID,
		EmailHash:      emailHash,
		PhoneEncrypted: phoneEncrypted,
		PhoneDEK:       phoneDEK,
		PhoneKeyID:     phoneKeyID,
		IsActive:       true,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.CreatedBy,
	}

	if err := s.repRepo.Create(ctx, tx, rep); err != nil {
		return nil, fmt.Errorf("create sales rep: %w", err)
	}

	if err := s.emitEvent(ctx, tx, rep, salesEvents.EventSalesRepCreated); err != nil {
		logger.Warn("failed to emit sales rep created event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, rep); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	_ = s.decryptSalesRep(ctx, rep)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_sales_rep", "sales_rep",
			&rep.SalesRepID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"code": rep.Code,
				"name": rep.Name,
			})
	}
	return rep, nil
}

func (s *salesRepService) UpdateSalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, req *UpdateSalesRepRequest) (*models.SalesRep, error) {
	logger := s.logger.With(zap.String("method", "UpdateSalesRep"))
	if companyID == uuid.Nil || salesRepID == uuid.Nil {
		return nil, salesErrors.ErrInvalidInput
	}
	if req.Name != nil {
		if err := s.validateSalesRepInput(*req.Name, req.Email); err != nil {
			return nil, err
		}
	} else if req.Email != nil {
		if err := s.validateSalesRepInput("dummy", req.Email); err != nil {
			return nil, err
		}
	}

	idempotencyKey := s.getIdempotencyKey(ctx)
	logger = logger.With(zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.SalesRep
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		if cached.SalesRepID != uuid.Nil {
			logger.Info("idempotent – returning cached sales rep")
			_ = s.decryptSalesRep(ctx, cached)
			return cached, nil
		}
		logger.Warn("idempotent cache returned zero object – continuing")
	}

	rep, err := s.repRepo.GetByIDForUpdate(ctx, tx, companyID, salesRepID)
	if err != nil {
		return nil, err
	}
	if rep.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}

	changes := make(map[string]interface{})

	if req.Name != nil && *req.Name != rep.Name {
		changes["name"] = map[string]string{"old": rep.Name, "new": *req.Name}
		rep.Name = *req.Name
	}

	if req.Email != nil {
		newHash := hashEmail(*req.Email)
		hashExists, err := s.repRepo.ExistsByEmailHashExcluding(ctx, tx, companyID, newHash, salesRepID)
		if err != nil {
			return nil, fmt.Errorf("check email uniqueness: %w", err)
		}
		if hashExists {
			return nil, fmt.Errorf("%w: email already in use", salesErrors.ErrDuplicate)
		}
		encrypted, dek, kid, err := s.encryptField(ctx, req.Email, "sales_rep_email")
		if err != nil {
			return nil, err
		}
		oldPlain, _ := s.decryptField(ctx, rep.EmailEncrypted, rep.EmailDEK, rep.EmailKeyID)
		changes["email"] = map[string]string{"old": oldPlain, "new": *req.Email}
		rep.EmailEncrypted = encrypted
		rep.EmailDEK = dek
		rep.EmailKeyID = kid
		rep.EmailHash = &newHash
	}

	if req.Phone != nil {
		encrypted, dek, kid, err := s.encryptField(ctx, req.Phone, "sales_rep_phone")
		if err != nil {
			return nil, err
		}
		oldPlain, _ := s.decryptField(ctx, rep.PhoneEncrypted, rep.PhoneDEK, rep.PhoneKeyID)
		changes["phone"] = map[string]string{"old": oldPlain, "new": *req.Phone}
		rep.PhoneEncrypted = encrypted
		rep.PhoneDEK = dek
		rep.PhoneKeyID = kid
	}

	if req.IsActive != nil && *req.IsActive != rep.IsActive {
		changes["is_active"] = map[string]bool{"old": rep.IsActive, "new": *req.IsActive}
		rep.IsActive = *req.IsActive
	}

	rep.UpdatedBy = req.UpdatedBy

	if err := s.repRepo.Update(ctx, tx, rep); err != nil {
		return nil, fmt.Errorf("update sales rep: %w", err)
	}

	if err := s.emitEvent(ctx, tx, rep, salesEvents.EventSalesRepUpdated); err != nil {
		logger.Warn("failed to emit sales rep updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, rep); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	_ = s.decryptSalesRep(ctx, rep)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_sales_rep", "sales_rep",
			&salesRepID, "user", req.UpdatedBy, nil, nil, changes)
	}
	return rep, nil
}

func (s *salesRepService) DeleteSalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteSalesRep"))
	idempotencyKey := s.getIdempotencyKey(ctx)
	logger = logger.With(zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}

	rep, err := s.repRepo.GetByID(ctx, tx, companyID, salesRepID)
	if err != nil {
		return err
	}
	if rep.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}

	var hasDeps bool
	err = tx.QueryRowContext(ctx, `
        SELECT EXISTS(
            SELECT 1 FROM sales.orders WHERE company_id=$1 AND sales_rep_id=$2 LIMIT 1
        ) OR EXISTS(
            SELECT 1 FROM sales.quotes WHERE company_id=$1 AND sales_rep_id=$2 LIMIT 1
        ) OR EXISTS(
            SELECT 1 FROM sales.invoices WHERE company_id=$1 AND sales_rep_id=$2 LIMIT 1
        )`, companyID, salesRepID).Scan(&hasDeps)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("check dependencies: %w", err)
	}

	if hasDeps {
		if err := s.repRepo.SetActiveStatus(ctx, tx, companyID, salesRepID, false, &deletedBy); err != nil {
			return fmt.Errorf("deactivate sales rep: %w", err)
		}
		logger.Info("sales rep has dependencies, deactivated instead of hard delete")
	} else {
		if err := s.repRepo.Delete(ctx, tx, companyID, salesRepID); err != nil {
			return fmt.Errorf("delete sales rep: %w", err)
		}
	}

	if err := s.emitEvent(ctx, tx, rep, salesEvents.EventSalesRepDeleted); err != nil {
		logger.Warn("failed to emit delete event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_sales_rep", "sales_rep",
			&salesRepID, "user", &deletedBy, nil, nil, map[string]interface{}{"had_dependencies": hasDeps})
	}
	return nil
}

// ----------------------------------------------------------------------------
// Read operations – now use read‑only transactions
// ----------------------------------------------------------------------------

func (s *salesRepService) GetSalesRepByID(ctx context.Context, companyID, salesRepID uuid.UUID) (*models.SalesRep, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	rep, err := s.repRepo.GetByID(ctx, tx, companyID, salesRepID)
	if err != nil {
		return nil, err
	}
	_ = s.decryptSalesRep(ctx, rep)
	return rep, nil
}

func (s *salesRepService) GetSalesRepByUserID(ctx context.Context, companyID, userID uuid.UUID) (*models.SalesRep, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	rep, err := s.repRepo.GetByUserID(ctx, tx, companyID, userID)
	if err != nil {
		return nil, err
	}
	_ = s.decryptSalesRep(ctx, rep)
	return rep, nil
}

func (s *salesRepService) GetSalesRepByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.SalesRep, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	rep, err := s.repRepo.GetByCode(ctx, tx, companyID, code)
	if err != nil {
		return nil, err
	}
	_ = s.decryptSalesRep(ctx, rep)
	return rep, nil
}

func (s *salesRepService) ListSalesReps(ctx context.Context, filter SalesRepListFilter, p Pagination, srt Sort) ([]*models.SalesRep, int64, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	repoFilter := repository.SalesRepFilter{
		CompanyID:   filter.CompanyID,
		IsActive:    filter.IsActive,
		SalesRepIDs: filter.SalesRepIDs,
		Code:        filter.Code,
		Name:        filter.Name,
		UserID:      filter.UserID,
	}
	reps, total, err := s.repRepo.List(ctx, tx, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
	if err != nil {
		return nil, 0, err
	}
	for _, r := range reps {
		_ = s.decryptSalesRep(ctx, r)
	}
	return reps, total, nil
}

func (s *salesRepService) SearchSalesReps(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.SalesRep, int64, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	reps, total, err := s.repRepo.Search(ctx, tx, companyID, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	for _, r := range reps {
		_ = s.decryptSalesRep(ctx, r)
	}
	return reps, total, nil
}

func (s *salesRepService) GetActiveSalesReps(ctx context.Context, companyID uuid.UUID) ([]*models.SalesRep, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	reps, err := s.repRepo.GetActiveSalesReps(ctx, tx, companyID)
	if err != nil {
		return nil, err
	}
	for _, r := range reps {
		_ = s.decryptSalesRep(ctx, r)
	}
	return reps, nil
}

// ----------------------------------------------------------------------------
// Activation / deactivation (idempotent) – unchanged (use read/write tx)
// ----------------------------------------------------------------------------

func (s *salesRepService) ActivateSalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, updatedBy uuid.UUID) error {
	return s.setActiveStatus(ctx, companyID, salesRepID, true, updatedBy)
}

func (s *salesRepService) DeactivateSalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, updatedBy uuid.UUID) error {
	return s.setActiveStatus(ctx, companyID, salesRepID, false, updatedBy)
}

func (s *salesRepService) setActiveStatus(ctx context.Context, companyID, salesRepID uuid.UUID, active bool, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "setActiveStatus"))
	idempotencyKey := s.getIdempotencyKey(ctx)
	logger = logger.With(zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – status already updated")
		return nil
	}

	if err := s.repRepo.SetActiveStatus(ctx, tx, companyID, salesRepID, active, &updatedBy); err != nil {
		return err
	}

	rep, _ := s.repRepo.GetByID(ctx, tx, companyID, salesRepID)
	if rep != nil {
		eventType := salesEvents.EventSalesRepDeactivated
		if active {
			eventType = salesEvents.EventSalesRepActivated
		}
		_ = s.emitEvent(ctx, tx, rep, eventType)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	return tx.Commit()
}

func (s *salesRepService) IsSalesRepActive(ctx context.Context, companyID, salesRepID uuid.UUID) (bool, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	return s.repRepo.IsActive(ctx, tx, companyID, salesRepID)
}

// ----------------------------------------------------------------------------
// Assignment helpers (idempotent) – unchanged (use read/write tx)
// ----------------------------------------------------------------------------

func (s *salesRepService) assignEntity(ctx context.Context, companyID, salesRepID, entityID uuid.UUID, entityType string, assignedBy uuid.UUID, updateFunc func(*sql.Tx) error) error {
	logger := s.logger.With(zap.String("method", "assignEntity"), zap.String("entity_type", entityType))
	idempotencyKey := s.getIdempotencyKey(ctx)
	logger = logger.With(zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – assignment already performed")
		return nil
	}

	active, err := s.repRepo.IsActive(ctx, tx, companyID, salesRepID)
	if err != nil {
		return err
	}
	if !active {
		return fmt.Errorf("%w: sales rep is not active", salesErrors.ErrInvalidInput)
	}

	if err := updateFunc(tx); err != nil {
		return fmt.Errorf("assign %s: %w", entityType, err)
	}

	rep, _ := s.repRepo.GetByID(ctx, tx, companyID, salesRepID)
	if rep != nil {
		payload := map[string]interface{}{
			"sales_rep_id": salesRepID.String(),
			"company_id":   companyID.String(),
			"entity_type":  entityType,
			"entity_id":    entityID.String(),
			"assigned_by":  assignedBy.String(),
		}
		data, _ := json.Marshal(payload)
		event := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "sales_rep_assignment",
			AggregateID:   salesRepID.String(),
			EventType:     salesEvents.EventSalesRepAssigned,
			Topic:         salesEvents.TopicSalesEvents,
			Payload:       data,
		}
		_ = s.outboxRepo.Store(ctx, tx, event)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	return tx.Commit()
}

func (s *salesRepService) removeAssignment(ctx context.Context, companyID, salesRepID, entityID uuid.UUID, entityType string, removedBy uuid.UUID, updateFunc func(*sql.Tx) error) error {
	logger := s.logger.With(zap.String("method", "removeAssignment"), zap.String("entity_type", entityType))
	idempotencyKey := s.getIdempotencyKey(ctx)
	logger = logger.With(zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – removal already performed")
		return nil
	}

	if err := updateFunc(tx); err != nil {
		return fmt.Errorf("remove %s assignment: %w", entityType, err)
	}

	rep, _ := s.repRepo.GetByID(ctx, tx, companyID, salesRepID)
	if rep != nil {
		payload := map[string]interface{}{
			"sales_rep_id": salesRepID.String(),
			"company_id":   companyID.String(),
			"entity_type":  entityType,
			"entity_id":    entityID.String(),
			"removed_by":   removedBy.String(),
		}
		data, _ := json.Marshal(payload)
		event := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "sales_rep_assignment",
			AggregateID:   salesRepID.String(),
			EventType:     salesEvents.EventSalesRepUnassigned,
			Topic:         salesEvents.TopicSalesEvents,
			Payload:       data,
		}
		_ = s.outboxRepo.Store(ctx, tx, event)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Assignment implementations
// ----------------------------------------------------------------------------

func (s *salesRepService) AssignOrder(ctx context.Context, companyID, salesRepID, orderID uuid.UUID, assignedBy uuid.UUID) error {
	return s.assignEntity(ctx, companyID, salesRepID, orderID, "order", assignedBy, func(tx *sql.Tx) error {
		order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
		if err != nil {
			return err
		}
		order.SalesRepID = &salesRepID
		order.UpdatedBy = &assignedBy
		return s.orderRepo.Update(ctx, tx, order)
	})
}

func (s *salesRepService) RemoveOrderAssignment(ctx context.Context, companyID, salesRepID, orderID uuid.UUID, removedBy uuid.UUID) error {
	return s.removeAssignment(ctx, companyID, salesRepID, orderID, "order", removedBy, func(tx *sql.Tx) error {
		order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
		if err != nil {
			return err
		}
		order.SalesRepID = nil
		order.UpdatedBy = &removedBy
		return s.orderRepo.Update(ctx, tx, order)
	})
}

func (s *salesRepService) GetAssignedOrders(ctx context.Context, companyID, salesRepID uuid.UUID, p Pagination, srt Sort) ([]*models.Order, int64, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	filter := repository.OrderFilter{
		CompanyID:  companyID,
		SalesRepID: &salesRepID,
	}
	return s.orderRepo.List(ctx, tx, filter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *salesRepService) AssignQuote(ctx context.Context, companyID, salesRepID, quoteID uuid.UUID, assignedBy uuid.UUID) error {
	return s.assignEntity(ctx, companyID, salesRepID, quoteID, "quote", assignedBy, func(tx *sql.Tx) error {
		quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
		if err != nil {
			return err
		}
		quote.SalesRepID = &salesRepID
		quote.UpdatedBy = &assignedBy
		return s.quoteRepo.Update(ctx, tx, quote)
	})
}

func (s *salesRepService) RemoveQuoteAssignment(ctx context.Context, companyID, salesRepID, quoteID uuid.UUID, removedBy uuid.UUID) error {
	return s.removeAssignment(ctx, companyID, salesRepID, quoteID, "quote", removedBy, func(tx *sql.Tx) error {
		quote, err := s.quoteRepo.GetByIDForUpdate(ctx, tx, companyID, quoteID)
		if err != nil {
			return err
		}
		quote.SalesRepID = nil
		quote.UpdatedBy = &removedBy
		return s.quoteRepo.Update(ctx, tx, quote)
	})
}

func (s *salesRepService) GetAssignedQuotes(ctx context.Context, companyID, salesRepID uuid.UUID, p Pagination, srt Sort) ([]*models.Quote, int64, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	filter := repository.QuoteFilter{
		CompanyID:  companyID,
		SalesRepID: &salesRepID,
	}
	return s.quoteRepo.List(ctx, tx, filter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *salesRepService) AssignInvoice(ctx context.Context, companyID, salesRepID, invoiceID uuid.UUID, assignedBy uuid.UUID) error {
	return s.assignEntity(ctx, companyID, salesRepID, invoiceID, "invoice", assignedBy, func(tx *sql.Tx) error {
		invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
		if err != nil {
			return err
		}
		invoice.SalesRepID = &salesRepID
		invoice.UpdatedBy = &assignedBy
		return s.invoiceRepo.Update(ctx, tx, invoice)
	})
}

func (s *salesRepService) RemoveInvoiceAssignment(ctx context.Context, companyID, salesRepID, invoiceID uuid.UUID, removedBy uuid.UUID) error {
	return s.removeAssignment(ctx, companyID, salesRepID, invoiceID, "invoice", removedBy, func(tx *sql.Tx) error {
		invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
		if err != nil {
			return err
		}
		invoice.SalesRepID = nil
		invoice.UpdatedBy = &removedBy
		return s.invoiceRepo.Update(ctx, tx, invoice)
	})
}

func (s *salesRepService) GetAssignedInvoices(ctx context.Context, companyID, salesRepID uuid.UUID, p Pagination, srt Sort) ([]*models.Invoice, int64, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	filter := repository.InvoiceFilter{
		CompanyID:  companyID,
		SalesRepID: &salesRepID,
	}
	return s.invoiceRepo.List(ctx, tx, filter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

// ----------------------------------------------------------------------------
// Commission plan (idempotent) – unchanged
// ----------------------------------------------------------------------------

func (s *salesRepService) SetCommissionPlan(ctx context.Context, companyID, salesRepID, commissionPlanID uuid.UUID, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "SetCommissionPlan"))
	idempotencyKey := s.getIdempotencyKey(ctx)
	logger = logger.With(zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – commission plan already set")
		return nil
	}

	comm, err := s.commissionRepo.GetByID(ctx, tx, companyID, commissionPlanID)
	if err != nil {
		return err
	}
	if comm.CompanyID != companyID || comm.SalesRepID != salesRepID {
		return fmt.Errorf("%w: commission plan not owned by this sales rep", salesErrors.ErrInvalidInput)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Commission calculation – now use read‑only transactions
// ----------------------------------------------------------------------------

func (s *salesRepService) CalculateCommission(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	return s.commissionRepo.GetTotalCommissionAmount(ctx, tx, companyID, &salesRepID, from, to)
}

func (s *salesRepService) GetEarnedCommission(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.CalculateCommission(ctx, companyID, salesRepID, from, to)
}

func (s *salesRepService) GetSalesRevenue(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	var total decimal.Decimal
	query := `SELECT COALESCE(SUM(grand_total), 0) FROM sales.orders WHERE company_id=$1 AND sales_rep_id=$2`
	args := []interface{}{companyID, salesRepID}
	if from != nil {
		query += ` AND order_date >= $3`
		args = append(args, *from)
	}
	if to != nil {
		query += ` AND order_date <= $4`
		args = append(args, *to)
	}
	err = tx.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil && err != sql.ErrNoRows {
		return decimal.Zero, fmt.Errorf("get sales revenue: %w", err)
	}
	return total, nil
}

func (s *salesRepService) GetCollectedRevenue(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	var total decimal.Decimal
	query := `
        SELECT COALESCE(SUM(p.amount), 0)
        FROM sales.payments p
        JOIN sales.payment_allocations pa ON pa.payment_id = p.payment_id
        JOIN sales.invoices i ON i.invoice_id = pa.invoice_id
        JOIN sales.orders o ON o.order_id = i.order_id
        WHERE p.company_id=$1 AND o.sales_rep_id=$2 AND p.status='completed'
    `
	args := []interface{}{companyID, salesRepID}
	if from != nil {
		query += ` AND p.payment_date >= $3`
		args = append(args, *from)
	}
	if to != nil {
		query += ` AND p.payment_date <= $4`
		args = append(args, *to)
	}
	err = tx.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil && err != sql.ErrNoRows {
		return decimal.Zero, fmt.Errorf("get collected revenue: %w", err)
	}
	return total, nil
}

func (s *salesRepService) GetAverageDealSize(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	var avg decimal.Decimal
	query := `SELECT COALESCE(AVG(grand_total), 0) FROM sales.orders WHERE company_id=$1 AND sales_rep_id=$2`
	args := []interface{}{companyID, salesRepID}
	if from != nil {
		query += ` AND order_date >= $3`
		args = append(args, *from)
	}
	if to != nil {
		query += ` AND order_date <= $4`
		args = append(args, *to)
	}
	err = tx.QueryRowContext(ctx, query, args...).Scan(&avg)
	if err != nil && err != sql.ErrNoRows {
		return decimal.Zero, fmt.Errorf("get average deal size: %w", err)
	}
	return avg, nil
}

func (s *salesRepService) GetConversionRate(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	var ordersCount, quotesCount int64
	orderQuery := `SELECT COUNT(*) FROM sales.orders WHERE company_id=$1 AND sales_rep_id=$2`
	quoteQuery := `SELECT COUNT(*) FROM sales.quotes WHERE company_id=$1 AND sales_rep_id=$2`
	args := []interface{}{companyID, salesRepID}
	if from != nil {
		orderQuery += ` AND order_date >= $3`
		quoteQuery += ` AND created_at >= $3`
		args = append(args, *from)
	}
	if to != nil {
		orderQuery += ` AND order_date <= $4`
		quoteQuery += ` AND created_at <= $4`
		args = append(args, *to)
	}
	err = tx.QueryRowContext(ctx, orderQuery, args...).Scan(&ordersCount)
	if err != nil && err != sql.ErrNoRows {
		return decimal.Zero, err
	}
	err = tx.QueryRowContext(ctx, quoteQuery, args...).Scan(&quotesCount)
	if err != nil && err != sql.ErrNoRows {
		return decimal.Zero, err
	}
	if quotesCount == 0 {
		return decimal.Zero, nil
	}
	rate := decimal.NewFromInt(ordersCount).Div(decimal.NewFromInt(quotesCount)).Mul(decimal.NewFromInt(100))
	return rate, nil
}

// ----------------------------------------------------------------------------
// Leaderboard & top reps
// ----------------------------------------------------------------------------

func (s *salesRepService) GetTopSalesReps(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.SalesRep, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	reps, err := s.repRepo.GetTopSalesRepsByRevenue(ctx, tx, companyID, limit, from, to)
	if err != nil {
		return nil, err
	}
	for _, r := range reps {
		_ = s.decryptSalesRep(ctx, r)
	}
	return reps, nil
}

func (s *salesRepService) GetSalesRepLeaderboard(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*SalesRepLeaderboardEntry, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	query := `
        SELECT
            sr.sales_rep_id, sr.code, sr.name,
            COALESCE(SUM(o.grand_total), 0) as total_revenue,
            COUNT(o.order_id) as total_orders,
            COALESCE(AVG(o.grand_total), 0) as avg_deal
        FROM sales.sales_reps sr
        LEFT JOIN sales.orders o ON o.sales_rep_id = sr.sales_rep_id AND o.company_id = sr.company_id
        WHERE sr.company_id = $1 AND sr.is_active = true
    `
	args := []interface{}{companyID}
	if from != nil {
		query += ` AND o.order_date >= $2`
		args = append(args, *from)
	}
	if to != nil {
		query += ` AND o.order_date <= $3`
		args = append(args, *to)
	}
	query += ` GROUP BY sr.sales_rep_id ORDER BY total_revenue DESC`

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*SalesRepLeaderboardEntry
	for rows.Next() {
		var e SalesRepLeaderboardEntry
		if err := rows.Scan(&e.SalesRepID, &e.Code, &e.Name, &e.TotalRevenue, &e.TotalOrders, &e.AverageDeal); err != nil {
			return nil, err
		}
		entries = append(entries, &e)
	}
	return entries, nil
}

// ----------------------------------------------------------------------------
// Sales target (idempotent) – unchanged for writes, read uses read‑only tx
// ----------------------------------------------------------------------------

func (s *salesRepService) SetSalesTarget(ctx context.Context, companyID, salesRepID uuid.UUID, req *SetSalesTargetRequest, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "SetSalesTarget"))
	if companyID == uuid.Nil || salesRepID == uuid.Nil {
		return salesErrors.ErrInvalidInput
	}
	if req.PeriodStart.After(req.PeriodEnd) {
		return fmt.Errorf("%w: period_start must be before period_end", salesErrors.ErrInvalidInput)
	}

	idempotencyKey := s.getIdempotencyKey(ctx)
	logger = logger.With(zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – target already set")
		return nil
	}

	active, err := s.repRepo.IsActive(ctx, tx, companyID, salesRepID)
	if err != nil {
		return err
	}
	if !active {
		return fmt.Errorf("%w: sales rep is not active", salesErrors.ErrInvalidInput)
	}

	delQuery := `DELETE FROM sales.sales_targets WHERE company_id=$1 AND sales_rep_id=$2 AND period_start=$3 AND period_end=$4`
	if _, err := tx.ExecContext(ctx, delQuery, companyID, salesRepID, req.PeriodStart, req.PeriodEnd); err != nil {
		return fmt.Errorf("delete existing target: %w", err)
	}

	target := &models.SalesTarget{
		TargetID:     uuid.New(),
		CompanyID:    companyID,
		SalesRepID:   salesRepID,
		PeriodStart:  req.PeriodStart,
		PeriodEnd:    req.PeriodEnd,
		TargetAmount: req.TargetAmount,
		Currency:     "USD",
		CreatedBy:    &updatedBy,
		UpdatedBy:    &updatedBy,
	}
	if err := s.targetRepo.Create(ctx, tx, target); err != nil {
		return fmt.Errorf("create sales target: %w", err)
	}

	if err := s.emitSalesTargetEvent(ctx, tx, target, salesEvents.EventSalesTargetSet); err != nil {
		logger.Warn("failed to emit sales target event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "set_sales_target", "sales_target",
			&target.TargetID, "user", &updatedBy, nil, nil, map[string]interface{}{
				"sales_rep_id":  salesRepID.String(),
				"period_start":  req.PeriodStart,
				"period_end":    req.PeriodEnd,
				"target_amount": req.TargetAmount,
			})
	}
	return nil
}

func (s *salesRepService) GetSalesTarget(ctx context.Context, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time) (*models.SalesTarget, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	return s.targetRepo.GetByPeriod(ctx, tx, companyID, salesRepID, periodStart, periodEnd)
}

// ----------------------------------------------------------------------------
// Validation & existence
// ----------------------------------------------------------------------------

func (s *salesRepService) ValidateSalesRep(ctx context.Context, rep *models.SalesRep) error {
	if rep.Code == "" {
		return fmt.Errorf("%w: code required", salesErrors.ErrInvalidInput)
	}
	if rep.Name == "" {
		return fmt.Errorf("%w: name required", salesErrors.ErrInvalidInput)
	}
	if rep.UserID == uuid.Nil {
		return fmt.Errorf("%w: user_id required", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *salesRepService) ValidateAssignment(ctx context.Context, companyID, salesRepID uuid.UUID, entityType string, entityID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin read‑only tx: %w", err)
	}
	defer tx.Rollback()

	active, err := s.repRepo.IsActive(ctx, tx, companyID, salesRepID)
	if err != nil {
		return err
	}
	if !active {
		return fmt.Errorf("%w: sales rep is not active", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *salesRepService) CanManageCustomer(ctx context.Context, companyID, salesRepID, customerID uuid.UUID) (bool, error) {
	// Not implemented – remains unchanged
	return false, nil
}

func (s *salesRepService) SalesRepExists(ctx context.Context, companyID, salesRepID uuid.UUID) (bool, error) {
	return s.repRepo.Exists(ctx, s.pgClient.DB, companyID, salesRepID)
}

func (s *salesRepService) SalesRepCodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	return s.repRepo.ExistsByCode(ctx, s.pgClient.DB, companyID, code)
}

func (s *salesRepService) UserAlreadyLinked(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
	return s.repRepo.ExistsByUserID(ctx, s.pgClient.DB, companyID, userID)
}

// ----------------------------------------------------------------------------
// Customer assignment – not supported
// ----------------------------------------------------------------------------

func (s *salesRepService) AssignCustomer(ctx context.Context, companyID, salesRepID, customerID uuid.UUID, assignedBy uuid.UUID) error {
	return fmt.Errorf("customer assignment not supported: customer model lacks sales_rep_id column")
}

func (s *salesRepService) RemoveCustomerAssignment(ctx context.Context, companyID, salesRepID, customerID uuid.UUID, removedBy uuid.UUID) error {
	return fmt.Errorf("customer assignment removal not supported")
}

func (s *salesRepService) GetAssignedCustomers(ctx context.Context, companyID, salesRepID uuid.UUID, p Pagination, srt Sort) ([]*models.Customer, int64, error) {
	return nil, 0, fmt.Errorf("customer assignment not supported")
}

func (s *salesRepService) GetCustomerSalesRep(ctx context.Context, companyID, customerID uuid.UUID) (*models.SalesRep, error) {
	return nil, fmt.Errorf("customer sales rep not supported")
}

// ----------------------------------------------------------------------------
// Event emission helpers – unchanged
// ----------------------------------------------------------------------------

func (s *salesRepService) emitEvent(ctx context.Context, tx *sql.Tx, rep *models.SalesRep, eventType string) error {
	payload := map[string]interface{}{
		"sales_rep_id": rep.SalesRepID.String(),
		"company_id":   rep.CompanyID.String(),
		"code":         rep.Code,
		"name":         rep.Name,
		"is_active":    rep.IsActive,
	}
	if rep.UserID != uuid.Nil {
		payload["user_id"] = rep.UserID.String()
	}
	data, _ := json.Marshal(payload)
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "sales_rep",
		AggregateID:   rep.SalesRepID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func (s *salesRepService) emitSalesTargetEvent(ctx context.Context, tx *sql.Tx, target *models.SalesTarget, eventType string) error {
	payload := map[string]interface{}{
		"target_id":     target.TargetID.String(),
		"company_id":    target.CompanyID.String(),
		"sales_rep_id":  target.SalesRepID.String(),
		"period_start":  target.PeriodStart,
		"period_end":    target.PeriodEnd,
		"target_amount": target.TargetAmount,
	}
	data, _ := json.Marshal(payload)
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "sales_target",
		AggregateID:   target.TargetID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
