package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// --------------------------------------------------------------------------
// Interface
// --------------------------------------------------------------------------

type AccountService interface {
	CreateAccount(ctx context.Context, req CreateAccountRequest, idempotencyKey string) (*models.Account, error)
	BulkCreateAccounts(ctx context.Context, req BulkCreateAccountsRequest, idempotencyKey string) error
	UpdateAccount(ctx context.Context, req UpdateAccountRequest, idempotencyKey string) (*models.Account, error)
	UpdateAccountStatus(ctx context.Context, companyID, accountID uuid.UUID, isActive bool, updatedBy *uuid.UUID, idempotencyKey string) error
	MoveAccount(ctx context.Context, companyID, accountID uuid.UUID, newParentID *uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	DeleteAccount(ctx context.Context, companyID, accountID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error
	GetAccount(ctx context.Context, accountID uuid.UUID) (*models.Account, error)
	GetAccountByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Account, error)
	ListAccounts(ctx context.Context, filter repository.AccountFilter, page, pageSize int, sort repository.Sort) ([]*models.Account, int64, error)
	GetAccountTree(ctx context.Context, companyID uuid.UUID) ([]*repository.AccountTreeNode, error)
	GetChildren(ctx context.Context, parentID uuid.UUID) ([]*models.Account, error)
	HasChildren(ctx context.Context, accountID uuid.UUID) (bool, error)
	CheckAccountUsage(ctx context.Context, accountID uuid.UUID) (bool, error)
	CheckCircularReference(ctx context.Context, accountID uuid.UUID, parentID *uuid.UUID) (bool, error)
	ValidatePostingAccount(ctx context.Context, companyID, accountID uuid.UUID) error
}

// --------------------------------------------------------------------------
// Service struct
// --------------------------------------------------------------------------

type accountService struct {
	repo             repository.AccountRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewAccountService(
	repo repository.AccountRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) AccountService {
	return &accountService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("account_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// --------------------------------------------------------------------------
// CreateAccount
// --------------------------------------------------------------------------

func (s *accountService) CreateAccount(ctx context.Context, req CreateAccountRequest, idempotencyKey string) (*models.Account, error) {
	logger := s.logger.With(
		zap.String("method", "CreateAccount"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("account_code", req.AccountCode),
		zap.String("idempotency_key", idempotencyKey),
	)

	if err := s.validateCreateRequest(&req); err != nil {
		return nil, err
	}
	if idempotencyKey == "" {
		return nil, ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var existing *models.Account
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
		logger.Info("idempotent request – returning cached account")
		return existing, nil
	}

	exists, err := s.repo.ExistsByCode(ctx, tx, req.CompanyID, req.AccountCode)
	if err != nil {
		return nil, fmt.Errorf("check duplicate code: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: account code %s already exists", ErrDuplicate, req.AccountCode)
	}

	if req.ParentAccountID != nil {
		parent, err := s.repo.GetByID(ctx, tx, *req.ParentAccountID)
		if err != nil {
			return nil, fmt.Errorf("get parent account: %w", err)
		}
		if parent == nil {
			return nil, fmt.Errorf("parent account does not exist")
		}
		if parent.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("parent account belongs to different company")
		}
		if req.AccountType != parent.AccountType {
			return nil, fmt.Errorf("invalid hierarchy: %s cannot be under %s", req.AccountType, parent.AccountType)
		}
		circular, err := s.repo.CheckCircularReference(ctx, tx, req.AccountID, req.ParentAccountID)
		if err != nil {
			return nil, fmt.Errorf("check circular reference: %w", err)
		}
		if circular {
			return nil, fmt.Errorf("%w: circular reference detected", ErrInvalidInput)
		}
	}

	account := &models.Account{
		AccountID:       req.AccountID,
		CompanyID:       req.CompanyID,
		AccountCode:     req.AccountCode,
		AccountName:     req.AccountName,
		AccountType:     req.AccountType,
		ParentAccountID: req.ParentAccountID,
		IsActive:        req.IsActive,
		Description:     req.Description,
		CreatedBy:       req.CreatedBy,
		UpdatedBy:       req.CreatedBy,
	}

	if err := s.repo.Create(ctx, tx, account); err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return nil, fmt.Errorf("%w: account code %s already exists", ErrDuplicate, req.AccountCode)
		}
		return nil, fmt.Errorf("create account: %w", err)
	}

	if err := s.emitAccountEvent(ctx, tx, account, events.EventAccountCreated); err != nil {
		logger.Warn("failed to emit account created event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, account)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "account", "create", "account",
			&account.AccountID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"account_code": account.AccountCode,
				"account_type": account.AccountType,
			})
	}
	logger.Info("account created", zap.String("account_id", account.AccountID.String()))
	return account, nil
}

// --------------------------------------------------------------------------
// BulkCreateAccounts (assumes req.Accounts is []*CreateAccountRequest)
// --------------------------------------------------------------------------

func (s *accountService) BulkCreateAccounts(ctx context.Context, req BulkCreateAccountsRequest, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "BulkCreateAccounts"),
		zap.Int("count", len(req.Accounts)),
		zap.String("idempotency_key", idempotencyKey),
	)

	if len(req.Accounts) == 0 {
		return nil
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent request – already processed")
		return nil
	}

	accounts := make([]*models.Account, 0, len(req.Accounts))

	// req.Accounts is slice of pointers
	for _, r := range req.Accounts {
		if err := s.validateCreateRequest(r); err != nil {
			return err
		}

		exists, err := s.repo.ExistsByCode(ctx, tx, r.CompanyID, r.AccountCode)
		if err != nil {
			return fmt.Errorf("check duplicate code: %w", err)
		}
		if exists {
			return fmt.Errorf("%w: account code %s already exists", ErrDuplicate, r.AccountCode)
		}
		if r.ParentAccountID != nil {
			parent, err := s.repo.GetByID(ctx, tx, *r.ParentAccountID)
			if err != nil {
				return fmt.Errorf("get parent account: %w", err)
			}
			if parent == nil {
				return fmt.Errorf("parent account does not exist for %s", r.AccountCode)
			}
			if parent.CompanyID != r.CompanyID {
				return fmt.Errorf("parent account belongs to different company for %s", r.AccountCode)
			}
			if r.AccountType != parent.AccountType {
				return fmt.Errorf("invalid hierarchy for %s: %s cannot be under %s", r.AccountCode, r.AccountType, parent.AccountType)
			}
			circular, err := s.repo.CheckCircularReference(ctx, tx, r.AccountID, r.ParentAccountID)
			if err != nil {
				return fmt.Errorf("check circular reference: %w", err)
			}
			if circular {
				return fmt.Errorf("%w: circular reference for account %s", ErrInvalidInput, r.AccountCode)
			}
		}
		accounts = append(accounts, &models.Account{
			AccountID:       r.AccountID,
			CompanyID:       r.CompanyID,
			AccountCode:     r.AccountCode,
			AccountName:     r.AccountName,
			AccountType:     r.AccountType,
			ParentAccountID: r.ParentAccountID,
			IsActive:        r.IsActive,
			Description:     r.Description,
			CreatedBy:       r.CreatedBy,
			UpdatedBy:       r.CreatedBy,
		})
	}

	if err := s.repo.BulkCreate(ctx, tx, accounts); err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return fmt.Errorf("%w: duplicate account code in batch", ErrDuplicate)
		}
		return fmt.Errorf("bulk create: %w", err)
	}

	for _, acc := range accounts {
		if err := s.emitAccountEvent(ctx, tx, acc, events.EventAccountCreated); err != nil {
			logger.Warn("failed to emit event", zap.String("account_id", acc.AccountID.String()), zap.Error(err))
		}
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil && len(accounts) > 0 {
		companyID := accounts[0].CompanyID
		actor := accounts[0].CreatedBy
		_ = s.auditService.LogAction(ctx, nil, &companyID, "account", "bulk_create", "account",
			nil, "user", actor, nil, nil, map[string]interface{}{
				"count": len(accounts),
				"codes": func() []string {
					codes := make([]string, len(accounts))
					for i, a := range accounts {
						codes[i] = a.AccountCode
					}
					return codes
				}(),
			})
	}
	logger.Info("bulk accounts created")
	return nil
}

// --------------------------------------------------------------------------
// UpdateAccount
// --------------------------------------------------------------------------

func (s *accountService) UpdateAccount(ctx context.Context, req UpdateAccountRequest, idempotencyKey string) (*models.Account, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateAccount"),
		zap.String("account_id", req.AccountID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if req.AccountID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	if idempotencyKey == "" {
		return nil, ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var existing *models.Account
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
		logger.Info("idempotent request – returning cached account")
		return existing, nil
	}

	account, err := s.getAccountWithCompanyCheck(ctx, tx, req.AccountID, req.CompanyID)
	if err != nil {
		return nil, err
	}

	oldStateJSON, _ := json.Marshal(account)

	// Account code is immutable – not present in request, so nothing to check

	if req.AccountType != "" && req.AccountType != account.AccountType {
		used, err := s.repo.CheckUsageInLedger(ctx, tx, account.AccountID)
		if err != nil {
			return nil, fmt.Errorf("check ledger usage for type change: %w", err)
		}
		if used {
			return nil, fmt.Errorf("cannot change account_type after usage in ledger entries")
		}
		account.AccountType = req.AccountType
	}

	if req.AccountName != "" {
		account.AccountName = strings.TrimSpace(req.AccountName)
	}
	if req.ParentAccountID != nil {
		if err := s.validateParentChange(ctx, tx, account.AccountID, account.CompanyID, req.ParentAccountID, account.AccountType); err != nil {
			return nil, err
		}
		account.ParentAccountID = req.ParentAccountID
	}
	account.IsActive = req.IsActive
	if req.Description != nil {
		account.Description = req.Description
	}
	account.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, account); err != nil {
		return nil, fmt.Errorf("update account: %w", err)
	}

	if err := s.emitAccountEvent(ctx, tx, account, events.EventAccountUpdated); err != nil {
		logger.Warn("failed to emit account updated event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, account)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	newStateJSON, _ := json.Marshal(account)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &account.CompanyID, "account", "update", "account",
			&account.AccountID, "user", req.UpdatedBy, oldStateJSON, newStateJSON, nil)
	}
	logger.Info("account updated")
	return account, nil
}

// --------------------------------------------------------------------------
// UpdateAccountStatus
// --------------------------------------------------------------------------

func (s *accountService) UpdateAccountStatus(ctx context.Context, companyID, accountID uuid.UUID, isActive bool, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "UpdateAccountStatus"),
		zap.String("company_id", companyID.String()),
		zap.String("account_id", accountID.String()),
		zap.Bool("is_active", isActive),
	)

	if accountID == uuid.Nil || companyID == uuid.Nil {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent request – already processed")
		return nil
	}

	account, err := s.getAccountWithCompanyCheck(ctx, tx, accountID, companyID)
	if err != nil {
		return err
	}

	oldStateJSON, _ := json.Marshal(account)

	if err := s.repo.UpdateStatus(ctx, tx, accountID, isActive, updatedBy); err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	account.IsActive = isActive

	if err := s.emitAccountEvent(ctx, tx, account, events.EventAccountStatusChanged); err != nil {
		logger.Warn("failed to emit status change event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	newStateJSON, _ := json.Marshal(account)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &account.CompanyID, "account", "update_status", "account",
			&accountID, "user", updatedBy, oldStateJSON, newStateJSON, map[string]interface{}{"is_active": isActive})
	}
	logger.Info("account status updated")
	return nil
}

// --------------------------------------------------------------------------
// MoveAccount
// --------------------------------------------------------------------------

func (s *accountService) MoveAccount(ctx context.Context, companyID, accountID uuid.UUID, newParentID *uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "MoveAccount"),
		zap.String("company_id", companyID.String()),
		zap.String("account_id", accountID.String()),
		zap.Any("new_parent_id", newParentID),
	)

	if accountID == uuid.Nil || companyID == uuid.Nil {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent request – already processed")
		return nil
	}

	account, err := s.getAccountWithCompanyCheck(ctx, tx, accountID, companyID)
	if err != nil {
		return err
	}

	if err := s.validateParentChange(ctx, tx, accountID, companyID, newParentID, account.AccountType); err != nil {
		return err
	}

	oldStateJSON, _ := json.Marshal(account)

	if err := s.repo.UpdateParent(ctx, tx, accountID, newParentID, updatedBy); err != nil {
		return fmt.Errorf("update parent: %w", err)
	}

	account.ParentAccountID = newParentID
	if err := s.emitAccountEvent(ctx, tx, account, events.EventAccountMoved); err != nil {
		logger.Warn("failed to emit move event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	newStateJSON, _ := json.Marshal(account)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &account.CompanyID, "account", "move", "account",
			&accountID, "user", updatedBy, oldStateJSON, newStateJSON, nil)
	}
	logger.Info("account moved")
	return nil
}

// --------------------------------------------------------------------------
// DeleteAccount
// --------------------------------------------------------------------------
func (s *accountService) DeleteAccount(
	ctx context.Context,
	companyID, accountID uuid.UUID,
	deletedBy *uuid.UUID,
	idempotencyKey string,
) error {

	logger := s.logger.With(
		zap.String("method", "DeleteAccount"),
		zap.String("company_id", companyID.String()),
		zap.String("account_id", accountID.String()),
	)

	// ---------- BASIC VALIDATION ----------
	if accountID == uuid.Nil || companyID == uuid.Nil {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// ---------- IDEMPOTENCY ----------
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent request – already processed")
		return nil
	}

	// ---------- FETCH ACCOUNT ----------
	account, err := s.getAccountWithCompanyCheck(ctx, tx, accountID, companyID)
	if err != nil {
		return err
	}

	// ---------- SYSTEM ACCOUNT PROTECTION ----------
	if isSystemAccount(account.AccountCode) {
		return fmt.Errorf("%w: system account cannot be deleted", ErrInvalidState)
	}

	// =====================================================
	// 🔥🔥 CRITICAL BUSINESS VALIDATIONS (MISSING EARLIER)
	// =====================================================

	// 1. CHILD CHECK
	hasChildren, err := s.repo.HasChildren(ctx, tx, accountID)
	if err != nil {
		return fmt.Errorf("check children: %w", err)
	}
	if hasChildren {
		return fmt.Errorf("%w: account has child accounts", ErrInvalidState)
	}

	// 2. LEDGER USAGE CHECK
	used, err := s.repo.CheckUsageInLedger(ctx, tx, accountID)
	if err != nil {
		return fmt.Errorf("check ledger usage: %w", err)
	}
	if used {
		return fmt.Errorf("%w: account used in ledger entries", ErrInvalidState)
	}

	// 3. OPTIONAL: already deleted safety (extra guard)
	if account.DeletedAt != nil {
		return fmt.Errorf("%w: account already deleted", ErrInvalidState)
	}

	// ---------- AUDIT SNAPSHOT ----------
	oldStateJSON, _ := json.Marshal(account)

	// ---------- DELETE ----------
	if err := s.repo.Delete(ctx, tx, accountID, deletedBy); err != nil {
		return fmt.Errorf("delete account: %w", err)
	}

	// ---------- EVENT ----------
	if err := s.emitAccountEvent(ctx, tx, account, events.EventAccountDeleted); err != nil {
		logger.Warn("failed to emit delete event", zap.Error(err))
	}

	// ---------- IDEMPOTENCY STORE ----------
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	// ---------- COMMIT ----------
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// ---------- AUDIT ----------
	newStateJSON, _ := json.Marshal(map[string]interface{}{
		"deleted":    true,
		"deleted_at": time.Now(),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(
			ctx,
			nil,
			&account.CompanyID,
			"account",
			"delete",
			"account",
			&accountID,
			"user",
			deletedBy,
			oldStateJSON,
			newStateJSON,
			nil,
		)
	}

	logger.Info("account soft-deleted successfully")
	return nil
}

// --------------------------------------------------------------------------
// Queries
// --------------------------------------------------------------------------

func (s *accountService) GetAccount(ctx context.Context, accountID uuid.UUID) (*models.Account, error) {
	account, err := s.repo.GetByID(ctx, s.pgClient.DB, accountID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, fmt.Errorf("%w: account %s", ErrNotFound, accountID)
	}
	return account, nil
}

func (s *accountService) GetAccountByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Account, error) {
	return s.repo.GetByCode(ctx, s.pgClient.DB, companyID, code)
}

func (s *accountService) ListAccounts(ctx context.Context, filter repository.AccountFilter, page, pageSize int, sort repository.Sort) ([]*models.Account, int64, error) {
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * pageSize
	pagination := repository.Pagination{Limit: pageSize, Offset: offset}
	accounts, err := s.repo.List(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.Count(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return accounts, total, nil
}

func (s *accountService) GetAccountTree(ctx context.Context, companyID uuid.UUID) ([]*repository.AccountTreeNode, error) {
	return s.repo.GetTree(ctx, s.pgClient.DB, companyID)
}

func (s *accountService) GetChildren(ctx context.Context, parentID uuid.UUID) ([]*models.Account, error) {
	return s.repo.GetChildren(ctx, s.pgClient.DB, parentID)
}

func (s *accountService) HasChildren(ctx context.Context, accountID uuid.UUID) (bool, error) {
	return s.repo.HasChildren(ctx, s.pgClient.DB, accountID)
}

func (s *accountService) CheckAccountUsage(ctx context.Context, accountID uuid.UUID) (bool, error) {
	return s.repo.CheckUsageInLedger(ctx, s.pgClient.DB, accountID)
}

func (s *accountService) CheckCircularReference(ctx context.Context, accountID uuid.UUID, parentID *uuid.UUID) (bool, error) {
	return s.repo.CheckCircularReference(ctx, s.pgClient.DB, accountID, parentID)
}

// --------------------------------------------------------------------------
// ValidatePostingAccount
// --------------------------------------------------------------------------

func (s *accountService) ValidatePostingAccount(ctx context.Context, companyID, accountID uuid.UUID) error {
	account, err := s.repo.GetByID(ctx, s.pgClient.DB, accountID)
	if err != nil {
		return err
	}
	if account == nil {
		return fmt.Errorf("account not found")
	}
	if account.CompanyID != companyID {
		return fmt.Errorf("account does not belong to company")
	}
	if !account.IsActive {
		return fmt.Errorf("inactive account cannot be used for posting")
	}
	isLeaf, err := s.repo.IsLeafAccount(ctx, s.pgClient.DB, accountID)
	if err != nil {
		return err
	}
	if !isLeaf {
		return fmt.Errorf("only leaf accounts can be used for transactions")
	}
	return nil
}

// --------------------------------------------------------------------------
// Internal Helpers
// --------------------------------------------------------------------------

func (s *accountService) validateCreateRequest(req *CreateAccountRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", ErrInvalidInput)
	}

	// Normalize inputs
	req.AccountCode = strings.ToUpper(strings.TrimSpace(req.AccountCode))
	req.AccountName = strings.TrimSpace(req.AccountName)
	req.AccountType = strings.ToLower(strings.TrimSpace(req.AccountType))

	if req.AccountCode == "" {
		return fmt.Errorf("%w: account_code required", ErrInvalidInput)
	}
	if req.AccountName == "" {
		return fmt.Errorf("%w: account_name required", ErrInvalidInput)
	}
	if req.AccountType == "" {
		return fmt.Errorf("%w: account_type required", ErrInvalidInput)
	}
	validTypes := map[string]bool{
		"asset": true, "liability": true, "equity": true,
		"revenue": true, "expense": true,
	}
	if !validTypes[req.AccountType] {
		return fmt.Errorf("%w: invalid account_type", ErrInvalidInput)
	}
	if req.AccountID == uuid.Nil {
		req.AccountID = uuid.New()
	}
	return nil
}

func (s *accountService) validateParentChange(ctx context.Context, tx repository.DBTX, accountID, companyID uuid.UUID, newParentID *uuid.UUID, childType string) error {
	if newParentID == nil {
		return nil
	}
	if *newParentID == accountID {
		return fmt.Errorf("%w: cannot set account as its own parent", ErrInvalidInput)
	}
	parent, err := s.repo.GetByID(ctx, tx, *newParentID)
	if err != nil {
		return fmt.Errorf("get parent account: %w", err)
	}
	if parent == nil {
		return fmt.Errorf("parent account does not exist")
	}
	if parent.CompanyID != companyID {
		return fmt.Errorf("parent account belongs to different company")
	}
	if childType != parent.AccountType {
		return fmt.Errorf("invalid hierarchy: %s cannot be under %s", childType, parent.AccountType)
	}
	circular, err := s.repo.CheckCircularReference(ctx, tx, accountID, newParentID)
	if err != nil {
		return fmt.Errorf("check circular reference: %w", err)
	}
	if circular {
		return fmt.Errorf("%w: circular reference detected", ErrInvalidInput)
	}
	return nil
}

func (s *accountService) getAccountWithCompanyCheck(ctx context.Context, tx repository.DBTX, accountID, expectedCompanyID uuid.UUID) (*models.Account, error) {
	account, err := s.repo.GetByIDForUpdate(ctx, tx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	if account == nil {
		return nil, fmt.Errorf("%w: account %s", ErrNotFound, accountID)
	}
	if expectedCompanyID != uuid.Nil && account.CompanyID != expectedCompanyID {
		return nil, fmt.Errorf("unauthorized: account does not belong to company")
	}
	return account, nil
}

func isSystemAccount(code string) bool {
	systemCodes := map[string]bool{
		"CASH": true, "BANK": true, "GST_PAYABLE": true,
	}
	return systemCodes[code]
}

func (s *accountService) emitAccountEvent(ctx context.Context, tx *sql.Tx, account *models.Account, eventType string) error {
	if s.outboxRepo == nil {
		return nil
	}
	payload, err := json.Marshal(events.AccountPayload{
		AccountID:   account.AccountID.String(),
		CompanyID:   account.CompanyID.String(),
		AccountCode: account.AccountCode,
		AccountName: account.AccountName,
		AccountType: account.AccountType,
		ParentID: func() *string {
			if account.ParentAccountID != nil {
				s := account.ParentAccountID.String()
				return &s
			}
			return nil
		}(),
		IsActive:    account.IsActive,
		Description: account.Description,
	})
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "account",
		AggregateID:   account.AccountID.String(),
		EventType:     eventType,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
