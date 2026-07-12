// file: internal/subscription/service/addon_service.go
package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/events"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/repository"
)

// AddonService defines the business operations for managing the addon catalog.
type AddonService interface {
	Create(ctx context.Context, addon *models.Addon) error
	Update(ctx context.Context, addon *models.Addon) error
	Delete(ctx context.Context, companyID, addonID uuid.UUID) error
	GetByID(ctx context.Context, companyID, addonID uuid.UUID) (*models.Addon, error)
	GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.Addon, error)
	Activate(ctx context.Context, companyID, addonID uuid.UUID) error
	Deactivate(ctx context.Context, companyID, addonID uuid.UUID) error
	Restore(ctx context.Context, companyID, addonID uuid.UUID) error
	UpdatePrice(ctx context.Context, companyID, addonID uuid.UUID, price decimal.Decimal, currency string) error
	UpdateBillingPolicy(ctx context.Context, companyID, addonID, billingPolicyID uuid.UUID) error
	Exists(ctx context.Context, companyID, addonID uuid.UUID) (bool, error)
	Validate(ctx context.Context, companyID, addonID uuid.UUID) (*models.Addon, error)
	List(ctx context.Context, filter repository.AddonFilter, p repository.Pagination, s repository.Sort) ([]*models.Addon, int64, error)
	Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Addon, int64, error)
	GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.Addon, error)
	GetByBillingPolicy(ctx context.Context, companyID, billingPolicyID uuid.UUID) ([]*models.Addon, error)
	GetByPriceRange(ctx context.Context, companyID uuid.UUID, min, max decimal.Decimal) ([]*models.Addon, error)
}

// addonService implements AddonService.
type addonService struct {
	addonRepo         repository.AddonRepository
	billingPolicyRepo repository.BillingPolicyRepository // new field
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	auditService      *audit.AuditService
	pgClient          *client.PostgresClient
	logger            *zap.Logger
}

// NewAddonService creates a new AddonService.
func NewAddonService(
	addonRepo repository.AddonRepository,
	billingPolicyRepo repository.BillingPolicyRepository, // new param
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) AddonService {
	return &addonService{
		addonRepo:         addonRepo,
		billingPolicyRepo: billingPolicyRepo,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		auditService:      auditService,
		pgClient:          pgClient,
		logger:            logger.Named("addon_service"),
	}
}

// --- helpers ---

// getSQLTx extracts a *sql.Tx from a repository.DBTX.
func (s *addonService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

// emitAddonEvent stores an outbox event for the addon aggregate.
func (s *addonService) emitAddonEvent(ctx context.Context, tx repository.DBTX, addonID, companyID uuid.UUID, eventType string, payload interface{}) error {
	sqlTx, err := s.getSQLTx(tx)
	if err != nil {
		return err
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "addon",
		AggregateID:   addonID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

// buildAddonPayload constructs the event payload for an addon.
func buildAddonPayload(addon *models.Addon) events.AddonPayload {
	payload := events.AddonPayload{
		AddonID:         addon.AddonID.String(),
		CompanyID:       addon.CompanyID.String(),
		Name:            addon.Name,
		Description:     addon.Description,
		BillingPolicyID: addon.BillingPolicyID.String(),
		Price:           addon.Price.String(),
		Currency:        addon.Currency,
		IsActive:        addon.IsActive,
		CreatedAt:       addon.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       addon.UpdatedAt.Format(time.RFC3339),
	}
	return payload
}

// allowedCurrencies defines the set of currency codes accepted.
// allowedCurrencies defines the set of currency codes accepted.
// This includes all active ISO 4217 currency codes (as of 2025) plus a few commonly used ones.
// The list is case‑insensitive via strings.ToUpper.
var allowedCurrencies = map[string]bool{
	// Major currencies
	"USD": true, // US Dollar
	"EUR": true, // Euro
	"GBP": true, // British Pound
	"JPY": true, // Japanese Yen
	"CAD": true, // Canadian Dollar
	"AUD": true, // Australian Dollar
	"CHF": true, // Swiss Franc
	"CNY": true, // Chinese Yuan
	"SEK": true, // Swedish Krona
	"NZD": true, // New Zealand Dollar

	// Other widely used currencies
	"AFN": true, // Afghan Afghani
	"ALL": true, // Albanian Lek
	"DZD": true, // Algerian Dinar
	"AOA": true, // Angolan Kwanza
	"ARS": true, // Argentine Peso
	"AMD": true, // Armenian Dram
	"AWG": true, // Aruban Florin
	"AZN": true, // Azerbaijani Manat
	"BSD": true, // Bahamian Dollar
	"BHD": true, // Bahraini Dinar
	"BDT": true, // Bangladeshi Taka
	"BBD": true, // Barbadian Dollar
	"BYN": true, // Belarusian Ruble
	"BZD": true, // Belize Dollar
	"BMD": true, // Bermudian Dollar
	"BTN": true, // Bhutanese Ngultrum
	"BOB": true, // Bolivian Boliviano
	"BAM": true, // Bosnia-Herzegovina Convertible Mark
	"BWP": true, // Botswanan Pula
	"BRL": true, // Brazilian Real
	"BND": true, // Brunei Dollar
	"BGN": true, // Bulgarian Lev
	"BIF": true, // Burundian Franc
	"KHR": true, // Cambodian Riel
	"XAF": true, // Central African CFA Franc
	"CVE": true, // Cape Verdean Escudo
	"KYD": true, // Cayman Islands Dollar
	"CLP": true, // Chilean Peso
	"COP": true, // Colombian Peso
	"KMF": true, // Comorian Franc
	"CDF": true, // Congolese Franc
	"CRC": true, // Costa Rican Colón
	"HRK": true, // Croatian Kuna (still used in some contexts)
	"CUP": true, // Cuban Peso
	"CZK": true, // Czech Koruna
	"DKK": true, // Danish Krone
	"DJF": true, // Djiboutian Franc
	"DOP": true, // Dominican Peso
	"XCD": true, // East Caribbean Dollar
	"EGP": true, // Egyptian Pound
	"ERN": true, // Eritrean Nakfa
	"ETB": true, // Ethiopian Birr
	"FKP": true, // Falkland Islands Pound
	"FJD": true, // Fijian Dollar
	"GMD": true, // Gambian Dalasi
	"GEL": true, // Georgian Lari
	"GHS": true, // Ghanaian Cedi
	"GIP": true, // Gibraltar Pound
	"GTQ": true, // Guatemalan Quetzal
	"GNF": true, // Guinean Franc
	"GYD": true, // Guyanese Dollar
	"HTG": true, // Haitian Gourde
	"HNL": true, // Honduran Lempira
	"HKD": true, // Hong Kong Dollar
	"HUF": true, // Hungarian Forint
	"ISK": true, // Icelandic Króna
	"INR": true, // Indian Rupee
	"IDR": true, // Indonesian Rupiah
	"IRR": true, // Iranian Rial
	"IQD": true, // Iraqi Dinar
	"ILS": true, // Israeli New Shekel
	"JMD": true, // Jamaican Dollar
	"JOD": true, // Jordanian Dinar
	"KZT": true, // Kazakhstani Tenge
	"KES": true, // Kenyan Shilling
	"KWD": true, // Kuwaiti Dinar
	"KGS": true, // Kyrgyzstani Som
	"LAK": true, // Lao Kip
	"LBP": true, // Lebanese Pound
	"LSL": true, // Lesotho Loti
	"LRD": true, // Liberian Dollar
	"LYD": true, // Libyan Dinar
	"MOP": true, // Macanese Pataca
	"MKD": true, // Macedonian Denar
	"MGA": true, // Malagasy Ariary
	"MWK": true, // Malawian Kwacha
	"MYR": true, // Malaysian Ringgit
	"MVR": true, // Maldivian Rufiyaa
	"MRU": true, // Mauritanian Ouguiya
	"MUR": true, // Mauritian Rupee
	"MXN": true, // Mexican Peso
	"MDL": true, // Moldovan Leu
	"MNT": true, // Mongolian Tögrög
	"MAD": true, // Moroccan Dirham
	"MZN": true, // Mozambican Metical
	"MMK": true, // Myanmar Kyat
	"NAD": true, // Namibian Dollar
	"NPR": true, // Nepalese Rupee
	"ANG": true, // Netherlands Antillean Guilder
	"TWD": true, // New Taiwan Dollar
	"NIO": true, // Nicaraguan Córdoba
	"NGN": true, // Nigerian Naira
	"KPW": true, // North Korean Won
	"NOK": true, // Norwegian Krone
	"OMR": true, // Omani Rial
	"PKR": true, // Pakistani Rupee
	"PAB": true, // Panamanian Balboa
	"PGK": true, // Papua New Guinean Kina
	"PYG": true, // Paraguayan Guarani
	"PEN": true, // Peruvian Sol
	"PHP": true, // Philippine Peso
	"PLN": true, // Polish Złoty
	"QAR": true, // Qatari Rial
	"RON": true, // Romanian Leu
	"RUB": true, // Russian Ruble
	"RWF": true, // Rwandan Franc
	"SHP": true, // Saint Helena Pound
	"WST": true, // Samoan Tālā
	"STN": true, // São Tomé and Príncipe Dobra
	"SAR": true, // Saudi Riyal
	"RSD": true, // Serbian Dinar
	"SCR": true, // Seychellois Rupee
	"SLL": true, // Sierra Leonean Leone (old, replaced by SLE)
	"SGD": true, // Singapore Dollar
	"SBD": true, // Solomon Islands Dollar
	"SOS": true, // Somali Shilling
	"ZAR": true, // South African Rand
	"KRW": true, // South Korean Won
	"SSP": true, // South Sudanese Pound
	"LKR": true, // Sri Lankan Rupee
	"SDG": true, // Sudanese Pound
	"SRD": true, // Surinamese Dollar
	"SZL": true, // Swazi Lilangeni
	"SYP": true, // Syrian Pound
	"TJS": true, // Tajikistani Somoni
	"TZS": true, // Tanzanian Shilling
	"THB": true, // Thai Baht
	"TOP": true, // Tongan Paʻanga
	"TTD": true, // Trinidad and Tobago Dollar
	"TND": true, // Tunisian Dinar
	"TRY": true, // Turkish Lira
	"TMT": true, // Turkmenistani Manat
	"UGX": true, // Ugandan Shilling
	"UAH": true, // Ukrainian Hryvnia
	"AED": true, // United Arab Emirates Dirham
	"UYU": true, // Uruguayan Peso
	"UZS": true, // Uzbekistani Som
	"VUV": true, // Vanuatu Vatu
	"VES": true, // Venezuelan Bolívar
	"VND": true, // Vietnamese Đồng
	"XPF": true, // CFP Franc (French Polynesia)
	"YER": true, // Yemeni Rial
	"ZMW": true, // Zambian Kwacha
	"ZWL": true, // Zimbabwean Dollar (historical, rarely used)

	// Special codes (not currencies per se, but often used in financial systems)
	"XTS": true, // Testing currency code
	"XXX": true, // No currency (for transactions without currency)
	// "XAU": true, // Gold (one troy ounce) – sometimes used
	// "XAG": true, // Silver
	// "XDR": true, // Special Drawing Rights (IMF)
}

// Note: The list can be moved to a configuration file or database for dynamic updates.
// For now, it covers virtually all actively used ISO 4217 currencies.
// isValidCurrency checks if the currency code is supported (case-insensitive).
func isValidCurrency(currency string) bool {
	return allowedCurrencies[strings.ToUpper(currency)]
}

// --- interface implementation ---

// Create persists a new addon.
// On idempotent hit (same key), it fetches the existing addon and copies it into the provided pointer.
func (s *addonService) Create(ctx context.Context, addon *models.Addon) error {
	logger := s.logger.With(zap.String("method", "Create"), zap.String("addon_name", addon.Name))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Include company ID in the idempotency key to avoid collisions across companies.
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("addon-create-%s-%s", addon.CompanyID.String(), addon.Name))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – addon creation already processed, fetching existing")
		existing, err := s.addonRepo.GetByName(ctx, tx, addon.CompanyID, addon.Name)
		if err != nil {
			return err
		}
		if existing == nil {
			// Should not happen if idempotency key exists, but handle gracefully.
			return fmt.Errorf("idempotent hit but addon not found")
		}
		*addon = *existing // copy existing data into the provided pointer
		return nil
	}

	// --- NEW VALIDATIONS ---

	// 1. Validate currency
	if !isValidCurrency(addon.Currency) {
		return subErrors.ErrInvalidCurrency
	}

	// 2. Validate billing policy existence
	exists, err := s.billingPolicyRepo.Exists(ctx, tx, addon.CompanyID, addon.BillingPolicyID)
	if err != nil {
		return err
	}
	if !exists {
		return subErrors.ErrBillingPolicyNotFound
	}

	// 3. Validate uniqueness of name per company
	exists, err = s.addonRepo.ExistsByName(ctx, tx, addon.CompanyID, addon.Name)
	if err != nil {
		return err
	}
	if exists {
		return subErrors.ErrAddonAlreadyExists
	}

	// Persist
	if err := s.addonRepo.Create(ctx, tx, addon); err != nil {
		return err
	}

	// Emit event
	payload := buildAddonPayload(addon)
	if err := s.emitAddonEvent(ctx, tx, addon.AddonID, addon.CompanyID, events.EventAddonCreated, payload); err != nil {
		logger.Warn("failed to emit addon.created event", zap.Error(err))
	}

	// Store idempotency
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &addon.CompanyID, "addon", "create", "addon",
			&addon.AddonID, "system", nil, nil, nil, map[string]interface{}{
				"name": addon.Name,
			})
	}

	return nil
}

// Update modifies an existing addon.
// On idempotent hit, it fetches the current addon and copies it into the provided pointer.
func (s *addonService) Update(ctx context.Context, addon *models.Addon) error {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("addon_id", addon.AddonID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("addon-update-%s", addon.AddonID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – addon update already processed, fetching current state")
		existing, err := s.addonRepo.GetByID(ctx, tx, addon.CompanyID, addon.AddonID)
		if err != nil {
			return err
		}
		if existing == nil {
			return subErrors.ErrAddonNotFound
		}
		*addon = *existing // copy current data back to the caller
		return nil
	}

	// Fetch existing for audit/version checks and name uniqueness validation
	existing, err := s.addonRepo.GetByIDForUpdate(ctx, tx, addon.CompanyID, addon.AddonID)
	if err != nil {
		return err
	}
	if existing == nil {
		return subErrors.ErrAddonNotFound
	}

	// --- NEW VALIDATIONS ---

	// Currency validation if changed
	if existing.Currency != addon.Currency {
		if !isValidCurrency(addon.Currency) {
			return subErrors.ErrInvalidCurrency
		}
	}

	// Billing policy validation if changed
	if existing.BillingPolicyID != addon.BillingPolicyID {
		exists, err := s.billingPolicyRepo.Exists(ctx, tx, addon.CompanyID, addon.BillingPolicyID)
		if err != nil {
			return err
		}
		if !exists {
			return subErrors.ErrBillingPolicyNotFound
		}
	}

	// Check if name changed and already exists
	if existing.Name != addon.Name {
		exists, err := s.addonRepo.ExistsByName(ctx, tx, addon.CompanyID, addon.Name)
		if err != nil {
			return err
		}
		if exists {
			return subErrors.ErrAddonAlreadyExists
		}
	}

	// Update the addon (set updated_at in repo or here)
	addon.UpdatedAt = time.Now()
	if err := s.addonRepo.Update(ctx, tx, addon); err != nil {
		return err
	}

	// Emit event
	payload := buildAddonPayload(addon)
	if err := s.emitAddonEvent(ctx, tx, addon.AddonID, addon.CompanyID, events.EventAddonUpdated, payload); err != nil {
		logger.Warn("failed to emit addon.updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		oldData, _ := json.Marshal(existing)
		newData, _ := json.Marshal(addon)
		_ = s.auditService.LogAction(ctx, nil, &addon.CompanyID, "addon", "update", "addon",
			&addon.AddonID, "system", nil, oldData, newData, nil)
	}
	return nil
}

// Delete soft-deletes an addon.
func (s *addonService) Delete(ctx context.Context, companyID, addonID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("addon_id", addonID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("addon-delete-%s", addonID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – addon delete already processed")
		return nil
	}

	// Check existence
	exists, err := s.addonRepo.Exists(ctx, tx, companyID, addonID)
	if err != nil {
		return err
	}
	if !exists {
		return subErrors.ErrAddonNotFound
	}

	if err := s.addonRepo.SoftDelete(ctx, tx, companyID, addonID); err != nil {
		return err
	}

	// Emit event (include isActive=false, deletedAt)
	addon, err := s.addonRepo.GetByID(ctx, tx, companyID, addonID)
	if err != nil {
		logger.Warn("failed to fetch addon for event payload", zap.Error(err))
	} else {
		payload := buildAddonPayload(addon)
		if err := s.emitAddonEvent(ctx, tx, addonID, companyID, events.EventAddonDeleted, payload); err != nil {
			logger.Warn("failed to emit addon.deleted event", zap.Error(err))
		}
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "addon", "delete", "addon",
			&addonID, "system", nil, nil, nil, nil)
	}
	return nil
}

// GetByID fetches an addon by ID.
func (s *addonService) GetByID(ctx context.Context, companyID, addonID uuid.UUID) (*models.Addon, error) {
	db := s.pgClient.DB
	return s.addonRepo.GetByID(ctx, db, companyID, addonID)
}

// GetByName fetches an addon by name.
func (s *addonService) GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.Addon, error) {
	db := s.pgClient.DB
	return s.addonRepo.GetByName(ctx, db, companyID, name)
}

// Activate sets an addon as active.
func (s *addonService) Activate(ctx context.Context, companyID, addonID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"), zap.String("addon_id", addonID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("addon-activate-%s", addonID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – addon activation already processed")
		return nil
	}

	// Check if already active
	addon, err := s.addonRepo.GetByIDForUpdate(ctx, tx, companyID, addonID)
	if err != nil {
		return err
	}
	if addon == nil {
		return subErrors.ErrAddonNotFound
	}
	if addon.IsActive {
		return nil // already active
	}

	if err := s.addonRepo.Activate(ctx, tx, companyID, addonID); err != nil {
		return err
	}

	// Emit event
	addon.IsActive = true
	payload := buildAddonPayload(addon)
	if err := s.emitAddonEvent(ctx, tx, addonID, companyID, events.EventAddonActivated, payload); err != nil {
		logger.Warn("failed to emit addon.activated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "addon", "activate", "addon",
			&addonID, "system", nil, nil, nil, nil)
	}
	return nil
}

// Deactivate sets an addon as inactive.
func (s *addonService) Deactivate(ctx context.Context, companyID, addonID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"), zap.String("addon_id", addonID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("addon-deactivate-%s", addonID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – addon deactivation already processed")
		return nil
	}

	addon, err := s.addonRepo.GetByIDForUpdate(ctx, tx, companyID, addonID)
	if err != nil {
		return err
	}
	if addon == nil {
		return subErrors.ErrAddonNotFound
	}
	if !addon.IsActive {
		return nil
	}

	if err := s.addonRepo.Deactivate(ctx, tx, companyID, addonID); err != nil {
		return err
	}

	addon.IsActive = false
	payload := buildAddonPayload(addon)
	if err := s.emitAddonEvent(ctx, tx, addonID, companyID, events.EventAddonDeactivated, payload); err != nil {
		logger.Warn("failed to emit addon.deactivated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "addon", "deactivate", "addon",
			&addonID, "system", nil, nil, nil, nil)
	}
	return nil
}

// Restore recovers a soft-deleted addon.
func (s *addonService) Restore(ctx context.Context, companyID, addonID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Restore"), zap.String("addon_id", addonID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("addon-restore-%s", addonID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – addon restore already processed")
		return nil
	}

	if err := s.addonRepo.Restore(ctx, tx, companyID, addonID); err != nil {
		return err
	}

	// Emit event
	addon, err := s.addonRepo.GetByID(ctx, tx, companyID, addonID)
	if err != nil {
		logger.Warn("failed to fetch addon for event payload", zap.Error(err))
	} else {
		payload := buildAddonPayload(addon)
		if err := s.emitAddonEvent(ctx, tx, addonID, companyID, events.EventAddonRestored, payload); err != nil {
			logger.Warn("failed to emit addon.restored event", zap.Error(err))
		}
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "addon", "restore", "addon",
			&addonID, "system", nil, nil, nil, nil)
	}
	return nil
}

// UpdatePrice updates the price and currency of an addon.
func (s *addonService) UpdatePrice(ctx context.Context, companyID, addonID uuid.UUID, price decimal.Decimal, currency string) error {
	logger := s.logger.With(zap.String("method", "UpdatePrice"), zap.String("addon_id", addonID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("addon-updateprice-%s", addonID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – price update already processed")
		return nil
	}

	addon, err := s.addonRepo.GetByIDForUpdate(ctx, tx, companyID, addonID)
	if err != nil {
		return err
	}
	if addon == nil {
		return subErrors.ErrAddonNotFound
	}

	// --- NEW: validate currency ---
	if !isValidCurrency(currency) {
		return subErrors.ErrInvalidCurrency
	}

	if err := s.addonRepo.UpdatePrice(ctx, tx, companyID, addonID, price, currency); err != nil {
		return err
	}

	// Emit event
	addon.Price = price
	addon.Currency = currency
	payload := buildAddonPayload(addon)
	if err := s.emitAddonEvent(ctx, tx, addonID, companyID, events.EventAddonPriceUpdated, payload); err != nil {
		logger.Warn("failed to emit addon.price_updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "addon", "update_price", "addon",
			&addonID, "system", nil, nil, nil, map[string]interface{}{
				"price":    price.String(),
				"currency": currency,
			})
	}
	return nil
}

// UpdateBillingPolicy updates the billing policy of an addon.
func (s *addonService) UpdateBillingPolicy(ctx context.Context, companyID, addonID, billingPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateBillingPolicy"), zap.String("addon_id", addonID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("addon-updatebillingpolicy-%s", addonID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – billing policy update already processed")
		return nil
	}

	addon, err := s.addonRepo.GetByIDForUpdate(ctx, tx, companyID, addonID)
	if err != nil {
		return err
	}
	if addon == nil {
		return subErrors.ErrAddonNotFound
	}

	// --- NEW: validate new billing policy ---
	exists, err := s.billingPolicyRepo.Exists(ctx, tx, companyID, billingPolicyID)
	if err != nil {
		return err
	}
	if !exists {
		return subErrors.ErrBillingPolicyNotFound
	}

	if err := s.addonRepo.UpdateBillingPolicy(ctx, tx, companyID, addonID, billingPolicyID); err != nil {
		return err
	}

	// Emit event
	addon.BillingPolicyID = billingPolicyID
	payload := buildAddonPayload(addon)
	if err := s.emitAddonEvent(ctx, tx, addonID, companyID, events.EventAddonBillingPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit addon.billing_policy_updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "addon", "update_billing_policy", "addon",
			&addonID, "system", nil, nil, nil, map[string]interface{}{
				"new_billing_policy_id": billingPolicyID.String(),
			})
	}
	return nil
}

// Exists checks if an addon exists.
func (s *addonService) Exists(ctx context.Context, companyID, addonID uuid.UUID) (bool, error) {
	db := s.pgClient.DB
	return s.addonRepo.Exists(ctx, db, companyID, addonID)
}

// Validate fetches and validates an addon (e.g., checks existence and active state).
func (s *addonService) Validate(ctx context.Context, companyID, addonID uuid.UUID) (*models.Addon, error) {
	db := s.pgClient.DB
	addon, err := s.addonRepo.GetByID(ctx, db, companyID, addonID)
	if err != nil {
		return nil, err
	}
	if addon == nil {
		return nil, subErrors.ErrAddonNotFound
	}
	if !addon.IsActive {
		return nil, subErrors.ErrAddonInactive
	}
	return addon, nil
}

// List returns a paginated list of addons based on filter.
func (s *addonService) List(ctx context.Context, filter repository.AddonFilter, p repository.Pagination, sort repository.Sort) ([]*models.Addon, int64, error) {
	db := s.pgClient.DB
	return s.addonRepo.List(ctx, db, filter, p, sort)
}

// Search performs a full-text search on addons.
func (s *addonService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Addon, int64, error) {
	db := s.pgClient.DB
	return s.addonRepo.Search(ctx, db, companyID, query, limit, offset)
}

// GetActive returns all active addons for a company.
func (s *addonService) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.Addon, error) {
	db := s.pgClient.DB
	return s.addonRepo.GetActive(ctx, db, companyID)
}

// GetByBillingPolicy returns addons using a specific billing policy.
func (s *addonService) GetByBillingPolicy(ctx context.Context, companyID, billingPolicyID uuid.UUID) ([]*models.Addon, error) {
	db := s.pgClient.DB
	return s.addonRepo.GetByBillingPolicy(ctx, db, companyID, billingPolicyID)
}

// GetByPriceRange returns addons within a price range.
func (s *addonService) GetByPriceRange(ctx context.Context, companyID uuid.UUID, min, max decimal.Decimal) ([]*models.Addon, error) {
	db := s.pgClient.DB
	return s.addonRepo.GetByPriceRange(ctx, db, companyID, min, max)
}
