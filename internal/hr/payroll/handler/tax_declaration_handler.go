package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type TaxDeclarationHandler struct {
	taxService service.TaxDeclarationService
	logger     *zap.Logger
}

func NewTaxDeclarationHandler(taxService service.TaxDeclarationService, logger *zap.Logger) *TaxDeclarationHandler {
	return &TaxDeclarationHandler{
		taxService: taxService,
		logger:     logger.Named("tax_declaration_handler"),
	}
}

// ----------------------------------------------------------------------
// Request & Response Types
// ----------------------------------------------------------------------

type createDeclarationTypeRequest struct {
	TypeCode    string   `json:"type_code"`
	Description string   `json:"description"`
	MaxLimit    *float64 `json:"max_limit,omitempty"`
}

func (r *createDeclarationTypeRequest) validate() error {
	if r.TypeCode == "" {
		return errMissingField("type_code")
	}
	if r.Description == "" {
		return errMissingField("description")
	}
	return nil
}

type updateDeclarationTypeRequest struct {
	Description string   `json:"description"`
	MaxLimit    *float64 `json:"max_limit,omitempty"`
	IsActive    bool     `json:"is_active"`
}

func (r *updateDeclarationTypeRequest) validate() error {
	if r.Description == "" {
		return errMissingField("description")
	}
	return nil
}

type declarationTypeResponse struct {
	CompanyID   uuid.UUID `json:"company_id"`
	TypeCode    string    `json:"type_code"`
	Description string    `json:"description"`
	MaxLimit    *float64  `json:"max_limit,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type createDeclarationRequest struct {
	UserID          uuid.UUID `json:"user_id"`
	FinancialYear   string    `json:"financial_year"`
	DeclarationType string    `json:"declaration_type"`
	Amount          float64   `json:"amount"`
	SupportingDocs  []string  `json:"supporting_docs,omitempty"`
}

func (r *createDeclarationRequest) validate() error {
	if r.UserID == uuid.Nil {
		return errMissingField("user_id")
	}
	if r.FinancialYear == "" {
		return errMissingField("financial_year")
	}
	if r.DeclarationType == "" {
		return errMissingField("declaration_type")
	}
	if r.Amount < 0 {
		return errInvalidField("amount cannot be negative")
	}
	return nil
}

type updateDeclarationRequest struct {
	Amount         float64  `json:"amount"`
	SupportingDocs []string `json:"supporting_docs,omitempty"`
}

func (r *updateDeclarationRequest) validate() error {
	if r.Amount < 0 {
		return errInvalidField("amount cannot be negative")
	}
	return nil
}

type verifyDeclarationRequest struct {
	Status string `json:"status"`
}

func (r *verifyDeclarationRequest) validate() error {
	if r.Status != models.DeclarationStatusVerified && r.Status != models.DeclarationStatusRejected {
		return errInvalidField("status must be 'verified' or 'rejected'")
	}
	return nil
}

type declarationResponse struct {
	DeclarationID   uuid.UUID  `json:"declaration_id"`
	CompanyID       uuid.UUID  `json:"company_id"`
	UserID          uuid.UUID  `json:"user_id"`
	FinancialYear   string     `json:"financial_year"`
	DeclarationType string     `json:"declaration_type"`
	Amount          float64    `json:"amount"`
	SupportingDocs  []string   `json:"supporting_docs"`
	Status          string     `json:"status"`
	SubmittedAt     time.Time  `json:"submitted_at"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
	VerifiedBy      *uuid.UUID `json:"verified_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func mapDeclarationToResponse(d *models.TaxDeclaration) declarationResponse {
	return declarationResponse{
		DeclarationID:   d.DeclarationID,
		CompanyID:       d.CompanyID,
		UserID:          d.UserID,
		FinancialYear:   d.FinancialYear,
		DeclarationType: d.DeclarationType,
		Amount:          d.Amount,
		SupportingDocs:  d.SupportingDocs,
		Status:          d.Status,
		SubmittedAt:     d.SubmittedAt,
		VerifiedAt:      d.VerifiedAt,
		VerifiedBy:      d.VerifiedBy,
		CreatedAt:       d.CreatedAt,
		UpdatedAt:       d.UpdatedAt,
	}
}

// ----------------------------------------------------------------------
// Declaration Type Handlers
// ----------------------------------------------------------------------

func (h *TaxDeclarationHandler) CreateDeclarationType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	actorID, err := getAdminActor(ctx)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createDeclarationTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	dt, err := h.taxService.CreateDeclarationType(ctx, companyID, req.TypeCode, req.Description, req.MaxLimit, actorID)
	if err != nil {
		h.logger.Error("failed to create declaration type", zap.Error(err))
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data": declarationTypeResponse{
			CompanyID:   dt.CompanyID,
			TypeCode:    dt.TypeCode,
			Description: dt.Description,
			MaxLimit:    dt.MaxLimit,
			IsActive:    dt.IsActive,
			CreatedAt:   dt.CreatedAt,
			UpdatedAt:   dt.UpdatedAt,
		},
	})
}

func (h *TaxDeclarationHandler) UpdateDeclarationType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	typeCode := chi.URLParam(r, "typeCode")
	if typeCode == "" {
		respondWithError(w, http.StatusBadRequest, "type code required")
		return
	}
	actorID, err := getAdminActor(ctx)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req updateDeclarationTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	dt, err := h.taxService.UpdateDeclarationType(ctx, companyID, typeCode, req.Description, req.MaxLimit, req.IsActive, actorID)
	if err != nil {
		h.logger.Error("failed to update declaration type", zap.Error(err))
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": declarationTypeResponse{
			CompanyID:   dt.CompanyID,
			TypeCode:    dt.TypeCode,
			Description: dt.Description,
			MaxLimit:    dt.MaxLimit,
			IsActive:    dt.IsActive,
			CreatedAt:   dt.CreatedAt,
			UpdatedAt:   dt.UpdatedAt,
		},
	})
}

func (h *TaxDeclarationHandler) ListDeclarationTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	types, err := h.taxService.ListDeclarationTypes(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to list declaration types", zap.Error(err))
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]declarationTypeResponse, 0, len(types))
	for _, dt := range types {
		resp = append(resp, declarationTypeResponse{
			CompanyID:   dt.CompanyID,
			TypeCode:    dt.TypeCode,
			Description: dt.Description,
			MaxLimit:    dt.MaxLimit,
			IsActive:    dt.IsActive,
			CreatedAt:   dt.CreatedAt,
			UpdatedAt:   dt.UpdatedAt,
		})
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *TaxDeclarationHandler) GetDeclarationType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	typeCode := chi.URLParam(r, "typeCode")
	if typeCode == "" {
		respondWithError(w, http.StatusBadRequest, "type code required")
		return
	}

	dt, err := h.taxService.GetDeclarationType(ctx, companyID, typeCode)
	if err != nil {
		h.logger.Error("failed to get declaration type", zap.Error(err))
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if dt == nil {
		respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    nil,
		})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": declarationTypeResponse{
			CompanyID:   dt.CompanyID,
			TypeCode:    dt.TypeCode,
			Description: dt.Description,
			MaxLimit:    dt.MaxLimit,
			IsActive:    dt.IsActive,
			CreatedAt:   dt.CreatedAt,
			UpdatedAt:   dt.UpdatedAt,
		},
	})
}

// ----------------------------------------------------------------------
// Declaration Handlers
// ----------------------------------------------------------------------

func (h *TaxDeclarationHandler) CreateDeclaration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	actorID, err := getAdminActor(ctx) // assuming admin creates on behalf of employee; adjust if needed
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createDeclarationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	declaration := &models.TaxDeclaration{
		CompanyID:       companyID,
		UserID:          req.UserID,
		FinancialYear:   req.FinancialYear,
		DeclarationType: req.DeclarationType,
		Amount:          req.Amount,
		SupportingDocs:  req.SupportingDocs,
		VerifiedBy:      &actorID, // creator is also verifier? The service uses VerifiedBy for audit.
	}

	created, err := h.taxService.CreateDeclaration(ctx, declaration)
	if err != nil {
		h.logger.Error("failed to create tax declaration", zap.Error(err))
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    mapDeclarationToResponse(created),
	})
}

func (h *TaxDeclarationHandler) UpdateDeclaration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	declarationID, err := parseUUIDParam(r, "declarationID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	actorID, err := getAdminActor(ctx)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req updateDeclarationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Construct a partial update object (only fields that can be updated)
	declaration := &models.TaxDeclaration{
		DeclarationID:  declarationID,
		Amount:         req.Amount,
		SupportingDocs: req.SupportingDocs,
		VerifiedBy:     &actorID, // used as updater for audit
	}

	updated, err := h.taxService.UpdateDeclaration(ctx, declaration)
	if err != nil {
		h.logger.Error("failed to update tax declaration", zap.Error(err))
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapDeclarationToResponse(updated),
	})
}

func (h *TaxDeclarationHandler) VerifyDeclaration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	declarationID, err := parseUUIDParam(r, "declarationID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	actorID, err := getAdminActor(ctx)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req verifyDeclarationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := h.taxService.VerifyDeclaration(ctx, declarationID, actorID, req.Status)
	if err != nil {
		h.logger.Error("failed to verify tax declaration", zap.Error(err))
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapDeclarationToResponse(updated),
	})
}

func (h *TaxDeclarationHandler) ListDeclarationsByUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := parseUUIDParam(r, "userID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	financialYear := r.URL.Query().Get("financial_year")
	if financialYear == "" {
		respondWithError(w, http.StatusBadRequest, "financial_year query parameter required")
		return
	}

	declarations, err := h.taxService.ListDeclarationsByUser(ctx, companyID, userID, financialYear)
	if err != nil {
		h.logger.Error("failed to list declarations by user", zap.Error(err))
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]declarationResponse, 0, len(declarations))
	for _, d := range declarations {
		resp = append(resp, mapDeclarationToResponse(&d))
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *TaxDeclarationHandler) ListDeclarationsByFinancialYear(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	financialYear := r.URL.Query().Get("financial_year")
	if financialYear == "" {
		respondWithError(w, http.StatusBadRequest, "financial_year query parameter required")
		return
	}
	var status *string
	if s := r.URL.Query().Get("status"); s != "" {
		status = &s
	}

	declarations, err := h.taxService.ListDeclarationsByFinancialYear(ctx, companyID, financialYear, status)
	if err != nil {
		h.logger.Error("failed to list declarations by financial year", zap.Error(err))
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]declarationResponse, 0, len(declarations))
	for _, d := range declarations {
		resp = append(resp, mapDeclarationToResponse(&d))
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *TaxDeclarationHandler) GetTotalDeclaredAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := parseUUIDParam(r, "userID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	financialYear := r.URL.Query().Get("financial_year")
	if financialYear == "" {
		respondWithError(w, http.StatusBadRequest, "financial_year query parameter required")
		return
	}
	onlyVerified := r.URL.Query().Get("only_verified") == "true"

	total, err := h.taxService.GetTotalDeclaredAmount(ctx, companyID, userID, financialYear, onlyVerified)
	if err != nil {
		h.logger.Error("failed to get total declared amount", zap.Error(err))
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"total": total,
		},
	})
}
