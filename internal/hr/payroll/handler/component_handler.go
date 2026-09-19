package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"
)

// ComponentHandler handles HTTP requests for payroll components.
type ComponentHandler struct {
	componentService service.ComponentService
}

// NewComponentHandler creates a new component handler.
func NewComponentHandler(componentService service.ComponentService) *ComponentHandler {
	return &ComponentHandler{
		componentService: componentService,
	}
}

// ListComponents returns all components for a given company.
// GET /companies/{companyID}/components
func (h *ComponentHandler) ListComponents(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	components, err := h.componentService.GetComponents(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve components")
		return
	}

	if components == nil {
		components = make(map[string]*models.PayrollComponent)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    components,
	})
}

// GetComponent returns a single component by its code.
// GET /companies/{companyID}/components/{code}
func (h *ComponentHandler) GetComponent(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	code := chi.URLParam(r, "code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "component code required")
		return
	}

	component, err := h.componentService.GetComponent(ctx, companyID, code)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve component")
		return
	}
	if component == nil {
		h.respondWithError(w, http.StatusNotFound, "component not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    component,
	})
}

// GetDefaultComponent returns the default component code for a given purpose.
// GET /companies/{companyID}/components/default?purpose={fine|arrears|loan|basic}
func (h *ComponentHandler) GetDefaultComponent(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	purpose := r.URL.Query().Get("purpose")
	if purpose == "" {
		h.respondWithError(w, http.StatusBadRequest, "purpose query parameter is required")
		return
	}

	allowedPurposes := map[string]bool{"fine": true, "arrears": true, "loan": true, "basic": true}
	if !allowedPurposes[purpose] {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Sprintf("invalid purpose, must be one of: fine, arrears, loan, basic"))
		return
	}

	code, err := h.componentService.GetDefaultComponent(ctx, companyID, purpose)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve default component")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    code,
	})
}

// ClearCache clears the in‑memory component cache for a company.
// POST /companies/{companyID}/components/clear-cache
func (h *ComponentHandler) ClearCache(w http.ResponseWriter, r *http.Request) {

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.componentService.ClearCache(companyID)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "cache cleared",
	})
}

// ----------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------

func (h *ComponentHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *ComponentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}

// parseUUIDParam extracts and parses a UUID path parameter.
