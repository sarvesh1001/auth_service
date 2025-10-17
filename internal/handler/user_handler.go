package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// UserHandler handles HTTP requests for user operations
type UserHandler struct {
	userService *service.UserService
	logger      *zap.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService *service.UserService, logger *zap.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
	}
}

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// Meta represents pagination metadata
type Meta struct {
	PageToken string `json:"page_token,omitempty"`
	Total     int    `json:"total,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
}

// successResponse creates a successful response
func successResponse(data interface{}, message string) Response {
	return Response{
		Success: true,
		Data:    data,
		Message: message,
	}
}

// errorResponse creates an error response
func errorResponse(err error, message string) Response {
	return Response{
		Success: false,
		Error:   err.Error(),
		Message: message,
	}
}

// RegisterRoutes registers all user routes
func (h *UserHandler) RegisterRoutes(router chi.Router) {
	// User routes
	router.Route("/users", func(r chi.Router) {
		// Public routes
		r.Post("/", h.CreateUser)
		r.Get("/health", h.HealthCheck)

		// Protected routes (require authentication)
		r.Group(func(r chi.Router) {
			// Add auth middleware here in production
			r.Get("/{userID}", h.GetUserByID)
			r.Get("/phone/{phoneNumber}", h.GetUserByPhone)
			r.Put("/{userID}", h.UpdateUser)
			r.Patch("/{userID}/profile", h.UpdateUserProfile)
			r.Patch("/{userID}/status", h.UpdateUserStatus)
			r.Patch("/{userID}/last-login", h.UpdateLastLogin)

			// Batch operations
			r.Post("/batch", h.CreateUsersBatch)
			r.Post("/batch/get", h.GetUsersByIDBatch)
			r.Put("/batch", h.UpdateUsersBatch)

			// KYC operations
			r.Patch("/{userID}/kyc", h.UpdateKYCStatus)
			r.Get("/kyc/{status}", h.GetUsersByKYCStatus)
			r.Patch("/{userID}/consent", h.UpdateUserConsent)

			// Administrative operations
			r.Post("/{userID}/ban", h.BanUser)
			r.Post("/{userID}/unban", h.UnbanUser)
			r.Get("/banned", h.GetBannedUsers)

			// Stats
			r.Get("/stats", h.GetServiceStats)
		})
	})
}

// CreateUser handles user creation
// @Summary Create a new user
// @Description Create a new user with phone number and device information
// @Tags users
// @Accept json
// @Produce json
// @Param request body service.UserCreateRequest true "User creation request"
// @Success 201 {object} Response
// @Failure 400 {object} Response
// @Failure 409 {object} Response
// @Failure 500 {object} Response
// @Router /users [post]
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req service.UserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	user, err := h.userService.CreateUser(ctx, &req)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to create user")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(user, "User created successfully"))
	h.logger.Info("User created via HTTP",
		util.String("user_id", user.UserID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "CreateUser"),
	)
}

// GetUserByID handles user retrieval by ID
// @Summary Get user by ID
// @Description Get user details by user ID
// @Tags users
// @Produce json
// @Param userID path string true "User ID"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/{userID} [get]
func (h *UserHandler) GetUserByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	user, err := h.userService.GetUserByID(ctx, userID)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get user")
		return
	}

	// Remove sensitive data before responding
	h.sanitizeUser(user)

	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User retrieved successfully"))
	h.logger.Debug("User retrieved via HTTP",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "GetUserByID"),
	)
}

// GetUserByPhone handles user retrieval by phone number
// @Summary Get user by phone number
// @Description Get user details by phone number
// @Tags users
// @Produce json
// @Param phoneNumber path string true "Phone number"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/phone/{phoneNumber} [get]
func (h *UserHandler) GetUserByPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	phoneNumber := chi.URLParam(r, "phoneNumber")
	if phoneNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, errors.New("phone number is required"), "Phone number is required")
		return
	}

	user, err := h.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to get user by phone")
		return
	}

	// Remove sensitive data before responding
	h.sanitizeUser(user)

	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User retrieved successfully"))
	h.logger.Debug("User retrieved by phone via HTTP",
		util.String("phone", phoneNumber),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "GetUserByPhone"),
	)
}

// UpdateUser handles user updates
// @Summary Update user
// @Description Update user information
// @Tags users
// @Accept json
// @Produce json
// @Param userID path string true "User ID"
// @Param request body service.UserUpdateRequest true "User update request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/{userID} [put]
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	var req service.UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	user, err := h.userService.UpdateUser(ctx, userID, &req)
	if err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update user")
		return
	}

	// Remove sensitive data before responding
	h.sanitizeUser(user)

	h.respondWithJSON(w, http.StatusOK, successResponse(user, "User updated successfully"))
	h.logger.Info("User updated via HTTP",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UpdateUser"),
	)
}

// UpdateUserProfile handles user profile updates
// @Summary Update user profile
// @Description Update user profile service ID
// @Tags users
// @Accept json
// @Produce json
// @Param userID path string true "User ID"
// @Param request body map[string]interface{} true "Profile update request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/{userID}/profile [patch]
func (h *UserHandler) UpdateUserProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	var req struct {
		ProfileServiceID string `json:"profile_service_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	profileServiceID, err := uuid.Parse(req.ProfileServiceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid profile service ID format")
		return
	}

	if err := h.userService.UpdateUserProfile(ctx, userID, profileServiceID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update user profile")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User profile updated successfully"))
	h.logger.Info("User profile updated via HTTP",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UpdateUserProfile"),
	)
}

// UpdateUserStatus handles user status updates
// @Summary Update user status
// @Description Update user verification and status flags
// @Tags users
// @Accept json
// @Produce json
// @Param userID path string true "User ID"
// @Param request body map[string]bool true "Status update request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/{userID}/status [patch]
func (h *UserHandler) UpdateUserStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	var req struct {
		IsVerified bool `json:"is_verified"`
		IsBlocked  bool `json:"is_blocked"`
		IsBanned   bool `json:"is_banned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.userService.UpdateUserStatus(ctx, userID, req.IsVerified, req.IsBlocked, req.IsBanned); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update user status")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User status updated successfully"))
	h.logger.Info("User status updated via HTTP",
		util.String("user_id", userID.String()),
		util.Bool("verified", req.IsVerified),
		util.Bool("blocked", req.IsBlocked),
		util.Bool("banned", req.IsBanned),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UpdateUserStatus"),
	)
}

// UpdateLastLogin handles last login updates
// @Summary Update last login
// @Description Update user's last login timestamp
// @Tags users
// @Produce json
// @Param userID path string true "User ID"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/{userID}/last-login [patch]
func (h *UserHandler) UpdateLastLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	if err := h.userService.UpdateLastLogin(ctx, userID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update last login")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Last login updated successfully"))
	h.logger.Debug("Last login updated via HTTP",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UpdateLastLogin"),
	)
}

// Batch Operations

// CreateUsersBatch handles batch user creation
// @Summary Batch create users
// @Description Create multiple users in batch
// @Tags users
// @Accept json
// @Produce json
// @Param request body []service.UserCreateRequest true "Batch user creation requests"
// @Success 201 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /users/batch [post]
func (h *UserHandler) CreateUsersBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var requests []*service.UserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if len(requests) == 0 {
		h.respondWithError(w, http.StatusBadRequest, errors.New("empty batch"), "No users to create")
		return
	}

	if len(requests) > 1000 {
		h.respondWithError(w, http.StatusBadRequest, errors.New("batch too large"), "Batch size cannot exceed 1000 users")
		return
	}

	users, err := h.userService.CreateUsersBatch(ctx, requests)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to create users batch")
		return
	}

	// Remove sensitive data from all users
	for _, user := range users {
		h.sanitizeUser(user)
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(users, "Users created successfully"))
	h.logger.Info("Batch users created via HTTP",
		util.Int("users_created", len(users)),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "CreateUsersBatch"),
	)
}

// GetUsersByIDBatch handles batch user retrieval
// @Summary Batch get users
// @Description Get multiple users by their IDs
// @Tags users
// @Accept json
// @Produce json
// @Param request body []string true "Array of user IDs"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /users/batch/get [post]
func (h *UserHandler) GetUsersByIDBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var userIDs []string
	if err := json.NewDecoder(r.Body).Decode(&userIDs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if len(userIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, errors.New("empty batch"), "No user IDs provided")
		return
	}

	if len(userIDs) > 1000 {
		h.respondWithError(w, http.StatusBadRequest, errors.New("batch too large"), "Batch size cannot exceed 1000 users")
		return
	}

	// Convert string IDs to UUIDs
	uuidList := make([]uuid.UUID, 0, len(userIDs))
	for _, idStr := range userIDs {
		userID, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, fmt.Sprintf("Invalid user ID: %s", idStr))
			return
		}
		uuidList = append(uuidList, userID)
	}

	users, err := h.userService.GetUsersByIDBatch(ctx, uuidList)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get users batch")
		return
	}

	// Remove sensitive data from all users
	for _, user := range users {
		h.sanitizeUser(user)
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(users, "Users retrieved successfully"))
	h.logger.Debug("Batch users retrieved via HTTP",
		util.Int("users_retrieved", len(users)),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "GetUsersByIDBatch"),
	)
}

// UpdateUsersBatch handles batch user updates
// @Summary Batch update users
// @Description Update multiple users in batch
// @Tags users
// @Accept json
// @Produce json
// @Param request body map[string]service.UserUpdateRequest true "Map of user ID to update request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /users/batch [put]
func (h *UserHandler) UpdateUsersBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var updates map[string]service.UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if len(updates) == 0 {
		h.respondWithError(w, http.StatusBadRequest, errors.New("empty batch"), "No updates provided")
		return
	}

	if len(updates) > 1000 {
		h.respondWithError(w, http.StatusBadRequest, errors.New("batch too large"), "Batch size cannot exceed 1000 users")
		return
	}

	// Convert string keys to UUIDs
	uuidUpdates := make(map[uuid.UUID]*service.UserUpdateRequest)
	for userIDStr, update := range updates {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, err, fmt.Sprintf("Invalid user ID: %s", userIDStr))
			return
		}
		// Create a pointer to the update
		updateCopy := update
		uuidUpdates[userID] = &updateCopy
	}

	updatedUsers, err := h.userService.UpdateUsersBatch(ctx, uuidUpdates)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to update users batch")
		return
	}

	// Remove sensitive data from all users
	for _, user := range updatedUsers {
		h.sanitizeUser(user)
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(updatedUsers, "Users updated successfully"))
	h.logger.Info("Batch users updated via HTTP",
		util.Int("users_updated", len(updatedUsers)),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UpdateUsersBatch"),
	)
}

// KYC Operations

// UpdateKYCStatus handles KYC status updates
// @Summary Update KYC status
// @Description Update user's KYC verification status
// @Tags users
// @Accept json
// @Produce json
// @Param userID path string true "User ID"
// @Param request body service.KYCUpdateRequest true "KYC update request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/{userID}/kyc [patch]
func (h *UserHandler) UpdateKYCStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	var req service.KYCUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Set the user ID from URL path
	req.UserID = userID

	if err := h.userService.UpdateKYCStatus(ctx, &req); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update KYC status")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "KYC status updated successfully"))
	h.logger.Info("KYC status updated via HTTP",
		util.String("user_id", userID.String()),
		util.String("status", req.Status),
		util.String("level", req.Level),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UpdateKYCStatus"),
	)
}

// GetUsersByKYCStatus handles KYC status queries
// @Summary Get users by KYC status
// @Description Get users filtered by KYC status with pagination
// @Tags users
// @Produce json
// @Param status path string true "KYC status"
// @Param limit query int false "Page size (default: 100, max: 1000)"
// @Param page_token query string false "Page token for pagination"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /users/kyc/{status} [get]
func (h *UserHandler) GetUsersByKYCStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	status := chi.URLParam(r, "status")
	if status == "" {
		h.respondWithError(w, http.StatusBadRequest, errors.New("status is required"), "KYC status is required")
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	pageToken := r.URL.Query().Get("page_token")

	limit := 100 // default
	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit <= 0 || parsedLimit > 1000 {
			h.respondWithError(w, http.StatusBadRequest, errors.New("invalid limit"), "Limit must be between 1 and 1000")
			return
		}
		limit = parsedLimit
	}

	users, nextPageToken, err := h.userService.GetUsersByKYCStatus(ctx, status, limit, pageToken)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get users by KYC status")
		return
	}

	// Remove sensitive data from all users
	for _, user := range users {
		h.sanitizeUser(user)
	}

	response := successResponse(users, "Users retrieved successfully")
	if nextPageToken != "" {
		response.Meta = &Meta{
			PageToken: nextPageToken,
			PageSize:  limit,
			Total:     len(users),
		}
	}

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Users retrieved by KYC status via HTTP",
		util.String("status", status),
		util.Int("count", len(users)),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "GetUsersByKYCStatus"),
	)
}

// UpdateUserConsent handles consent updates
// @Summary Update user consent
// @Description Update user consent information
// @Tags users
// @Accept json
// @Produce json
// @Param userID path string true "User ID"
// @Param request body map[string]interface{} true "Consent update request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/{userID}/consent [patch]
func (h *UserHandler) UpdateUserConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	var req struct {
		Agreed  bool   `json:"agreed"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := h.userService.UpdateUserConsent(ctx, userID, req.Agreed, req.Version); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to update user consent")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User consent updated successfully"))
	h.logger.Info("User consent updated via HTTP",
		util.String("user_id", userID.String()),
		util.Bool("agreed", req.Agreed),
		util.String("version", req.Version),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UpdateUserConsent"),
	)
}

// Administrative Operations

// BanUser handles user banning
// @Summary Ban user
// @Description Ban a user with reason
// @Tags users
// @Accept json
// @Produce json
// @Param userID path string true "User ID"
// @Param request body service.BanUserRequest true "Ban request"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/{userID}/ban [post]
func (h *UserHandler) BanUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	var req service.BanUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Set the user ID from URL path
	req.UserID = userID

	if err := h.userService.BanUser(ctx, &req); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to ban user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User banned successfully"))
	h.logger.Warn("User banned via HTTP",
		util.String("user_id", userID.String()),
		util.String("banned_by", req.BannedBy.String()),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "BanUser"),
	)
}

// UnbanUser handles user unbanning
// @Summary Unban user
// @Description Unban a previously banned user
// @Tags users
// @Produce json
// @Param userID path string true "User ID"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Failure 500 {object} Response
// @Router /users/{userID}/unban [post]
func (h *UserHandler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID format")
		return
	}

	if err := h.userService.UnbanUser(ctx, userID); err != nil {
		statusCode := h.getStatusCode(err)
		h.respondWithError(w, statusCode, err, "Failed to unban user")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "User unbanned successfully"))
	h.logger.Info("User unbanned via HTTP",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "UnbanUser"),
	)
}

// GetBannedUsers handles banned users retrieval
// @Summary Get banned users
// @Description Get list of banned users with pagination
// @Tags users
// @Produce json
// @Param limit query int false "Page size (default: 100, max: 1000)"
// @Param page_token query string false "Page token for pagination"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /users/banned [get]
func (h *UserHandler) GetBannedUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	pageToken := r.URL.Query().Get("page_token")

	limit := 100 // default
	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit <= 0 || parsedLimit > 1000 {
			h.respondWithError(w, http.StatusBadRequest, errors.New("invalid limit"), "Limit must be between 1 and 1000")
			return
		}
		limit = parsedLimit
	}

	users, nextPageToken, err := h.userService.GetBannedUsers(ctx, limit, pageToken)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get banned users")
		return
	}

	// Remove sensitive data from all users
	for _, user := range users {
		h.sanitizeUser(user)
	}

	response := successResponse(users, "Banned users retrieved successfully")
	if nextPageToken != "" {
		response.Meta = &Meta{
			PageToken: nextPageToken,
			PageSize:  limit,
			Total:     len(users),
		}
	}

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Banned users retrieved via HTTP",
		util.Int("count", len(users)),
		util.Duration("duration", time.Since(startTime)),
		util.String("method", "GetBannedUsers"),
	)
}

// HealthCheck handles service health check
// @Summary Health check
// @Description Check if the user service is healthy
// @Tags users
// @Produce json
// @Success 200 {object} Response
// @Router /users/health [get]
func (h *UserHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.userService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, err, "Service unhealthy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Service is healthy"))
}

// GetServiceStats handles service statistics
// @Summary Get service statistics
// @Description Get user service statistics and metrics
// @Tags users
// @Produce json
// @Success 200 {object} Response
// @Failure 500 {object} Response
// @Router /users/stats [get]
func (h *UserHandler) GetServiceStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.userService.GetServiceStats(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get service stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Service stats retrieved successfully"))
}

// Helper Methods

// respondWithJSON sends a JSON response
func (h *UserHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", util.ErrorField(err))
	}
}

// respondWithError sends an error response
func (h *UserHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.logger.Warn("HTTP error response",
		util.ErrorField(err),
		util.Int("status_code", statusCode),
		util.String("message", message),
	)
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}

// getStatusCode determines the appropriate HTTP status code for an error
func (h *UserHandler) getStatusCode(err error) int {
	switch {
	case errors.Is(err, service.ErrUserNotFound):
		return http.StatusNotFound
	case errors.Is(err, service.ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, service.ErrUserAlreadyExists):
		return http.StatusConflict
	case errors.Is(err, service.ErrPermissionDenied):
		return http.StatusForbidden
	case errors.Is(err, service.ErrUserBanned), errors.Is(err, service.ErrUserBlocked):
		return http.StatusForbidden
	case errors.Is(err, service.ErrKYCRequired):
		return http.StatusPreconditionFailed
	default:
		return http.StatusInternalServerError
	}
}

// sanitizeUser removes sensitive data from user before sending in response
func (h *UserHandler) sanitizeUser(user *models.User) {
	// Clear encrypted phone data
	user.PhoneEncrypted = nil
	user.PhoneKeyID = uuid.Nil
	// Note: We keep phone hash for identification but not the encrypted version
}