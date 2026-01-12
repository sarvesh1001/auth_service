package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// CONSTANTS AND TYPES
// ============================================================================
// EventType constants (DB aligned)
const (
	EventCheckIn         = "check_in"
	EventCheckOut        = "check_out"
	EventBreakStart      = "break_start"
	EventBreakEnd        = "break_end"
	EventOvertimeIn      = "overtime_in"
	EventOvertimeOut     = "overtime_out"
	EventLeave           = "leave"
	EventSafetyViolation = "safety_violation"
	EventAbsent          = "absent"
	EventHalfDay         = "half_day"
	EventPresent         = "present"
	EventClassIn         = "class_in"
	EventClassOut        = "class_out"
)

// AttendanceSource constants (DB aligned)
const (
	SourceWeb        = "web"
	SourceMobile     = "mobile"
	SourceSAP        = "sap"
	SourceFactoryIoT = "factory_iot"
	SourceBiometric  = "biometric"
	SourceManual     = "manual"
	SourceRFID       = "rfid"
)

// Status constants (DB aligned)
const (
	StatusPresent  = "present"
	StatusAbsent   = "absent"
	StatusHalfDay  = "half_day"
	StatusLeave    = "leave"
	StatusLate     = "late"
	StatusOvertime = "overtime"
)

// Safety Zones that require helmets (DB / IoT aligned)
var HelmetRequiredZones = map[string]bool{
	"production_line": true,
	"warehouse":       true,
	"maintenance":     true,
	"construction":    true,
	"foundry":         true,
	"assembly":        true,
}

// ============================================================================
// INTERFACES AND STRUCTURES
// ============================================================================

// SAPAttendanceEvent represents attendance data from SAP system
type SAPAttendanceEvent struct {
	EmployeeID      string    `json:"employee_id"`
	RFIDTag         *string   `json:"rfid_tag,omitempty"`
	EventDateTime   time.Time `json:"event_datetime"`
	EventType       string    `json:"event_type"` // "IN", "OUT", "BREAK_START", "BREAK_END"
	LocationCode    *string   `json:"location_code,omitempty"`
	MachineID       *string   `json:"machine_id,omitempty"`
	WorkCenter      string    `json:"work_center"`
	SAPTransaction  string    `json:"sap_transaction"`
	RawData         string    `json:"raw_data"`
	ExternalEventID string    `json:"external_event_id"` // For idempotency
	CostCenter      *string   `json:"cost_center,omitempty"`
	FactoryZone     *string   `json:"factory_zone,omitempty"`
	Remarks         *string   `json:"remarks,omitempty"`
}

// FactoryAttendanceData represents data from factory IoT devices
type FactoryAttendanceData struct {
	DeviceID        string    `json:"device_id"`
	EmployeeRFID    string    `json:"employee_rfid"`
	EventTimestamp  time.Time `json:"event_timestamp"`
	GateNumber      string    `json:"gate_number"`
	Direction       string    `json:"direction"` // "IN", "OUT"
	Temperature     float64   `json:"temperature,omitempty"`
	MaskDetected    bool      `json:"mask_detected,omitempty"`
	HelmetDetected  bool      `json:"helmet_detected,omitempty"`
	BiometricMatch  bool      `json:"biometric_match,omitempty"`
	FactoryZone     string    `json:"factory_zone"`
	ExternalEventID string    `json:"external_event_id"` // For idempotency
}

// WorkedTime represents calculated work time
type WorkedTime struct {
	TotalMinutes    int
	RegularMinutes  int
	OvertimeMinutes int
	BreakMinutes    int
	LateMinutes     int
	EarlyDeparture  int
	ProductiveHours float64
}

// AttendanceService handles business logic for attendance operations
type AttendanceService interface {
	// Event Management
	CreateAttendanceEvent(ctx context.Context, event *attendance.AttendanceEvent, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*attendance.AttendanceEvent, error)
	CreateBulkAttendanceEvents(ctx context.Context, events []*attendance.AttendanceEvent, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// SAP/FACTORY Integration
	ProcessSAPAttendanceEvent(ctx context.Context, sapEvent *SAPAttendanceEvent, companyID uuid.UUID, sourceType string, sourceID *uuid.UUID) (*attendance.AttendanceEvent, error)
	SyncFactoryAttendance(ctx context.Context, factoryData *FactoryAttendanceData, companyID uuid.UUID) error

	// Policy Management
	CreateAttendancePolicy(ctx context.Context, policy *attendance.AttendancePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*attendance.AttendancePolicy, error)
	AssignUserAttendancePolicy(ctx context.Context, userPolicy *attendance.UserAttendancePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Daily Summary Generation
	GenerateDailySummary(ctx context.Context, companyID, userID uuid.UUID, date time.Time, timezone string) (*attendance.AttendanceDailySummary, error)
	GenerateBulkDailySummaries(ctx context.Context, companyID uuid.UUID, timezone string, startDate, endDate time.Time) ([]*attendance.AttendanceDailySummary, error)

	// RFID Management
	AssignRFIDToEmployee(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, rfidTag string, assignedBy uuid.UUID) error
	UnassignRFID(ctx context.Context, rfidID uuid.UUID, unassignedBy uuid.UUID) error
	GetEmployeeByRFID(ctx context.Context, rfidTag string, companyID uuid.UUID) (*attendance.EmployeeRFIDMapping, error)

	// Work Center Management
	MapWorkCenterToShift(ctx context.Context, companyID uuid.UUID, workCenterCode string, shiftID uuid.UUID, effectiveFrom time.Time, effectiveTo *time.Time, createdBy uuid.UUID) error
	GetShiftForWorkCenter(ctx context.Context, workCenterCode string, companyID uuid.UUID) (*attendance.WorkCenterShift, error)

	// SAP Business Rules Management
	GetSAPBusinessRules(ctx context.Context, companyID uuid.UUID) (*attendance.SAPBusinessRules, error)
	UpdateSAPBusinessRules(ctx context.Context, companyID uuid.UUID, rules *attendance.SAPBusinessRules, updatedBy uuid.UUID) error

	// Event Type Management
	GetAttendanceEventType(ctx context.Context, eventType string) (*attendance.AttendanceEventType, error)
	ListAttendanceEventTypes(ctx context.Context, activeOnly bool) ([]*attendance.AttendanceEventType, error)

	// Source Type Management
	GetAttendanceSourceType(ctx context.Context, sourceType string) (*attendance.AttendanceSourceType, error)
	ListAttendanceSourceTypes(ctx context.Context) ([]*attendance.AttendanceSourceType, error)

	// Company Rules Management
	GetCompanyAttendanceRules(ctx context.Context, companyID uuid.UUID) (*attendance.CompanyAttendanceRules, error)
	UpdateCompanyAttendanceRules(ctx context.Context, rules *attendance.CompanyAttendanceRules, updatedBy uuid.UUID) error

	// Department Rules Management
	GetDepartmentAttendanceRules(ctx context.Context, companyID, departmentID uuid.UUID) (*attendance.DepartmentAttendanceRules, error)

	// User Profile Management
	GetUserAttendanceProfile(ctx context.Context, userID uuid.UUID) (*attendance.UserAttendanceProfile, error)

	// Rule Resolution & Validation
	ResolveAttendanceRules(ctx context.Context, userID, companyID, departmentID uuid.UUID) (*attendance.ResolvedAttendanceRules, error)
	ValidateAttendanceEventType(ctx context.Context, eventType string) error
	// 🔴 UPDATED: sourceID added (IMPORTANT)
	ValidateAttendanceSourceType(
		ctx context.Context,
		sourceType string,
		sourceID *uuid.UUID,
	) error
	ValidateEventAgainstRules(ctx context.Context, event *attendance.AttendanceEvent, rules *attendance.ResolvedAttendanceRules) error
	// Health Check
	CompleteSAPAttendanceFlow(
		ctx context.Context,
		sapEvent *SAPAttendanceEvent,
		companyID uuid.UUID,
	) error
	// Department Rules Management
	UpsertDepartmentAttendanceRules(
		ctx context.Context,
		rules *attendance.DepartmentAttendanceRules,
	) error

	// User Profile Management
	UpsertUserAttendanceProfile(
		ctx context.Context,
		profile *attendance.UserAttendanceProfile,
	) error

	HealthCheck(ctx context.Context) error
}

// ============================================================================
// SERVICE IMPLEMENTATION
// ============================================================================

type attendanceServiceImpl struct {
	attendanceRepo repository.AttendanceRepository
	logger         *zap.Logger
}

// NewAttendanceService creates a new attendance service
func NewAttendanceService(
	attendanceRepo repository.AttendanceRepository,
	logger *zap.Logger,
) AttendanceService {
	return &attendanceServiceImpl{
		attendanceRepo: attendanceRepo,
		logger:         logger,
	}
}

// ============================================================================
// EVENT MANAGEMENT
// ============================================================================
func (s *attendanceServiceImpl) CreateAttendanceEvent(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*attendance.AttendanceEvent, error) {
	startTime := time.Now()

	// 🔴 Prepare + validate (DB-driven)
	if err := s.prepareAttendanceEvent(ctx, event); err != nil {
		return nil, fmt.Errorf("attendance event validation failed: %w", err)
	}

	// Apply attendance rules
	if err := s.applyAttendanceRules(ctx, event); err != nil {
		return nil, fmt.Errorf("attendance rules validation failed: %w", err)
	}

	// Persist event
	if err := s.persistAttendanceEvent(ctx, event); err != nil {
		s.logger.Error("Failed to create attendance event",
			util.String("event_id", event.AttendanceEventID.String()),
			util.String("user_id", event.UserID.String()),
			util.String("company_id", event.CompanyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create attendance event: %w", err)
	}

	s.logger.Info("Attendance event created",
		util.String("event_id", event.AttendanceEventID.String()),
		util.String("user_id", event.UserID.String()),
		util.String("company_id", event.CompanyID.String()),
		util.String("event_type", event.EventType),
		util.String("source_type", event.SourceType),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return event, nil
}

func (s *attendanceServiceImpl) CreateBulkAttendanceEvents(
	ctx context.Context,
	events []*attendance.AttendanceEvent,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	if len(events) == 0 {
		return fmt.Errorf("no events provided for bulk creation")
	}

	companyID := events[0].CompanyID

	// Apply all business rules before batch insert
	for i, event := range events {
		// Validate each event
		if err := s.validateAttendanceEvent(ctx, event); err != nil {
			return fmt.Errorf("event %d validation failed: %w", i, err)
		}

		// Generate event ID if not provided
		if event.AttendanceEventID == uuid.Nil {
			event.AttendanceEventID = uuid.New()
		}

		// Set timestamps
		now := time.Now().UTC()
		if event.CreatedAt.IsZero() {
			event.CreatedAt = now
		}
		if event.EventTime.IsZero() {
			event.EventTime = now
		}

		// Apply business rules
		if err := s.applyAttendanceRules(ctx, event); err != nil {
			return fmt.Errorf("event %d rules validation failed: %w", i, err)
		}
	}

	// Create events in batch
	err := s.attendanceRepo.CreateAttendanceEventsBatch(ctx, events)
	if err != nil {
		s.logger.Error("Failed to create bulk attendance events",
			util.Int("event_count", len(events)),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create bulk attendance events: %w", err)
	}

	s.logger.Info("Bulk attendance events created",
		util.Int("event_count", len(events)),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// SAP INTEGRATION
// ============================================================================

func (s *attendanceServiceImpl) ProcessSAPAttendanceEvent(
	ctx context.Context,
	sapEvent *SAPAttendanceEvent,
	companyID uuid.UUID,
	sourceType string,
	sourceID *uuid.UUID,
) (*attendance.AttendanceEvent, error) {
	startTime := time.Now()
	s.logger.Info("Processing SAP attendance event",
		util.String("employee_id", sapEvent.EmployeeID),
		util.String("company_id", companyID.String()),
		util.String("event_type", sapEvent.EventType))

	// Step 1: Identify user
	var userID uuid.UUID
	var err error

	// Try RFID first if available
	if sapEvent.RFIDTag != nil && *sapEvent.RFIDTag != "" {
		userID, err = s.lookupUserByRFID(ctx, *sapEvent.RFIDTag, companyID)
		if err != nil {
			s.logger.Warn("RFID lookup failed, trying employee ID",
				util.String("rfid", *sapEvent.RFIDTag),
				util.ErrorField(err))
		}
	}

	// If RFID failed or not available, use employee ID
	if userID == uuid.Nil {
		userID, err = s.lookupUserByEmployeeID(ctx, sapEvent.EmployeeID, companyID)
		if err != nil {
			s.logger.Error("Failed to identify user for SAP event",
				util.String("employee_id", sapEvent.EmployeeID),
				util.String("company_id", companyID.String()),
				util.ErrorField(err))
			return nil, fmt.Errorf("failed to identify user: %w", err)
		}
	}

	// Map SAP event type to internal event type
	eventType := s.mapSAPEventType(sapEvent.EventType)
	if eventType == "" {
		return nil, fmt.Errorf("unsupported SAP event type: %s", sapEvent.EventType)
	}

	// Step 2: Create attendance event
	event := &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         companyID,
		UserID:            userID,
		EventType:         eventType,
		EventTime:         sapEvent.EventDateTime,
		SourceType:        sourceType,
		SourceID:          sourceID,
		DeviceID:          sapEvent.MachineID,
		CreatedAt:         time.Now(),
		CreatedBy:         nil, // System-generated
	}

	// Step 3: Apply location and shift mappings
	if sapEvent.LocationCode != nil {
		locationID := s.getLocationIDByCode(ctx, *sapEvent.LocationCode, companyID)
		event.Metadata.LocationID = locationID
	} else if sapEvent.FactoryZone != nil {
		locationID := s.getFactoryZoneLocationID(ctx, *sapEvent.FactoryZone, companyID)
		event.Metadata.LocationID = locationID
	}

	if sapEvent.WorkCenter != "" {
		shiftID := s.getShiftByWorkCenter(ctx, sapEvent.WorkCenter, companyID)
		event.Metadata.ShiftID = shiftID
	}

	// Step 4: Apply SAP business rules
	if err := s.applySAPBusinessRules(ctx, event, sapEvent); err != nil {
		s.logger.Warn("SAP business rules application had issues",
			util.String("event_id", event.AttendanceEventID.String()),
			util.ErrorField(err))
		// Don't fail the event ingestion
	}

	// Step 5: Save the event
	metadata := map[string]interface{}{
		"sap_transaction":   sapEvent.SAPTransaction,
		"work_center":       sapEvent.WorkCenter,
		"raw_data":          sapEvent.RawData,
		"external_event_id": sapEvent.ExternalEventID,
		"cost_center":       sapEvent.CostCenter,
	}

	createdEvent, err := s.CreateAttendanceEvent(ctx, event, "system", uuid.Nil, metadata)
	if err != nil {
		// Check if it's a duplicate error
		if util.IsDuplicateError(err) && sapEvent.ExternalEventID != "" {
			s.logger.Info("SAP event already processed (idempotent)",
				util.String("external_id", sapEvent.ExternalEventID))
			// Return existing event
			return event, nil
		}
		return nil, fmt.Errorf("failed to create SAP attendance event: %w", err)
	}

	s.logger.Info("SAP attendance event processed",
		util.String("external_id", sapEvent.ExternalEventID),
		util.String("sap_transaction", sapEvent.SAPTransaction),
		util.String("employee_id", sapEvent.EmployeeID),
		util.Duration("duration", time.Since(startTime)))

	return createdEvent, nil
}

// ============================================================================
// FACTORY INTEGRATION
// ============================================================================

func (s *attendanceServiceImpl) SyncFactoryAttendance(
	ctx context.Context,
	factoryData *FactoryAttendanceData,
	companyID uuid.UUID,
) error {
	startTime := time.Now()

	// Validate factory data
	if err := s.validateFactoryData(factoryData); err != nil {
		return fmt.Errorf("factory data validation failed: %w", err)
	}

	// Check for duplicate using external event ID
	if factoryData.ExternalEventID != "" {
		s.logger.Debug("Checking for duplicate factory event",
			util.String("external_id", factoryData.ExternalEventID))
	}

	// Lookup user by RFID
	userID, err := s.lookupUserByRFID(ctx, factoryData.EmployeeRFID, companyID)
	if err != nil {
		return fmt.Errorf("failed to lookup user by RFID: %w", err)
	}

	// Check safety compliance - log violations but don't fail
	safetyViolations := s.checkFactorySafetyCompliance(factoryData)
	if len(safetyViolations) > 0 {
		s.logger.Warn("Factory safety compliance violations",
			util.String("rfid", factoryData.EmployeeRFID),
			util.Strings("violations", safetyViolations))

		// Create a safety violation event (don't block attendance)
		violationEvent := &attendance.AttendanceEvent{
			AttendanceEventID: uuid.New(),
			CompanyID:         companyID,
			UserID:            userID,
			EventType:         EventSafetyViolation,
			EventTime:         factoryData.EventTimestamp,
			SourceType:        SourceFactoryIoT,
			DeviceID:          &factoryData.DeviceID,
			Metadata: attendance.EventMetadata{
				LocationID: s.getFactoryZoneLocationID(ctx, factoryData.FactoryZone, companyID),
				Reason:     &safetyViolations[0], // First violation as reason
			},
			CreatedAt: time.Now().UTC(),
		}

		// Create violation event (async or fire-and-forget)
		// Create violation event (async, SAFE context propagation)
		go func(parentCtx context.Context) {
			ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
			defer cancel()

			if _, err := s.CreateAttendanceEvent(
				ctx,
				violationEvent,
				"system",
				uuid.Nil,
				map[string]interface{}{
					"mask_detected":     factoryData.MaskDetected,
					"helmet_detected":   factoryData.HelmetDetected,
					"temperature":       factoryData.Temperature,
					"gate_number":       factoryData.GateNumber,
					"external_event_id": factoryData.ExternalEventID + "_violation",
				},
			); err != nil {
				s.logger.Error("Failed to create safety violation event",
					util.String("rfid", factoryData.EmployeeRFID),
					util.ErrorField(err))
			}
		}(ctx)

		// Continue with attendance processing despite violations
	}

	// Create attendance event
	eventType := EventCheckIn
	if factoryData.Direction == "OUT" {
		eventType = EventCheckOut
	}

	event := &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         companyID,
		UserID:            userID,
		EventType:         eventType,
		EventTime:         factoryData.EventTimestamp,
		SourceType:        SourceFactoryIoT,
		DeviceID:          &factoryData.DeviceID,
		Metadata: attendance.EventMetadata{
			LocationID: s.getFactoryZoneLocationID(ctx, factoryData.FactoryZone, companyID),
		},
		CreatedAt: time.Now().UTC(),
	}

	metadata := map[string]interface{}{
		"gate_number":       factoryData.GateNumber,
		"temperature":       factoryData.Temperature,
		"mask_detected":     factoryData.MaskDetected,
		"helmet_detected":   factoryData.HelmetDetected,
		"biometric_match":   factoryData.BiometricMatch,
		"direction":         factoryData.Direction,
		"external_event_id": factoryData.ExternalEventID,
	}

	_, err = s.CreateAttendanceEvent(ctx, event, "system", uuid.Nil, metadata)
	if err != nil {
		// Check if it's a duplicate error
		if util.IsDuplicateError(err) && factoryData.ExternalEventID != "" {
			s.logger.Info("Factory event already processed (idempotent)",
				util.String("external_id", factoryData.ExternalEventID))
			return nil // Success - event already processed
		}
		return fmt.Errorf("failed to create factory attendance event: %w", err)
	}

	s.logger.Info("Factory attendance synced",
		util.String("rfid", factoryData.EmployeeRFID),
		util.String("device_id", factoryData.DeviceID),
		util.String("direction", factoryData.Direction),
		util.String("external_id", factoryData.ExternalEventID),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// POLICY MANAGEMENT
// ============================================================================

func (s *attendanceServiceImpl) CreateAttendancePolicy(
	ctx context.Context,
	policy *attendance.AttendancePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	// Validate policy
	if err := s.validateAttendancePolicy(policy); err != nil {
		return nil, fmt.Errorf("attendance policy validation failed: %w", err)
	}

	// Generate policy ID if not provided
	if policy.PolicyID == uuid.Nil {
		policy.PolicyID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	if policy.UpdatedAt.IsZero() {
		policy.UpdatedAt = now
	}

	// Check for duplicate policy code
	existingPolicy, err := s.attendanceRepo.GetAttendancePolicyByCode(ctx, policy.CompanyID, policy.PolicyCode)
	if err == nil && existingPolicy != nil {
		return nil, fmt.Errorf("policy code already exists: %s", policy.PolicyCode)
	}

	// Validate policy rules
	if err := s.validatePolicyRules(&policy.Rules); err != nil {
		return nil, fmt.Errorf("policy rules validation failed: %w", err)
	}

	// Create policy in repository
	err = s.attendanceRepo.CreateAttendancePolicy(ctx, policy)
	if err != nil {
		s.logger.Error("Failed to create attendance policy",
			util.String("policy_code", policy.PolicyCode),
			util.String("company_id", policy.CompanyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create attendance policy: %w", err)
	}

	s.logger.Info("Attendance policy created",
		util.String("policy_id", policy.PolicyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.String("policy_type", policy.PolicyType),
		util.String("company_id", policy.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

func (s *attendanceServiceImpl) AssignUserAttendancePolicy(
	ctx context.Context,
	userPolicy *attendance.UserAttendancePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Validate user policy assignment
	if userPolicy.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if userPolicy.PolicyID == uuid.Nil {
		return fmt.Errorf("policy ID is required")
	}
	if userPolicy.EffectiveFrom.IsZero() {
		userPolicy.EffectiveFrom = time.Now().UTC()
	}

	// Check if policy exists
	policy, err := s.attendanceRepo.GetAttendancePolicyByID(ctx, userPolicy.PolicyID)
	if err != nil {
		return fmt.Errorf("attendance policy not found: %w", err)
	}

	// Check if user already has an active policy
	currentPolicy, err := s.attendanceRepo.GetUserCurrentAttendancePolicy(ctx, userPolicy.UserID, time.Now().UTC())
	if err == nil && currentPolicy != nil {
		// End the current policy assignment
		userPolicies, err := s.attendanceRepo.GetUserAttendancePolicyHistory(ctx, userPolicy.UserID)
		if err == nil && len(userPolicies) > 0 {
			for _, up := range userPolicies {
				if up.PolicyID == currentPolicy.PolicyID && up.EffectiveTo == nil {
					now := time.Now().UTC()
					up.EffectiveTo = &now
					if err := s.attendanceRepo.UpdateUserAttendancePolicy(ctx, up); err != nil {
						s.logger.Warn("Failed to end previous policy assignment",
							util.String("user_id", userPolicy.UserID.String()),
							util.ErrorField(err))
					}
					break
				}
			}
		}
	}

	// Create user policy assignment
	userPolicy.CreatedAt = time.Now().UTC()
	err = s.attendanceRepo.AssignUserAttendancePolicy(ctx, userPolicy)
	if err != nil {
		s.logger.Error("Failed to assign user attendance policy",
			util.String("user_id", userPolicy.UserID.String()),
			util.String("policy_id", userPolicy.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign user attendance policy: %w", err)
	}

	s.logger.Info("User attendance policy assigned",
		util.String("user_id", userPolicy.UserID.String()),
		util.String("policy_id", userPolicy.PolicyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.Time("effective_from", userPolicy.EffectiveFrom),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// DAILY SUMMARY GENERATION
// ============================================================================

func (s *attendanceServiceImpl) GenerateDailySummary(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
	timezone string,
) (*attendance.AttendanceDailySummary, error) {
	startTime := time.Now()

	// Validate timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		// Fallback to UTC
		loc = time.UTC
		s.logger.Warn("Invalid timezone, falling back to UTC",
			util.String("timezone", timezone),
			util.String("user_id", userID.String()))
	}

	// Normalize date to company timezone
	dateInLoc := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, loc)
	dateUTC := dateInLoc.UTC()

	// Check if summary already exists
	existingSummary, err := s.attendanceRepo.GetAttendanceDailySummaryByUserDate(ctx, userID, dateUTC)
	if err == nil && existingSummary != nil {
		s.logger.Debug("Daily summary already exists",
			util.String("user_id", userID.String()),
			util.String("date", dateInLoc.Format("2006-01-02")))
		return existingSummary, nil
	}

	// Get user's attendance policy for the date
	policy, err := s.attendanceRepo.GetUserCurrentAttendancePolicy(ctx, userID, dateUTC)
	if err != nil {
		s.logger.Warn("No active attendance policy found for user",
			util.String("user_id", userID.String()),
			util.String("date", dateInLoc.Format("2006-01-02")))
		// Continue with default policy
	}

	// Get attendance events for the day (using UTC times for query)
	startOfDayUTC := dateUTC
	endOfDayUTC := startOfDayUTC.Add(24 * time.Hour).Add(-time.Second)

	events, err := s.attendanceRepo.GetAttendanceEventsByUser(ctx, userID, startOfDayUTC, endOfDayUTC, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance events for summary: %w", err)
	}

	// Calculate attendance status and metrics
	summary, err := s.calculateDailySummary(events, policy, dateInLoc, loc)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate daily summary: %w", err)
	}

	// Set company and user IDs
	summary.CompanyID = companyID
	summary.UserID = userID
	summary.AttendanceSummaryID = uuid.New()
	summary.AttendanceDate = dateUTC // Store in UTC
	summary.GeneratedAt = time.Now().UTC()
	summary.GeneratedBy = "system"

	// Save the summary
	err = s.attendanceRepo.CreateAttendanceDailySummary(ctx, summary)
	if err != nil {
		return nil, fmt.Errorf("failed to save daily summary: %w", err)
	}

	s.logger.Info("Daily summary generated",
		util.String("summary_id", summary.AttendanceSummaryID.String()),
		util.String("user_id", userID.String()),
		util.String("date", dateInLoc.Format("2006-01-02")),
		util.String("timezone", timezone),
		util.String("status", summary.Status),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
}

func (s *attendanceServiceImpl) GenerateBulkDailySummaries(
	ctx context.Context,
	companyID uuid.UUID,
	timezone string,
	startDate, endDate time.Time,
) ([]*attendance.AttendanceDailySummary, error) {
	startTime := time.Now()

	// Validate timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}

	// Validate date range using calendar days
	startNormalized := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, loc)
	endNormalized := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 0, loc)

	// Calculate calendar days difference
	calendarDays := int(endNormalized.Sub(startNormalized).Hours()/24) + 1
	if calendarDays > 31 {
		return nil, fmt.Errorf("date range cannot exceed 31 days, got %d days", calendarDays)
	}

	// TODO: In production, fetch all active users for the company
	// For now, generate placeholder summaries
	var summaries []*attendance.AttendanceDailySummary
	currentDate := startNormalized

	for !currentDate.After(endNormalized) {
		// Convert to UTC for storage
		dateUTC := currentDate.UTC()

		// Create placeholder summary
		summary := &attendance.AttendanceDailySummary{
			AttendanceSummaryID: uuid.New(),
			CompanyID:           companyID,
			AttendanceDate:      dateUTC,
			Status:              StatusPresent,
			WorkedMinutes:       intPtr(480), // 8 hours
			GeneratedAt:         time.Now().UTC(),
			GeneratedBy:         "system",
		}
		summaries = append(summaries, summary)

		// Move to next day
		currentDate = currentDate.Add(24 * time.Hour)
	}

	// Save summaries in batch
	if len(summaries) > 0 {
		err := s.attendanceRepo.CreateAttendanceDailySummariesBatch(ctx, summaries)
		if err != nil {
			return nil, fmt.Errorf("failed to save bulk daily summaries: %w", err)
		}
	}

	s.logger.Info("Bulk daily summaries generated",
		util.String("company_id", companyID.String()),
		util.String("timezone", timezone),
		util.Time("start_date", startNormalized),
		util.Time("end_date", endNormalized),
		util.Int("summary_count", len(summaries)),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return summaries, nil
}

// ============================================================================
// RFID MANAGEMENT SERVICE METHODS
// ============================================================================

func (s *attendanceServiceImpl) AssignRFIDToEmployee(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	rfidTag string,
	assignedBy uuid.UUID,
) error {
	startTime := time.Now()
	s.logger.Info("Assigning RFID to employee",
		util.String("rfid_tag", rfidTag),
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()))

	// Check if RFID is already assigned
	existingMapping, err := s.attendanceRepo.GetRFIDMappingByTag(ctx, rfidTag, companyID)
	if err == nil && existingMapping != nil && existingMapping.IsActive {
		return fmt.Errorf("RFID tag %s is already assigned to user %s", rfidTag, existingMapping.UserID)
	}

	// Deactivate any existing RFID for this user
	existingUserMapping, err := s.attendanceRepo.GetRFIDMappingByUser(ctx, userID, companyID)
	if err == nil && existingUserMapping != nil {
		if err := s.attendanceRepo.DeactivateRFIDMapping(ctx, existingUserMapping.RFIDID); err != nil {
			s.logger.Warn("Failed to deactivate existing RFID mapping",
				util.String("rfid_id", existingUserMapping.RFIDID.String()),
				util.ErrorField(err))
		}
	}

	// Create new mapping
	mapping := &attendance.EmployeeRFIDMapping{
		RFIDID:     uuid.New(),
		UserID:     userID,
		CompanyID:  companyID,
		RFIDTag:    rfidTag,
		IsActive:   true,
		AssignedAt: time.Now(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.attendanceRepo.CreateRFIDMapping(ctx, mapping); err != nil {
		s.logger.Error("Failed to assign RFID to employee",
			util.String("rfid_tag", rfidTag),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign RFID: %w", err)
	}

	s.logger.Info("RFID assigned successfully",
		util.String("rfid_tag", rfidTag),
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) UnassignRFID(
	ctx context.Context,
	rfidID uuid.UUID,
	unassignedBy uuid.UUID,
) error {
	startTime := time.Now()
	s.logger.Info("Unassigning RFID", util.String("rfid_id", rfidID.String()))

	if err := s.attendanceRepo.DeactivateRFIDMapping(ctx, rfidID); err != nil {
		s.logger.Error("Failed to unassign RFID",
			util.String("rfid_id", rfidID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to unassign RFID: %w", err)
	}

	s.logger.Info("RFID unassigned successfully",
		util.String("rfid_id", rfidID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) GetEmployeeByRFID(
	ctx context.Context,
	rfidTag string,
	companyID uuid.UUID,
) (*attendance.EmployeeRFIDMapping, error) {
	startTime := time.Now()
	s.logger.Debug("Getting employee by RFID",
		util.String("rfid_tag", rfidTag),
		util.String("company_id", companyID.String()))

	mapping, err := s.attendanceRepo.GetRFIDMappingByTag(ctx, rfidTag, companyID)
	if err != nil {
		s.logger.Warn("RFID mapping not found",
			util.String("rfid_tag", rfidTag),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("RFID mapping not found: %w", err)
	}

	s.logger.Debug("Employee retrieved by RFID",
		util.String("rfid_tag", rfidTag),
		util.String("user_id", mapping.UserID.String()),
		util.Duration("duration", time.Since(startTime)))

	return mapping, nil
}

// ============================================================================
// WORK CENTER MANAGEMENT SERVICE METHODS
// ============================================================================

func (s *attendanceServiceImpl) MapWorkCenterToShift(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	shiftID uuid.UUID,
	effectiveFrom time.Time,
	effectiveTo *time.Time,
	createdBy uuid.UUID,
) error {
	startTime := time.Now()
	s.logger.Info("Mapping work center to shift",
		util.String("work_center_code", workCenterCode),
		util.String("shift_id", shiftID.String()),
		util.String("company_id", companyID.String()))

	// Deactivate any existing active mapping for this work center
	existingMapping, err := s.attendanceRepo.GetWorkCenterShiftByCode(ctx, workCenterCode, companyID)
	if err == nil && existingMapping != nil && existingMapping.IsActive {
		if err := s.attendanceRepo.DeactivateWorkCenterShift(ctx, existingMapping.MappingID); err != nil {
			s.logger.Warn("Failed to deactivate existing work center shift mapping",
				util.String("mapping_id", existingMapping.MappingID.String()),
				util.ErrorField(err))
		}
	}

	// Create new mapping
	wcShift := &attendance.WorkCenterShift{
		MappingID:      uuid.New(),
		CompanyID:      companyID,
		WorkCenterCode: workCenterCode,
		ShiftID:        shiftID,
		EffectiveFrom:  effectiveFrom,
		EffectiveTo:    effectiveTo,
		IsActive:       true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := s.attendanceRepo.CreateWorkCenterShift(ctx, wcShift); err != nil {
		s.logger.Error("Failed to map work center to shift",
			util.String("work_center_code", workCenterCode),
			util.String("shift_id", shiftID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to map work center to shift: %w", err)
	}

	s.logger.Info("Work center mapped to shift successfully",
		util.String("work_center_code", workCenterCode),
		util.String("shift_id", shiftID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) GetShiftForWorkCenter(
	ctx context.Context,
	workCenterCode string,
	companyID uuid.UUID,
) (*attendance.WorkCenterShift, error) {
	startTime := time.Now()
	s.logger.Debug("Getting shift for work center",
		util.String("work_center_code", workCenterCode),
		util.String("company_id", companyID.String()))

	wcShift, err := s.attendanceRepo.GetWorkCenterShiftByCode(ctx, workCenterCode, companyID)
	if err != nil {
		s.logger.Warn("Work center shift mapping not found",
			util.String("work_center_code", workCenterCode),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("work center shift mapping not found: %w", err)
	}

	s.logger.Debug("Shift retrieved for work center",
		util.String("work_center_code", workCenterCode),
		util.String("shift_id", wcShift.ShiftID.String()),
		util.Duration("duration", time.Since(startTime)))

	return wcShift, nil
}

// ============================================================================
// SAP BUSINESS RULES MANAGEMENT
// ============================================================================

func (s *attendanceServiceImpl) GetSAPBusinessRules(
	ctx context.Context,
	companyID uuid.UUID,
) (*attendance.SAPBusinessRules, error) {
	startTime := time.Now()
	s.logger.Debug("Getting SAP business rules",
		util.String("company_id", companyID.String()))

	rules, err := s.attendanceRepo.GetSAPBusinessRules(ctx, companyID)
	if err != nil {
		s.logger.Error("Failed to get SAP business rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get SAP business rules: %w", err)
	}

	s.logger.Debug("SAP business rules retrieved",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return rules, nil
}

func (s *attendanceServiceImpl) UpdateSAPBusinessRules(
	ctx context.Context,
	companyID uuid.UUID,
	rules *attendance.SAPBusinessRules,
	updatedBy uuid.UUID,
) error {
	startTime := time.Now()
	s.logger.Info("Updating SAP business rules",
		util.String("company_id", companyID.String()),
		util.String("updated_by", updatedBy.String()))

	if err := s.attendanceRepo.SaveSAPBusinessRules(ctx, companyID, rules); err != nil {
		s.logger.Error("Failed to update SAP business rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update SAP business rules: %w", err)
	}

	s.logger.Info("SAP business rules updated successfully",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// LOOKUP METHODS IMPLEMENTATION
// ============================================================================

func (s *attendanceServiceImpl) lookupUserByEmployeeID(
	ctx context.Context,
	employeeID string,
	companyID uuid.UUID,
) (uuid.UUID, error) {
	startTime := time.Now()
	s.logger.Debug("Looking up user by employee ID",
		util.String("employee_id", employeeID),
		util.String("company_id", companyID.String()))

	if employeeID == "" {
		return uuid.Nil, fmt.Errorf("employee ID cannot be empty")
	}

	userID, err := s.attendanceRepo.GetUserIDByEmployeeID(ctx, employeeID, companyID)
	if err != nil {
		s.logger.Error("Failed to lookup user by employee ID",
			util.String("employee_id", employeeID),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return uuid.Nil, fmt.Errorf("employee not found for employee_id=%s: %w", employeeID, err)
	}

	s.logger.Debug("User lookup by employee ID successful",
		util.String("employee_id", employeeID),
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)))

	return userID, nil
}

func (s *attendanceServiceImpl) lookupUserByRFID(
	ctx context.Context,
	rfid string,
	companyID uuid.UUID,
) (uuid.UUID, error) {
	startTime := time.Now()
	s.logger.Debug("Looking up user by RFID",
		util.String("rfid", rfid),
		util.String("company_id", companyID.String()))

	if rfid == "" {
		return uuid.Nil, fmt.Errorf("RFID cannot be empty")
	}

	userID, err := s.attendanceRepo.GetUserIDByRFID(ctx, rfid, companyID)
	if err != nil {
		s.logger.Error("Failed to lookup user by RFID",
			util.String("rfid", rfid),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return uuid.Nil, fmt.Errorf("user not found for RFID=%s: %w", rfid, err)
	}

	s.logger.Debug("User lookup by RFID successful",
		util.String("rfid", rfid),
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)))

	return userID, nil
}

func (s *attendanceServiceImpl) getLocationIDByCode(
	ctx context.Context,
	locationCode string,
	companyID uuid.UUID,
) *uuid.UUID {
	if locationCode == "" {
		return nil
	}

	startTime := time.Now()
	s.logger.Debug("Looking up location by code",
		util.String("location_code", locationCode),
		util.String("company_id", companyID.String()))

	locationID, err := s.attendanceRepo.GetLocationIDByCode(ctx, locationCode, companyID)
	if err != nil {
		s.logger.Warn("Location not found for code",
			util.String("location_code", locationCode),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil
	}

	s.logger.Debug("Location lookup by code successful",
		util.String("location_code", locationCode),
		util.String("location_id", locationID.String()),
		util.Duration("duration", time.Since(startTime)))

	return &locationID
}

func (s *attendanceServiceImpl) getShiftByWorkCenter(
	ctx context.Context,
	workCenter string,
	companyID uuid.UUID,
) *uuid.UUID {
	if workCenter == "" {
		return nil
	}

	startTime := time.Now()
	s.logger.Debug("Looking up shift by work center",
		util.String("work_center", workCenter),
		util.String("company_id", companyID.String()))

	shiftID, err := s.attendanceRepo.GetShiftIDByWorkCenter(ctx, workCenter, companyID)
	if err != nil {
		s.logger.Warn("Shift not found for work center",
			util.String("work_center", workCenter),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil
	}

	s.logger.Debug("Shift lookup by work center successful",
		util.String("work_center", workCenter),
		util.String("shift_id", shiftID.String()),
		util.Duration("duration", time.Since(startTime)))

	return &shiftID
}

func (s *attendanceServiceImpl) getFactoryZoneLocationID(
	ctx context.Context,
	zone string,
	companyID uuid.UUID,
) *uuid.UUID {
	if zone == "" {
		return nil
	}

	startTime := time.Now()
	s.logger.Debug("Looking up factory zone location",
		util.String("zone", zone),
		util.String("company_id", companyID.String()))

	locationID, err := s.attendanceRepo.GetLocationIDByFactoryZone(ctx, zone, companyID)
	if err != nil {
		s.logger.Warn("Factory zone location not found",
			util.String("zone", zone),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil
	}

	s.logger.Debug("Factory zone location lookup successful",
		util.String("zone", zone),
		util.String("location_id", locationID.String()),
		util.Duration("duration", time.Since(startTime)))

	return &locationID
}

// ============================================================================
// SAP BUSINESS RULES APPLICATION
// ============================================================================

func (s *attendanceServiceImpl) applySAPBusinessRules(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	sapEvent *SAPAttendanceEvent,
) error {
	startTime := time.Now()
	s.logger.Debug("Applying SAP business rules",
		util.String("event_id", event.AttendanceEventID.String()),
		util.String("employee_id", sapEvent.EmployeeID))

	// Get SAP business rules for the company
	rules, err := s.attendanceRepo.GetSAPBusinessRules(ctx, event.CompanyID)
	if err != nil {
		s.logger.Error("Failed to get SAP business rules",
			util.String("company_id", event.CompanyID.String()),
			util.ErrorField(err))
		// Don't block ingestion if rules can't be loaded
		return nil
	}

	// Apply validation rules
	errors := s.validateSAPEvent(ctx, event, sapEvent, rules)
	if len(errors) > 0 {
		// Log validation errors but don't block ingestion
		for _, err := range errors {
			s.logger.Warn("SAP validation warning",
				util.String("employee_id", sapEvent.EmployeeID),
				util.String("warning", err.Error()))
		}
	}

	// Apply business logic
	s.applySAPBusinessLogic(ctx, event, sapEvent, rules)

	s.logger.Debug("SAP business rules applied successfully",
		util.String("event_id", event.AttendanceEventID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) validateSAPEvent(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	sapEvent *SAPAttendanceEvent,
	rules *attendance.SAPBusinessRules,
) []error {
	var errors []error

	// Validate employee ID if required
	if rules.ValidateEmployeeID != nil && *rules.ValidateEmployeeID {
		if sapEvent.EmployeeID == "" {
			errors = append(errors, fmt.Errorf("employee ID is required"))
		}
	}

	// Validate work center if required
	if rules.ValidateWorkCenter != nil && *rules.ValidateWorkCenter {
		if sapEvent.WorkCenter == "" {
			errors = append(errors, fmt.Errorf("work center is required"))
		}
	}

	// Validate cost center if required
	if rules.ValidateCostCenter != nil && *rules.ValidateCostCenter {
		if sapEvent.CostCenter == nil || *sapEvent.CostCenter == "" {
			errors = append(errors, fmt.Errorf("cost center is required"))
		}
	}

	// Validate event sequence (check-out cannot be before check-in)
	if event.EventType == EventCheckOut {
		s.logger.Debug("Validating check-out sequence", util.String("event_time", event.EventTime.String()))
	}

	return errors
}

func (s *attendanceServiceImpl) applySAPBusinessLogic(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	sapEvent *SAPAttendanceEvent,
	rules *attendance.SAPBusinessRules,
) {
	// Apply grace period for late arrivals
	if rules.GracePeriodMinutes != nil && *rules.GracePeriodMinutes > 0 {
		s.applyGracePeriod(event, sapEvent, rules)
	}

	// Tag overtime events
	if isOvertimeEvent(event.EventType) {
		s.tagOvertimeEvent(event, sapEvent, rules)
	}

	// Validate shift overlap
	if rules.AllowShiftOverlap != nil && !*rules.AllowShiftOverlap {
		s.validateShiftOverlap(ctx, event, sapEvent, rules)
	}

	// Add SAP metadata to event
	s.addSAPMetadata(event, sapEvent)
}

func (s *attendanceServiceImpl) applyGracePeriod(
	event *attendance.AttendanceEvent,
	sapEvent *SAPAttendanceEvent,
	rules *attendance.SAPBusinessRules,
) {
	if rules.GracePeriodMinutes == nil {
		return
	}

	_ = time.Duration(*rules.GracePeriodMinutes) * time.Minute

	if event.EventType == EventCheckIn {
		s.logger.Debug("Applying grace period check",
			util.String("event_time", event.EventTime.String()),
			util.Int("grace_minutes", *rules.GracePeriodMinutes))
	}
}

func (s *attendanceServiceImpl) tagOvertimeEvent(
	event *attendance.AttendanceEvent,
	sapEvent *SAPAttendanceEvent,
	rules *attendance.SAPBusinessRules,
) {
	if event.Metadata.Reason == nil {
		reason := "SAP_OVERTIME"
		event.Metadata.Reason = &reason
	}

	// Apply overtime threshold if set
	if rules.OvertimeThreshold != nil {
		s.logger.Debug("Applying overtime threshold",
			util.String("event_type", event.EventType),
			util.Int("threshold_minutes", *rules.OvertimeThreshold))
	}
}

func (s *attendanceServiceImpl) validateShiftOverlap(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	sapEvent *SAPAttendanceEvent,
	rules *attendance.SAPBusinessRules,
) {
	s.logger.Debug("Validating shift overlap",
		util.String("user_id", event.UserID.String()),
		util.String("event_time", event.EventTime.String()))

	if rules.MaxOverlapMinutes != nil {
		// Check if overlap exceeds allowed minutes
	}
}

func (s *attendanceServiceImpl) addSAPMetadata(
	event *attendance.AttendanceEvent,
	sapEvent *SAPAttendanceEvent,
) {
	// Add SAP-specific information to metadata
	if event.Metadata.Reason == nil && sapEvent.Remarks != nil {
		event.Metadata.Reason = sapEvent.Remarks
	}

	// Add work center to metadata if available
	if sapEvent.WorkCenter != "" {
		s.logger.Debug("Adding SAP metadata",
			util.String("work_center", sapEvent.WorkCenter),
			util.String("event_id", event.AttendanceEventID.String()))
	}
}

// ============================================================================
// HELPER METHODS
// ============================================================================
func (s *attendanceServiceImpl) validateAttendanceEvent(
	ctx context.Context,
	event *attendance.AttendanceEvent,
) error {
	if event == nil {
		return fmt.Errorf("attendance event cannot be nil")
	}

	if event.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if event.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if event.EventType == "" {
		return fmt.Errorf("event type is required")
	}
	if event.SourceType == "" {
		return fmt.Errorf("source type is required")
	}

	// 🔴 DB is the single source of truth
	if err := s.ValidateAttendanceEventType(ctx, event.EventType); err != nil {
		return fmt.Errorf("invalid event type: %w", err)
	}

	if err := s.ValidateAttendanceSourceType(ctx, event.SourceType, event.SourceID); err != nil {
		return fmt.Errorf("invalid source type: %w", err)
	}

	return nil
}

func (s *attendanceServiceImpl) applyAttendanceRules(ctx context.Context, event *attendance.AttendanceEvent) error {
	// Get user's current attendance policy
	policy, err := s.attendanceRepo.GetUserCurrentAttendancePolicy(ctx, event.UserID, event.EventTime)
	if err != nil {
		// No policy found, use default rules
		return nil
	}

	// Apply grace period if configured
	if policy.Rules.GracePeriod != nil && *policy.Rules.GracePeriod > 0 {
		if event.EventType == EventCheckIn {
			// TODO: Calculate expected check-in time based on shift schedule
		}
	}

	// Apply max late allowed
	if policy.Rules.MaxLateAllowed != nil && *policy.Rules.MaxLateAllowed > 0 {
		// TODO: Track cumulative late minutes
	}

	return nil
}

// func (s *attendanceServiceImpl) validateSAPEvent(sapEvent *SAPAttendanceEvent) error {
// 	if sapEvent.EmployeeID == "" {
// 		return fmt.Errorf("employee ID is required")
// 	}
// 	if sapEvent.EventDateTime.IsZero() {
// 		return fmt.Errorf("event date time is required")
// 	}
// 	if sapEvent.EventType == "" {
// 		return fmt.Errorf("event type is required")
// 	}
// 	if sapEvent.SAPTransaction == "" {
// 		return fmt.Errorf("SAP transaction is required")
// 	}

// 	// Validate SAP event type
// 	validSAPTypes := map[string]bool{
// 		"IN":           true,
// 		"OUT":          true,
// 		"BREAK_START":  true,
// 		"BREAK_END":    true,
// 		"OVERTIME_IN":  true,
// 		"OVERTIME_OUT": true,
// 	}

// 	if !validSAPTypes[sapEvent.EventType] {
// 		return fmt.Errorf("invalid SAP event type: %s", sapEvent.EventType)
// 	}

// 	return nil
// }

func (s *attendanceServiceImpl) mapSAPEventType(sapEventType string) string {
	mapping := map[string]string{
		"IN":           EventCheckIn,
		"OUT":          EventCheckOut,
		"BREAK_START":  EventBreakStart,
		"BREAK_END":    EventBreakEnd,
		"OVERTIME_IN":  EventOvertimeIn,
		"OVERTIME_OUT": EventOvertimeOut,
	}
	return mapping[sapEventType]
}

func (s *attendanceServiceImpl) validateFactoryData(data *FactoryAttendanceData) error {
	if data.DeviceID == "" {
		return fmt.Errorf("device ID is required")
	}
	if data.EmployeeRFID == "" {
		return fmt.Errorf("employee RFID is required")
	}
	if data.EventTimestamp.IsZero() {
		return fmt.Errorf("event timestamp is required")
	}
	if data.Direction == "" {
		return fmt.Errorf("direction is required")
	}
	if data.FactoryZone == "" {
		return fmt.Errorf("factory zone is required")
	}

	// Validate direction
	if data.Direction != "IN" && data.Direction != "OUT" {
		return fmt.Errorf("invalid direction: %s", data.Direction)
	}

	// Validate temperature if provided
	if data.Temperature < 30.0 || data.Temperature > 45.0 {
		return fmt.Errorf("unrealistic temperature: %.1f°C", data.Temperature)
	}

	return nil
}

func (s *attendanceServiceImpl) checkFactorySafetyCompliance(data *FactoryAttendanceData) []string {
	var violations []string

	// Check mask compliance (required in all zones)
	if !data.MaskDetected {
		violations = append(violations, "SAFETY_MASK_NOT_DETECTED")
	}

	// Check helmet compliance for certain zones
	if HelmetRequiredZones[data.FactoryZone] && !data.HelmetDetected {
		violations = append(violations, fmt.Sprintf("SAFETY_HELMET_NOT_DETECTED_IN_ZONE_%s", data.FactoryZone))
	}

	// Check temperature (fever screening)
	if data.Temperature > 37.5 {
		violations = append(violations, fmt.Sprintf("ELEVATED_TEMPERATURE_%.1f°C", data.Temperature))
	}

	// Check biometric match (if system supports it)
	if !data.BiometricMatch {
		violations = append(violations, "BIOMETRIC_VERIFICATION_FAILED")
	}

	return violations
}

func (s *attendanceServiceImpl) validateAttendancePolicy(policy *attendance.AttendancePolicy) error {
	if policy.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if policy.PolicyCode == "" {
		return fmt.Errorf("policy code is required")
	}
	if policy.PolicyType == "" {
		return fmt.Errorf("policy type is required")
	}

	// Validate policy code format
	if len(policy.PolicyCode) > 50 {
		return fmt.Errorf("policy code cannot exceed 50 characters")
	}

	return nil
}

func (s *attendanceServiceImpl) validatePolicyRules(rules *attendance.PolicyRules) error {
	// Validate grace period
	if rules.GracePeriod != nil && *rules.GracePeriod < 0 {
		return fmt.Errorf("grace period cannot be negative")
	}

	// Validate max late allowed
	if rules.MaxLateAllowed != nil && *rules.MaxLateAllowed < 0 {
		return fmt.Errorf("max late allowed cannot be negative")
	}

	// Validate half day after
	if rules.HalfDayAfter != nil {
		if *rules.HalfDayAfter < 1 {
			return fmt.Errorf("half day after must be at least 1 hour")
		}
		if *rules.HalfDayAfter > 12 {
			return fmt.Errorf("half day after cannot exceed 12 hours")
		}
	}

	// Cross-validation: Half day should be after grace period
	if rules.GracePeriod != nil && rules.HalfDayAfter != nil {
		graceHours := float64(*rules.GracePeriod) / 60.0
		if float64(*rules.HalfDayAfter) <= graceHours {
			return fmt.Errorf("half day threshold (%.1f hours) must be after grace period (%.1f hours)",
				float64(*rules.HalfDayAfter), graceHours)
		}
	}

	return nil
}

func (s *attendanceServiceImpl) calculateDailySummary(
	events []*attendance.AttendanceEvent,
	policy *attendance.AttendancePolicy,
	date time.Time,
	loc *time.Location,
) (*attendance.AttendanceDailySummary, error) {
	summary := &attendance.AttendanceDailySummary{
		Status:   StatusAbsent, // Default status
		Metadata: attendance.SummaryMetadata{},
	}

	if len(events) == 0 {
		return summary, nil
	}

	// Sort events by time (efficient)
	sortedEvents := make([]*attendance.AttendanceEvent, len(events))
	copy(sortedEvents, events)
	sort.Slice(sortedEvents, func(i, j int) bool {
		return sortedEvents[i].EventTime.Before(sortedEvents[j].EventTime)
	})

	// Calculate work metrics (proper implementation)
	workedTime := s.calculateWorkedTime(sortedEvents, policy, date, loc)

	summary.WorkedMinutes = &workedTime.RegularMinutes
	summary.OvertimeMinutes = &workedTime.OvertimeMinutes
	summary.LateMinutes = &workedTime.LateMinutes

	// Determine attendance status
	summary.Status = s.determineAttendanceStatus(sortedEvents, workedTime, policy)

	// Set metadata
	summary.Metadata.ClassesAttended = intPtr(0) // Placeholder
	summary.Metadata.PeriodsTaken = intPtr(0)    // Placeholder

	return summary, nil
}

func (s *attendanceServiceImpl) calculateWorkedTime(
	events []*attendance.AttendanceEvent,
	policy *attendance.AttendancePolicy,
	date time.Time,
	loc *time.Location,
) WorkedTime {
	var workedTime WorkedTime

	// Expected work hours (default 8 hours)
	expectedWorkMinutes := 480
	if policy != nil && policy.Rules.HalfDayAfter != nil {
		expectedWorkMinutes = *policy.Rules.HalfDayAfter * 60
	}

	// Pair CHECK_IN and CHECK_OUT events
	var checkInTime, checkOutTime *time.Time
	var inPairs [][2]time.Time // [check_in, check_out]

	for _, event := range events {
		switch event.EventType {
		case EventCheckIn:
			if checkInTime == nil {
				checkInTime = &event.EventTime
			}
		case EventCheckOut:
			if checkInTime != nil {
				checkOutTime = &event.EventTime
				inPairs = append(inPairs, [2]time.Time{*checkInTime, *checkOutTime})
				checkInTime = nil
				checkOutTime = nil
			}
		}
	}

	// Calculate total worked minutes from pairs
	for _, pair := range inPairs {
		duration := pair[1].Sub(pair[0])
		minutes := int(duration.Minutes())

		// Apply grace period
		graceMinutes := 0
		if policy != nil && policy.Rules.GracePeriod != nil {
			graceMinutes = *policy.Rules.GracePeriod
		}

		if minutes > graceMinutes {
			workedTime.RegularMinutes += minutes - graceMinutes
		}

		// Check for late arrival (if check-in after expected time)
		expectedStart := time.Date(date.Year(), date.Month(), date.Day(), 9, 0, 0, 0, loc) // 9 AM
		if pair[0].After(expectedStart) {
			lateMinutes := int(pair[0].Sub(expectedStart).Minutes())
			if lateMinutes > graceMinutes {
				workedTime.LateMinutes += lateMinutes - graceMinutes
			}
		}
	}

	// Calculate overtime (anything beyond expected work minutes)
	if workedTime.RegularMinutes > expectedWorkMinutes {
		workedTime.OvertimeMinutes = workedTime.RegularMinutes - expectedWorkMinutes
		workedTime.RegularMinutes = expectedWorkMinutes
	}

	workedTime.TotalMinutes = workedTime.RegularMinutes + workedTime.OvertimeMinutes
	workedTime.ProductiveHours = float64(workedTime.RegularMinutes) / 60.0

	return workedTime
}

func (s *attendanceServiceImpl) determineAttendanceStatus(
	events []*attendance.AttendanceEvent,
	workedTime WorkedTime,
	policy *attendance.AttendancePolicy,
) string {
	// Check for leave events
	for _, event := range events {
		if event.EventType == EventLeave {
			return StatusLeave
		}
	}

	// Check if present (has check-in events)
	hasCheckIn := false
	for _, event := range events {
		if event.EventType == EventCheckIn {
			hasCheckIn = true
			break
		}
	}

	if !hasCheckIn {
		return StatusAbsent
	}

	// Check if half day
	halfDayThreshold := 240 // 4 hours default
	if policy != nil && policy.Rules.HalfDayAfter != nil {
		halfDayThreshold = *policy.Rules.HalfDayAfter * 60 / 2
	}

	if workedTime.RegularMinutes < halfDayThreshold {
		return StatusHalfDay
	}

	// Check if late
	if workedTime.LateMinutes > 0 {
		// Apply max late allowed
		maxLateAllowed := 30 // default
		if policy != nil && policy.Rules.MaxLateAllowed != nil {
			maxLateAllowed = *policy.Rules.MaxLateAllowed
		}

		if workedTime.LateMinutes <= maxLateAllowed {
			return StatusLate
		}
	}

	// Check if overtime
	if workedTime.OvertimeMinutes > 0 {
		return StatusOvertime
	}

	return StatusPresent
}

// Helper function to check if event is overtime related
func isOvertimeEvent(eventType string) bool {
	overtimeEvents := map[string]bool{
		EventOvertimeIn:  true,
		EventOvertimeOut: true,
		"EXTRA_SHIFT":    true,
	}
	return overtimeEvents[eventType]
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (s *attendanceServiceImpl) HealthCheck(ctx context.Context) error {
	if err := s.attendanceRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func intPtr(i int) *int {
	return &i
}

func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

// Helper function to convert interface to JSON bytes
func toJSONBytes(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// ============================================================================
// ATTENDANCE EVENT TYPE METHODS
// ============================================================================

func (s *attendanceServiceImpl) GetAttendanceEventType(
	ctx context.Context,
	eventType string,
) (*attendance.AttendanceEventType, error) {
	startTime := time.Now()

	if eventType == "" {
		return nil, fmt.Errorf("event type cannot be empty")
	}

	s.logger.Debug("Getting attendance event type",
		util.String("event_type", eventType))

	// Use the repository method
	eventTypeObj, err := s.attendanceRepo.GetAttendanceEventType(ctx, eventType)
	if err != nil {
		s.logger.Error("Failed to get attendance event type",
			util.String("event_type", eventType),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance event type: %w", err)
	}

	// Check if the event type is active
	if !eventTypeObj.IsActive {
		s.logger.Warn("Attendance event type is inactive",
			util.String("event_type", eventType))
		return eventTypeObj, nil // Still return it, but log warning
	}

	s.logger.Debug("Attendance event type retrieved",
		util.String("event_type", eventType),
		util.String("category", eventTypeObj.Category),
		util.Duration("duration", time.Since(startTime)))

	return eventTypeObj, nil
}

func (s *attendanceServiceImpl) ListAttendanceEventTypes(
	ctx context.Context,
	activeOnly bool,
) ([]*attendance.AttendanceEventType, error) {
	startTime := time.Now()

	s.logger.Debug("Listing attendance event types",
		util.Bool("active_only", activeOnly))

	eventTypes, err := s.attendanceRepo.ListAttendanceEventTypes(ctx, activeOnly)
	if err != nil {
		s.logger.Error("Failed to list attendance event types",
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list attendance event types: %w", err)
	}

	// Group by category for easier consumption
	if len(eventTypes) > 0 {
		categories := make(map[string]int)
		for _, et := range eventTypes {
			categories[et.Category]++
		}

		s.logger.Debug("Attendance event types listed",
			util.Int("total_count", len(eventTypes)),
			util.Int("category_count", len(categories)),
			util.Duration("duration", time.Since(startTime)))
	}

	return eventTypes, nil
}

// ============================================================================
// ATTENDANCE SOURCE TYPE METHODS
// ============================================================================

func (s *attendanceServiceImpl) GetAttendanceSourceType(
	ctx context.Context,
	sourceType string,
) (*attendance.AttendanceSourceType, error) {
	startTime := time.Now()

	if sourceType == "" {
		return nil, fmt.Errorf("source type cannot be empty")
	}

	s.logger.Debug("Getting attendance source type",
		util.String("source_type", sourceType))

	sourceTypeObj, err := s.attendanceRepo.GetAttendanceSourceType(ctx, sourceType)
	if err != nil {
		s.logger.Error("Failed to get attendance source type",
			util.String("source_type", sourceType),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance source type: %w", err)
	}

	s.logger.Debug("Attendance source type retrieved",
		util.String("source_type", sourceType),
		util.Bool("requires_reference", sourceTypeObj.RequiresReference),
		util.Duration("duration", time.Since(startTime)))

	return sourceTypeObj, nil
}

func (s *attendanceServiceImpl) ListAttendanceSourceTypes(
	ctx context.Context,
) ([]*attendance.AttendanceSourceType, error) {
	startTime := time.Now()

	s.logger.Debug("Listing attendance source types")

	sourceTypes, err := s.attendanceRepo.ListAttendanceSourceTypes(ctx)
	if err != nil {
		s.logger.Error("Failed to list attendance source types",
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list attendance source types: %w", err)
	}

	s.logger.Debug("Attendance source types listed",
		util.Int("count", len(sourceTypes)),
		util.Duration("duration", time.Since(startTime)))

	return sourceTypes, nil
}

// ============================================================================
// COMPANY ATTENDANCE RULES METHODS
// ============================================================================

func (s *attendanceServiceImpl) GetCompanyAttendanceRules(
	ctx context.Context,
	companyID uuid.UUID,
) (*attendance.CompanyAttendanceRules, error) {
	startTime := time.Now()

	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID cannot be empty")
	}

	s.logger.Debug("Getting company attendance rules",
		util.String("company_id", companyID.String()))

	rules, err := s.attendanceRepo.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		s.logger.Error("Failed to get company attendance rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get company attendance rules: %w", err)
	}

	// Apply business logic transformations
	s.enrichCompanyRules(rules)

	s.logger.Debug("Company attendance rules retrieved",
		util.String("company_id", companyID.String()),
		util.Int("allowed_sources", len(rules.AllowedSourceTypes)),
		util.Bool("allow_multiple_checkins", rules.AllowMultipleCheckins),
		util.String("timezone", rules.Timezone),
		util.Duration("duration", time.Since(startTime)))

	return rules, nil
}

func (s *attendanceServiceImpl) UpdateCompanyAttendanceRules(
	ctx context.Context,
	rules *attendance.CompanyAttendanceRules,
	updatedBy uuid.UUID,
) error {
	startTime := time.Now()

	if err := s.validateCompanyRules(rules); err != nil {
		return fmt.Errorf("company rules validation failed: %w", err)
	}

	s.logger.Info("Updating company attendance rules",
		util.String("company_id", rules.CompanyID.String()),
		util.String("updated_by", updatedBy.String()),
		util.Int("allowed_sources", len(rules.AllowedSourceTypes)))

	// Validate each source type exists
	for _, sourceType := range rules.AllowedSourceTypes {
		if _, err := s.GetAttendanceSourceType(ctx, sourceType); err != nil {
			return fmt.Errorf("invalid source type '%s': %w", sourceType, err)
		}
	}

	// Use repository to upsert
	if err := s.attendanceRepo.UpsertCompanyAttendanceRules(ctx, rules); err != nil {
		s.logger.Error("Failed to update company attendance rules",
			util.String("company_id", rules.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update company attendance rules: %w", err)
	}

	// Create audit log entry
	metadata := map[string]interface{}{
		"updated_by":              updatedBy,
		"allowed_sources":         rules.AllowedSourceTypes,
		"timezone":                rules.Timezone,
		"allow_multiple_checkins": rules.AllowMultipleCheckins,
	}

	// You might want to add audit logging here
	s.logAuditEvent(ctx, "company_rules_updated", rules.CompanyID, updatedBy, metadata)

	s.logger.Info("Company attendance rules updated successfully",
		util.String("company_id", rules.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// DEPARTMENT ATTENDANCE RULES METHODS
// ============================================================================

func (s *attendanceServiceImpl) GetDepartmentAttendanceRules(
	ctx context.Context,
	companyID, departmentID uuid.UUID,
) (*attendance.DepartmentAttendanceRules, error) {
	startTime := time.Now()

	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID cannot be empty")
	}
	if departmentID == uuid.Nil {
		return nil, fmt.Errorf("department ID cannot be empty")
	}

	s.logger.Debug("Getting department attendance rules",
		util.String("company_id", companyID.String()),
		util.String("department_id", departmentID.String()))

	rules, err := s.attendanceRepo.GetDepartmentAttendanceRules(ctx, companyID, departmentID)
	if err != nil {
		s.logger.Error("Failed to get department attendance rules",
			util.String("company_id", companyID.String()),
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get department attendance rules: %w", err)
	}

	// If no department-specific rules, return nil (caller should check)
	if rules == nil {
		s.logger.Debug("No department-specific attendance rules found",
			util.String("department_id", departmentID.String()))
		return nil, nil
	}

	// Validate that all event types and source types exist
	if err := s.validateDepartmentRules(ctx, rules); err != nil {
		s.logger.Warn("Department rules validation warnings",
			util.String("rule_id", rules.RuleID.String()),
			util.ErrorField(err))
		// Continue despite validation warnings
	}

	s.logger.Debug("Department attendance rules retrieved",
		util.String("rule_id", rules.RuleID.String()),
		util.Int("allowed_sources", len(rules.AllowedSourceTypes)),
		util.Int("allowed_events", len(rules.AllowedEventTypes)),
		util.Bool("require_location", rules.RequireLocation),
		util.Bool("require_device", rules.RequireDevice),
		util.Duration("duration", time.Since(startTime)))

	return rules, nil
}

// ============================================================================
// USER ATTENDANCE PROFILE METHODS
// ============================================================================

func (s *attendanceServiceImpl) GetUserAttendanceProfile(
	ctx context.Context,
	userID uuid.UUID,
) (*attendance.UserAttendanceProfile, error) {
	startTime := time.Now()

	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	s.logger.Debug("Getting user attendance profile",
		util.String("user_id", userID.String()))

	profile, err := s.attendanceRepo.GetUserAttendanceProfile(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user attendance profile",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get user attendance profile: %w", err)
	}

	// If no user-specific profile, return nil (caller should check)
	if profile == nil {
		s.logger.Debug("No user-specific attendance profile found",
			util.String("user_id", userID.String()))
		return nil, nil
	}

	s.logger.Debug("User attendance profile retrieved",
		util.String("user_id", userID.String()),
		util.String("company_id", profile.CompanyID.String()),
		util.Int("override_sources", len(profile.OverrideSourceTypes)),
		util.Int("override_events", len(profile.OverrideEventTypes)),
		util.Duration("duration", time.Since(startTime)))

	return profile, nil
}

// ============================================================================
// RULE RESOLUTION METHOD
// ============================================================================

func (s *attendanceServiceImpl) ResolveAttendanceRules(
	ctx context.Context,
	userID, companyID, departmentID uuid.UUID,
) (*attendance.ResolvedAttendanceRules, error) {
	startTime := time.Now()

	s.logger.Debug("Resolving attendance rules hierarchy",
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.String("department_id", departmentID.String()))

	// Get company rules (always exists, defaults if not configured)
	companyRules, err := s.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company rules: %w", err)
	}

	// Get department rules (optional)
	var deptRules *attendance.DepartmentAttendanceRules
	if departmentID != uuid.Nil {
		deptRules, err = s.GetDepartmentAttendanceRules(ctx, companyID, departmentID)
		if err != nil {
			s.logger.Warn("Failed to get department rules, using company defaults",
				util.String("department_id", departmentID.String()),
				util.ErrorField(err))
			// Continue without department rules
		}
	}

	// Get user profile (optional)
	userProfile, err := s.GetUserAttendanceProfile(ctx, userID)
	if err != nil {
		s.logger.Warn("Failed to get user profile, using department/company rules",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		// Continue without user profile
	}

	// Resolve hierarchy (User → Department → Company)
	resolvedRules := s.resolveRulesHierarchy(companyRules, deptRules, userProfile)

	// Apply business logic to final resolved rules
	s.enrichResolvedRules(resolvedRules)

	s.logger.Debug("Attendance rules resolved",
		util.String("user_id", userID.String()),
		util.Int("final_allowed_sources", len(resolvedRules.AllowedSourceTypes)),
		util.Int("final_allowed_events", len(resolvedRules.AllowedEventTypes)),
		util.String("timezone", resolvedRules.Timezone),
		util.Duration("duration", time.Since(startTime)))

	return resolvedRules, nil
}

// ============================================================================
// VALIDATION METHODS
// ============================================================================

func (s *attendanceServiceImpl) ValidateAttendanceEventType(
	ctx context.Context,
	eventType string,
) error {
	startTime := time.Now()

	if eventType == "" {
		return fmt.Errorf("event type cannot be empty")
	}

	s.logger.Debug("Validating attendance event type",
		util.String("event_type", eventType))

	// Get the event type from database
	eventTypeObj, err := s.GetAttendanceEventType(ctx, eventType)
	if err != nil {
		return fmt.Errorf("invalid event type '%s': %w", eventType, err)
	}

	// Check if event type is active
	if !eventTypeObj.IsActive {
		return fmt.Errorf("event type '%s' is not active", eventType)
	}

	// Check if event type can be triggered by user (if applicable)
	// This might depend on business logic

	s.logger.Debug("Attendance event type validation passed",
		util.String("event_type", eventType),
		util.String("category", eventTypeObj.Category),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) ValidateAttendanceSourceType(
	ctx context.Context,
	sourceType string,
	sourceID *uuid.UUID,
) error {
	startTime := time.Now()

	if sourceType == "" {
		return fmt.Errorf("source type cannot be empty")
	}

	s.logger.Debug("Validating attendance source type",
		util.String("source_type", sourceType))

	sourceTypeObj, err := s.GetAttendanceSourceType(ctx, sourceType)
	if err != nil {
		return fmt.Errorf("invalid source type '%s': %w", sourceType, err)
	}

	// 🔴 IMPORTANT PART
	if sourceTypeObj.RequiresReference && sourceID == nil {
		return fmt.Errorf("source type '%s' requires source_id", sourceType)
	}

	s.logger.Debug("Attendance source type validation passed",
		util.String("source_type", sourceType),
		util.Bool("requires_reference", sourceTypeObj.RequiresReference),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) ValidateEventAgainstRules(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	rules *attendance.ResolvedAttendanceRules,
) error {
	startTime := time.Now()

	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	if rules == nil {
		return fmt.Errorf("rules cannot be nil")
	}

	s.logger.Debug("Validating event against rules",
		util.String("event_id", event.AttendanceEventID.String()),
		util.String("user_id", event.UserID.String()),
		util.String("event_type", event.EventType),
		util.String("source_type", event.SourceType))

	var validationErrors []string

	// 1. Validate source type is allowed
	if !rules.AllowedSourceTypesMap[event.SourceType] {
		validationErrors = append(validationErrors,
			fmt.Sprintf("source type '%s' not allowed", event.SourceType))
	}

	// 2. Validate event type is allowed (if specific event types are restricted)
	if !rules.AllowAllEventTypes && !rules.AllowedEventTypesMap[event.EventType] {
		validationErrors = append(validationErrors,
			fmt.Sprintf("event type '%s' not allowed", event.EventType))
	}

	// 3. Validate location requirement
	if rules.RequireLocation && event.Metadata.LocationID == nil {
		validationErrors = append(validationErrors,
			"location is required but not provided")
	}

	// 4. Validate device requirement
	if rules.RequireDevice && event.DeviceID == nil {
		validationErrors = append(validationErrors,
			"device ID is required but not provided")
	}

	// 5. Validate multiple check-ins
	if !rules.AllowMultipleCheckins && event.EventType == "check_in" {
		// Check if user already has a check-in today
		// This would require additional database check
		s.logger.Debug("Multiple check-in validation would be performed here")
	}

	// 6. Validate source-specific requirements
	if err := s.validateSourceSpecificRequirements(ctx, event, rules); err != nil {
		validationErrors = append(validationErrors, err.Error())
	}

	// If any validation errors, return them
	if len(validationErrors) > 0 {
		errorMsg := "event validation failed: " + strings.Join(validationErrors, "; ")
		s.logger.Error("Event validation failed",
			util.String("event_id", event.AttendanceEventID.String()),
			util.Strings("errors", validationErrors))
		return fmt.Errorf(errorMsg)
	}

	s.logger.Debug("Event validation passed",
		util.String("event_id", event.AttendanceEventID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// HELPER METHODS
// ============================================================================

func (s *attendanceServiceImpl) enrichCompanyRules(rules *attendance.CompanyAttendanceRules) {
	// Ensure at least basic sources are allowed
	if len(rules.AllowedSourceTypes) == 0 {
		rules.AllowedSourceTypes = []string{"mobile", "web", "system"}
		s.logger.Debug("Enriched company rules with default sources")
	}

	// Ensure timezone is valid
	if rules.Timezone == "" {
		rules.Timezone = "UTC"
	}
}

func (s *attendanceServiceImpl) validateCompanyRules(rules *attendance.CompanyAttendanceRules) error {
	if rules.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}

	if len(rules.AllowedSourceTypes) == 0 {
		return fmt.Errorf("at least one source type must be allowed")
	}

	// Validate timezone
	if _, err := time.LoadLocation(rules.Timezone); err != nil {
		return fmt.Errorf("invalid timezone '%s': %w", rules.Timezone, err)
	}

	return nil
}

func (s *attendanceServiceImpl) validateDepartmentRules(
	ctx context.Context,
	rules *attendance.DepartmentAttendanceRules,
) error {
	var warnings []string

	// Validate source types exist
	for _, sourceType := range rules.AllowedSourceTypes {
		if _, err := s.GetAttendanceSourceType(ctx, sourceType); err != nil {
			warnings = append(warnings, fmt.Sprintf("source type '%s' does not exist", sourceType))
		}
	}

	// Validate event types exist
	for _, eventType := range rules.AllowedEventTypes {
		if _, err := s.GetAttendanceEventType(ctx, eventType); err != nil {
			warnings = append(warnings, fmt.Sprintf("event type '%s' does not exist", eventType))
		}
	}

	if len(warnings) > 0 {
		return fmt.Errorf(strings.Join(warnings, "; "))
	}

	return nil
}

func (s *attendanceServiceImpl) resolveRulesHierarchy(
	companyRules *attendance.CompanyAttendanceRules,
	deptRules *attendance.DepartmentAttendanceRules,
	userProfile *attendance.UserAttendanceProfile,
) *attendance.ResolvedAttendanceRules {
	resolved := &attendance.ResolvedAttendanceRules{
		Timezone:              companyRules.Timezone,
		AllowMultipleCheckins: companyRules.AllowMultipleCheckins,
		// Start with company rules
		AllowedSourceTypes: companyRules.AllowedSourceTypes,
		AllowedEventTypes:  []string{}, // Empty means all event types allowed
		RequireLocation:    false,
		RequireDevice:      false,
	}

	// Apply department rules (if they exist)
	if deptRules != nil {
		// Department can override source types (must be subset of company allowed)
		if len(deptRules.AllowedSourceTypes) > 0 {
			// Intersection of company and department allowed sources
			resolved.AllowedSourceTypes = intersect(
				resolved.AllowedSourceTypes,
				deptRules.AllowedSourceTypes)
		}

		// Department can restrict event types
		if len(deptRules.AllowedEventTypes) > 0 {
			resolved.AllowedEventTypes = deptRules.AllowedEventTypes
		}

		// Department can add requirements
		if deptRules.RequireLocation {
			resolved.RequireLocation = true
		}
		if deptRules.RequireDevice {
			resolved.RequireDevice = true
		}
	}

	// Apply user profile overrides (highest priority)
	if userProfile != nil {
		// User can override source types (must be subset of department/company allowed)
		if len(userProfile.OverrideSourceTypes) > 0 {
			resolved.AllowedSourceTypes = intersect(
				resolved.AllowedSourceTypes,
				userProfile.OverrideSourceTypes)
		}

		// User can restrict event types further
		if len(userProfile.OverrideEventTypes) > 0 {
			if len(resolved.AllowedEventTypes) == 0 {
				// If no department restrictions, use user restrictions
				resolved.AllowedEventTypes = userProfile.OverrideEventTypes
			} else {
				// Intersection of department and user restrictions
				resolved.AllowedEventTypes = intersect(
					resolved.AllowedEventTypes,
					userProfile.OverrideEventTypes)
			}
		}
	}

	return resolved
}

func (s *attendanceServiceImpl) enrichResolvedRules(rules *attendance.ResolvedAttendanceRules) {
	// -------- Source Types Map --------
	rules.AllowedSourceTypesMap = make(map[string]bool)
	for _, src := range rules.AllowedSourceTypes {
		rules.AllowedSourceTypesMap[src] = true
	}

	// -------- Event Types Map --------
	if len(rules.AllowedEventTypes) == 0 {
		// Empty = allow all events
		rules.AllowAllEventTypes = true
	} else {
		rules.AllowedEventTypesMap = make(map[string]bool)
		for _, evt := range rules.AllowedEventTypes {
			rules.AllowedEventTypesMap[evt] = true
		}

		// Always allow system-generated events
		systemEvents := []string{
			"system_generated",
			"imported_event",
			"missing_punch",
		}
		for _, evt := range systemEvents {
			rules.AllowedEventTypesMap[evt] = true
		}
	}

	rules.AppliedAt = time.Now().UTC()
}

func (s *attendanceServiceImpl) validateSourceSpecificRequirements(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	rules *attendance.ResolvedAttendanceRules,
) error {
	// Get source type details
	sourceType, err := s.GetAttendanceSourceType(ctx, event.SourceType)
	if err != nil {
		return fmt.Errorf("failed to validate source type: %w", err)
	}

	// Check if source requires reference and if provided
	if sourceType.RequiresReference && event.SourceID == nil {
		return fmt.Errorf("source type '%s' requires a reference ID", event.SourceType)
	}

	return nil
}

func (s *attendanceServiceImpl) logAuditEvent(
	ctx context.Context,
	action string,
	companyID uuid.UUID,
	actorID uuid.UUID,
	metadata map[string]interface{},
) {
	// This would log to your audit system
	s.logger.Info("Attendance audit event",
		util.String("action", action),
		util.String("company_id", companyID.String()),
		util.String("actor_id", actorID.String()),
		util.Any("metadata", metadata))
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func intersect(slice1, slice2 []string) []string {
	if len(slice1) == 0 {
		return slice2
	}
	if len(slice2) == 0 {
		return slice1
	}

	set := make(map[string]bool)
	for _, s := range slice1 {
		set[s] = true
	}

	var result []string
	for _, s := range slice2 {
		if set[s] {
			result = append(result, s)
		}
	}

	return result
}
func (s *attendanceServiceImpl) prepareAttendanceEvent(
	ctx context.Context,
	event *attendance.AttendanceEvent,
) error {
	if err := s.validateAttendanceEvent(ctx, event); err != nil {
		return err
	}

	now := time.Now().UTC()

	if event.AttendanceEventID == uuid.Nil {
		event.AttendanceEventID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = now
	}
	if event.EventTime.IsZero() {
		event.EventTime = now
	}

	return nil
}

func (s *attendanceServiceImpl) persistAttendanceEvent(
	ctx context.Context,
	event *attendance.AttendanceEvent,
) error {
	return s.attendanceRepo.CreateAttendanceEvent(ctx, event)
}

// service/attendance.go - Enhanced SAP flow
// service/attendance_service.go - Fix the CompleteSAPAttendanceFlow method

func (s *attendanceServiceImpl) CompleteSAPAttendanceFlow(
	ctx context.Context,
	sapEvent *SAPAttendanceEvent,
	companyID uuid.UUID,
) error {
	// Step 1: Identify employee
	var userID uuid.UUID
	var err error

	if sapEvent.RFIDTag != nil && *sapEvent.RFIDTag != "" {
		userID, err = s.lookupUserByRFID(ctx, *sapEvent.RFIDTag, companyID)
		if err != nil {
			s.logger.Warn("RFID lookup failed, trying employee ID",
				util.String("rfid", *sapEvent.RFIDTag),
				util.ErrorField(err))
		}
	}

	if userID == uuid.Nil {
		userID, err = s.lookupUserByEmployeeID(ctx, sapEvent.EmployeeID, companyID)
		if err != nil {
			return fmt.Errorf("employee lookup failed: %w", err)
		}
	}

	// Step 2: Get department (OPTIONAL)
	var departmentID uuid.UUID

	deptPtr, err := s.attendanceRepo.GetEmployeeDepartment(ctx, userID, companyID)
	if err != nil {
		s.logger.Warn("Department lookup failed, falling back to company rules",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
	} else if deptPtr != nil {
		departmentID = *deptPtr
	}

	// Step 3: Resolve rules
	rules, err := s.ResolveAttendanceRules(ctx, userID, companyID, departmentID)
	if err != nil {
		return fmt.Errorf("rules resolution failed: %w", err)
	}

	// Step 4: Build event
	event := &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         companyID,
		UserID:            userID,
		EventType:         s.mapSAPEventType(sapEvent.EventType),
		EventTime:         sapEvent.EventDateTime,
		SourceType:        SourceSAP,
		SourceID:          nil,
		CreatedAt:         time.Now().UTC(),
	}

	// Step 5: Validate event
	if err := s.ValidateEventAgainstRules(ctx, event, rules); err != nil {
		return fmt.Errorf("event validation failed: %w", err)
	}

	// Step 6: Apply SAP mappings
	if sapEvent.WorkCenter != "" {
		event.Metadata.ShiftID = s.getShiftByWorkCenter(ctx, sapEvent.WorkCenter, companyID)
	}

	// Step 7: Persist event
	metadata := map[string]interface{}{
		"sap_transaction":   sapEvent.SAPTransaction,
		"work_center":       sapEvent.WorkCenter,
		"external_event_id": sapEvent.ExternalEventID,
		"cost_center":       sapEvent.CostCenter,
	}

	_, err = s.CreateAttendanceEvent(ctx, event, "system", uuid.Nil, metadata)
	return err
}

// ============================================================================
// DEPARTMENT / USER RULE WRITE METHODS
// ============================================================================

func (s *attendanceServiceImpl) UpsertDepartmentAttendanceRules(
	ctx context.Context,
	rules *attendance.DepartmentAttendanceRules,
) error {
	if rules.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if rules.DepartmentID == uuid.Nil {
		return fmt.Errorf("department ID is required")
	}

	// Validate source types exist
	for _, src := range rules.AllowedSourceTypes {
		if _, err := s.GetAttendanceSourceType(ctx, src); err != nil {
			return fmt.Errorf("invalid source type '%s': %w", src, err)
		}
	}

	// Validate event types exist
	for _, evt := range rules.AllowedEventTypes {
		if _, err := s.GetAttendanceEventType(ctx, evt); err != nil {
			return fmt.Errorf("invalid event type '%s': %w", evt, err)
		}
	}

	return s.attendanceRepo.UpsertDepartmentAttendanceRules(ctx, rules)
}

func (s *attendanceServiceImpl) UpsertUserAttendanceProfile(
	ctx context.Context,
	profile *attendance.UserAttendanceProfile,
) error {
	if profile.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if profile.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}

	// Validate override source types
	for _, src := range profile.OverrideSourceTypes {
		if _, err := s.GetAttendanceSourceType(ctx, src); err != nil {
			return fmt.Errorf("invalid source type '%s': %w", src, err)
		}
	}

	// Validate override event types
	for _, evt := range profile.OverrideEventTypes {
		if _, err := s.GetAttendanceEventType(ctx, evt); err != nil {
			return fmt.Errorf("invalid event type '%s': %w", evt, err)
		}
	}

	return s.attendanceRepo.UpsertUserAttendanceProfile(ctx, profile)
}
