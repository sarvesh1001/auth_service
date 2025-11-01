// internal/models/audit.go
package models

import (
	"encoding/json"
	"net"
	"time"

	"github.com/google/uuid"
)

// AdminAuditLog represents an audit log entry for admin actions
// Stored in admin_audit_log table with 90-day retention
type AdminAuditLog struct {
	AuditBucket     int       `db:"audit_bucket" json:"audit_bucket"`
	AuditID         uuid.UUID `db:"audit_id" json:"audit_id"`
	AdminID         uuid.UUID `db:"admin_id" json:"admin_id"`
	ActionDate      string    `db:"action_date" json:"action_date"` // YYYY-MM-DD for bucketing
	ActionTime      time.Time `db:"action_time" json:"action_time"`
	ActionType      string    `db:"action_type" json:"action_type"`
	ResourceType    string    `db:"resource_type" json:"resource_type"`
	ResourceID      uuid.UUID `db:"resource_id" json:"resource_id"`
	OperationStatus string    `db:"operation_status" json:"operation_status"` // 'SUCCESS' | 'FAILURE'
	Changes         string    `db:"changes" json:"changes"` // JSON string of changes
	IPAddress       net.IP    `db:"ip_address" json:"ip_address"`
	UserAgent       string    `db:"user_agent" json:"user_agent"`
	OldValues       string    `db:"old_values" json:"old_values"` // JSON string of previous state
	NewValues       string    `db:"new_values" json:"new_values"` // JSON string of new state
	Reason          string    `db:"reason" json:"reason"` // Why the action was taken
	ErrorMessage    string    `db:"error_message" json:"error_message"` // If operation failed
}

// ActionType constants
const (
	ActionCreateUser      = "CREATE_USER"
	ActionUpdateUser      = "UPDATE_USER"
	ActionDeleteUser      = "DELETE_USER"
	ActionBlockUser       = "BLOCK_USER"
	ActionUnblockUser     = "UNBLOCK_USER"
	ActionBanUser         = "BAN_USER"
	ActionUnbanUser       = "UNBAN_USER"
	ActionVerifyKYC       = "VERIFY_KYC"
	ActionPromoteAdmin    = "PROMOTE_ADMIN"
	ActionDemoteAdmin     = "DEMOTE_ADMIN"
	ActionUpdatePermissions = "UPDATE_PERMISSIONS"
	ActionInvalidateSession = "INVALIDATE_SESSION"
	ActionExportData      = "EXPORT_DATA"
	ActionSystemConfig    = "SYSTEM_CONFIG"
	ActionAdminLogin      = "ADMIN_LOGIN"
	ActionAdminLogout     = "ADMIN_LOGOUT"
)

// ResourceType constants
const (
	ResourceTypeUser    = "USER"
	ResourceTypeAdmin   = "ADMIN"
	ResourceTypeSession = "SESSION"
	ResourceTypeOTP     = "OTP"
	ResourceTypeMPIN    = "MPIN"
	ResourceTypeSystem  = "SYSTEM"
)

// OperationStatus constants
const (
	StatusSuccess = "SUCCESS"
	StatusFailure = "FAILURE"
)

// AuditChange represents a single change in the audit log
type AuditChange struct {
	Field    string      `json:"field"`
	OldValue interface{} `json:"old_value"`
	NewValue interface{} `json:"new_value"`
}

// AuditChanges represents a collection of changes
type AuditChanges struct {
	Changes []AuditChange `json:"changes"`
}

// NewAuditLog creates a new audit log entry
func NewAuditLog(adminID uuid.UUID, actionType, resourceType string, resourceID uuid.UUID, status string) *AdminAuditLog {
	now := time.Now().UTC()
	return &AdminAuditLog{
		AuditBucket:     int(now.Unix() / 86400), // Daily bucket
		AuditID:         uuid.New(),
		AdminID:         adminID,
		ActionDate:      now.Format("2006-01-02"),
		ActionTime:      now,
		ActionType:      actionType,
		ResourceType:    resourceType,
		ResourceID:      resourceID,
		OperationStatus: status,
	}
}

// SetChanges sets the changes as JSON string
func (a *AdminAuditLog) SetChanges(changes []AuditChange) error {
	changesData := AuditChanges{Changes: changes}
	jsonData, err := json.Marshal(changesData)
	if err != nil {
		return err
	}
	a.Changes = string(jsonData)
	return nil
}

// GetChanges retrieves changes from JSON string
func (a *AdminAuditLog) GetChanges() ([]AuditChange, error) {
	var changesData AuditChanges
	if err := json.Unmarshal([]byte(a.Changes), &changesData); err != nil {
		return nil, err
	}
	return changesData.Changes, nil
}

// SetOldValues sets the old values as JSON string
func (a *AdminAuditLog) SetOldValues(values interface{}) error {
	jsonData, err := json.Marshal(values)
	if err != nil {
		return err
	}
	a.OldValues = string(jsonData)
	return nil
}

// SetNewValues sets the new values as JSON string
func (a *AdminAuditLog) SetNewValues(values interface{}) error {
	jsonData, err := json.Marshal(values)
	if err != nil {
		return err
	}
	a.NewValues = string(jsonData)
	return nil
}

// IsSuccess checks if the operation was successful
func (a *AdminAuditLog) IsSuccess() bool {
	return a.OperationStatus == StatusSuccess
}

// IsFailure checks if the operation failed
func (a *AdminAuditLog) IsFailure() bool {
	return a.OperationStatus == StatusFailure
}

// AuditLogFilter represents filters for querying audit logs
type AuditLogFilter struct {
	AdminID      *uuid.UUID
	ActionType   *string
	ResourceType *string
	ResourceID   *uuid.UUID
	StartDate    *time.Time
	EndDate      *time.Time
	Status       *string
	Limit        int
	PageState    []byte
}