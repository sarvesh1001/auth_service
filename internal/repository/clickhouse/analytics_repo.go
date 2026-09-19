package clickhouse

import (
	"context"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/models"
)

// AnalyticsRepository provides query methods for all time-series event tables.
type AnalyticsRepository struct {
	ch *client.ClickHouseClient
}

// NewAnalyticsRepository creates a new repository instance.
func NewAnalyticsRepository(ch *client.ClickHouseClient) *AnalyticsRepository {
	return &AnalyticsRepository{ch: ch}
}

// --------------------------------------------------------------------------
// OTP Logs
// --------------------------------------------------------------------------

type OTPSearchFilter struct {
	UserID    *string
	Phone     *string
	Status    *string
	StartDate *time.Time
	EndDate   *time.Time
	Limit     int
	Offset    int
}

func (r *AnalyticsRepository) ListOTP(ctx context.Context, filter OTPSearchFilter) ([]*models.OTPLogEvent, int, error) {
	conditions, args := buildConditions(
		cond("user_id", filter.UserID),
		cond("phone_number", filter.Phone),
		cond("status", filter.Status),
		condDateRange("timestamp", filter.StartDate, filter.EndDate),
	)
	where := whereClause(conditions)

	// Count
	total, err := r.count(ctx, "auth_analytics.otp_events", where, args)
	if err != nil || total == 0 {
		return []*models.OTPLogEvent{}, total, err
	}

	// Data
	query := fmt.Sprintf(`
		SELECT event_id, event_type, timestamp, user_id, phone_number, status,
		       attempt_number, attempts_left, error_code, error_message, ip_address,
		       device_id, purpose, otp_provider, duration_ms, environment, version,
		       message, service_name
		FROM auth_analytics.otp_events
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, where)

	params := append(args, filter.Limit, filter.Offset)
	rows, err := r.ch.QueryRows(ctx, query, params...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*models.OTPLogEvent
	for rows.Next() {
		var e models.OTPLogEvent
		if err := rows.Scan(
			&e.EventID, &e.EventType, &e.Timestamp,
			&e.UserID, &e.PhoneNumber, &e.Status,
			&e.AttemptNumber, &e.AttemptsLeft,
			&e.ErrorCode, &e.ErrorMessage, &e.IPAddress,
			&e.DeviceID, &e.Purpose, &e.OTPProvider, &e.Duration,
			&e.Environment, &e.Version, &e.Message, &e.ServiceName,
		); err != nil {
			continue
		}
		events = append(events, &e)
	}
	return events, total, nil
}

// --------------------------------------------------------------------------
// MPIN Logs
// --------------------------------------------------------------------------

type MPINSearchFilter struct {
	UserID    *string
	Status    *string
	IsLocked  *bool
	StartDate *time.Time
	EndDate   *time.Time
	Limit     int
	Offset    int
}

func (r *AnalyticsRepository) ListMPIN(ctx context.Context, filter MPINSearchFilter) ([]*models.MPINLogEvent, int, error) {
	conditions, args := buildConditions(
		cond("user_id", filter.UserID),
		cond("status", filter.Status),
		condBool("is_locked", filter.IsLocked),
		condDateRange("timestamp", filter.StartDate, filter.EndDate),
	)
	where := whereClause(conditions)

	total, err := r.count(ctx, "auth_analytics.mpin_events", where, args)
	if err != nil || total == 0 {
		return []*models.MPINLogEvent{}, total, err
	}

	query := fmt.Sprintf(`
		SELECT event_id, event_type, timestamp, user_id, status, attempts, attempts_left,
		       is_locked, error_code, error_message, device_id, device_trust, duration_ms,
		       failure_reason, environment, version, message, service_name
		FROM auth_analytics.mpin_events
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, where)

	params := append(args, filter.Limit, filter.Offset)
	rows, err := r.ch.QueryRows(ctx, query, params...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*models.MPINLogEvent
	for rows.Next() {
		var e models.MPINLogEvent
		var locked uint8
		if err := rows.Scan(
			&e.EventID, &e.EventType, &e.Timestamp,
			&e.UserID, &e.Status, &e.Attempts, &e.AttemptsLeft,
			&locked, &e.ErrorCode, &e.ErrorMessage, &e.DeviceID,
			&e.DeviceTrust, &e.Duration, &e.FailureReason,
			&e.Environment, &e.Version, &e.Message, &e.ServiceName,
		); err != nil {
			continue
		}
		e.IsLocked = locked == 1
		events = append(events, &e)
	}
	return events, total, nil
}

// --------------------------------------------------------------------------
// Device Logs
// --------------------------------------------------------------------------

type DeviceSearchFilter struct {
	UserID    *string
	DeviceID  *string
	Action    *string
	Status    *string
	StartDate *time.Time
	EndDate   *time.Time
	Limit     int
	Offset    int
}

func (r *AnalyticsRepository) ListDevice(ctx context.Context, filter DeviceSearchFilter) ([]*models.DeviceLogEvent, int, error) {
	conditions, args := buildConditions(
		cond("user_id", filter.UserID),
		cond("device_id", filter.DeviceID),
		cond("action", filter.Action),
		cond("status", filter.Status),
		condDateRange("timestamp", filter.StartDate, filter.EndDate),
	)
	where := whereClause(conditions)

	total, err := r.count(ctx, "auth_analytics.device_events", where, args)
	if err != nil || total == 0 {
		return []*models.DeviceLogEvent{}, total, err
	}

	query := fmt.Sprintf(`
		SELECT event_id, event_type, timestamp, user_id, device_id, action,
		       status, bind_token, error_code, error_message, ip_address,
		       session_id, duration_ms, environment, version, message, service_name
		FROM auth_analytics.device_events
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, where)

	params := append(args, filter.Limit, filter.Offset)
	rows, err := r.ch.QueryRows(ctx, query, params...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*models.DeviceLogEvent
	for rows.Next() {
		var e models.DeviceLogEvent
		if err := rows.Scan(
			&e.EventID, &e.EventType, &e.Timestamp,
			&e.UserID, &e.DeviceID, &e.Action, &e.Status,
			&e.BindToken, &e.ErrorCode, &e.ErrorMessage,
			&e.IPAddress, &e.SessionID, &e.Duration,
			&e.Environment, &e.Version, &e.Message, &e.ServiceName,
		); err != nil {
			continue
		}
		events = append(events, &e)
	}
	return events, total, nil
}

// --------------------------------------------------------------------------
// Security Logs
// --------------------------------------------------------------------------

type SecuritySearchFilter struct {
	UserID        *string
	EventCategory *string
	Severity      *string
	IPAddress     *string
	Action        *string
	StartDate     *time.Time
	EndDate       *time.Time
	Limit         int
	Offset        int
}

func (r *AnalyticsRepository) ListSecurity(ctx context.Context, filter SecuritySearchFilter) ([]*models.SecurityLogEvent, int, error) {
	conditions, args := buildConditions(
		cond("user_id", filter.UserID),
		cond("event_category", filter.EventCategory),
		cond("severity", filter.Severity),
		cond("ip_address", filter.IPAddress),
		cond("action", filter.Action),
		condDateRange("timestamp", filter.StartDate, filter.EndDate),
	)
	where := whereClause(conditions)

	total, err := r.count(ctx, "auth_analytics.security_events", where, args)
	if err != nil || total == 0 {
		return []*models.SecurityLogEvent{}, total, err
	}

	query := fmt.Sprintf(`
		SELECT event_id, event_type, timestamp, user_id, event_category, severity,
		       ip_address, device_id, action, risk_score, reason,
		       environment, version, message, service_name
		FROM auth_analytics.security_events
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, where)

	params := append(args, filter.Limit, filter.Offset)
	rows, err := r.ch.QueryRows(ctx, query, params...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*models.SecurityLogEvent
	for rows.Next() {
		var e models.SecurityLogEvent
		if err := rows.Scan(
			&e.EventID, &e.EventType, &e.Timestamp,
			&e.UserID, &e.EventCategory, &e.Severity,
			&e.IPAddress, &e.DeviceID, &e.Action,
			&e.RiskScore, &e.Reason,
			&e.Environment, &e.Version, &e.Message, &e.ServiceName,
		); err != nil {
			continue
		}
		events = append(events, &e)
	}
	return events, total, nil
}

// --------------------------------------------------------------------------
// Security Risk Logs (models.SecurityEvent)
// --------------------------------------------------------------------------

type SecurityRiskSearchFilter struct {
	PhoneNumber  *string
	IPAddress    *string
	RiskScoreMin *int
	ActionTaken  *string
	StartDate    *time.Time
	EndDate      *time.Time
	Limit        int
	Offset       int
}

func (r *AnalyticsRepository) ListSecurityRisk(ctx context.Context, filter SecurityRiskSearchFilter) ([]*models.SecurityEvent, int, error) {
	conditions, args := buildConditions(
		cond("phone_number", filter.PhoneNumber),
		cond("ip_address", filter.IPAddress),
		cond("action_taken", filter.ActionTaken),
		condDateRange("timestamp", filter.StartDate, filter.EndDate),
	)
	if filter.RiskScoreMin != nil {
		conditions = append(conditions, "risk_score >= ?")
		args = append(args, *filter.RiskScoreMin)
	}
	where := whereClause(conditions)

	total, err := r.count(ctx, "auth_analytics.security_risk_events", where, args)
	if err != nil || total == 0 {
		return []*models.SecurityEvent{}, total, err
	}

	query := fmt.Sprintf(`
		SELECT event_id, event_type, timestamp, phone_number, ip_address, device_id,
		       user_agent, risk_score, event_type_detail, reasons, action_taken,
		       environment, version, message, service_name
		FROM auth_analytics.security_risk_events
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, where)

	params := append(args, filter.Limit, filter.Offset)
	rows, err := r.ch.QueryRows(ctx, query, params...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*models.SecurityEvent
	for rows.Next() {
		var e models.SecurityEvent
		if err := rows.Scan(
			&e.EventID, &e.EventType, &e.Timestamp,
			&e.PhoneNumber, &e.IPAddress, &e.DeviceID,
			&e.UserAgent, &e.RiskScore, &e.EventType, // event_type_detail is same as EventType
			&e.Reasons, &e.ActionTaken,
			&e.Environment, &e.Version, &e.Message, &e.ServiceName,
		); err != nil {
			continue
		}
		events = append(events, &e)
	}
	return events, total, nil
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func (r *AnalyticsRepository) count(ctx context.Context, table, where string, args []interface{}) (int, error) {
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", table, where)
	rows, err := r.ch.QueryRows(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var total int
	if rows.Next() {
		rows.Scan(&total)
	}
	return total, nil
}

type condPair struct {
	field string
	value interface{}
}

func cond(field string, val interface{}) condPair {
	if val == nil {
		return condPair{}
	}
	// Check for nil pointer
	switch v := val.(type) {
	case *string:
		if v == nil {
			return condPair{}
		}
	case *bool:
		if v == nil {
			return condPair{}
		}
	case *time.Time:
		if v == nil {
			return condPair{}
		}
	case *int:
		if v == nil {
			return condPair{}
		}
	}
	return condPair{field: field, value: val}
}

func condBool(field string, val *bool) condPair {
	if val == nil {
		return condPair{}
	}
	return condPair{field: field, value: *val}
}

func condDateRange(field string, start, end *time.Time) []condPair {
	var pairs []condPair
	if start != nil {
		pairs = append(pairs, condPair{field: field + " >= ?", value: *start})
	}
	if end != nil {
		pairs = append(pairs, condPair{field: field + " <= ?", value: *end})
	}
	return pairs
}

func buildConditions(pairs ...interface{}) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	for _, p := range pairs {
		switch v := p.(type) {
		case condPair:
			if v.field != "" {
				conditions = append(conditions, v.field)
				args = append(args, v.value)
			}
		case []condPair:
			for _, cp := range v {
				if cp.field != "" {
					conditions = append(conditions, cp.field)
					args = append(args, cp.value)
				}
			}
		}
	}
	return conditions, args
}

func whereClause(conditions []string) string {
	if len(conditions) == 0 {
		return ""
	}
	return "WHERE " + strings.Join(conditions, " AND ")
}
