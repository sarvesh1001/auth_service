// internal/service/analytics.go
package service

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/repository/clickhouse"
	esrepo "auth-service/internal/repository/elasticsearch" // alias to avoid name conflict
)

// AnalyticsService combines ClickHouse and Elasticsearch for operational analytics.
type AnalyticsService struct {
	chRepo     *clickhouse.AnalyticsRepository
	esRepo     *esrepo.AnalyticsESRepository // use alias
	chClient   *client.ClickHouseClient
	esClient   *elasticsearch.Client
	logger     *zap.Logger
	companySvc *CompanyService // optional, for user validation
}

// NewAnalyticsService creates a new instance.
func NewAnalyticsService(
	chRepo *clickhouse.AnalyticsRepository,
	esRepo *esrepo.AnalyticsESRepository,
	chClient *client.ClickHouseClient,
	esClient *elasticsearch.Client,
	logger *zap.Logger,
	companySvc *CompanyService,
) *AnalyticsService {
	return &AnalyticsService{
		chRepo:     chRepo,
		esRepo:     esRepo,
		chClient:   chClient,
		esClient:   esClient,
		logger:     logger.Named("analytics_service"),
		companySvc: companySvc,
	}
}

// =============================================================================
// CLICKHOUSE-BASED LOGS (Time‑Series)
// =============================================================================

// ---- OTP Logs ----

func (s *AnalyticsService) ListOTPLogs(
	ctx context.Context,
	filter clickhouse.OTPSearchFilter,
) ([]*models.OTPLogEvent, int, error) {
	s.logger.Debug("listing OTP logs", zap.Any("filter", filter))
	return s.chRepo.ListOTP(ctx, filter)
}

func (s *AnalyticsService) GetOTPStats(
	ctx context.Context,
	userID *string,
	startDate, endDate *time.Time,
) (map[string]interface{}, error) {
	s.logger.Debug("getting OTP stats", zap.Any("userID", userID), zap.Any("start", startDate), zap.Any("end", endDate))
	return s.queryOTPStats(ctx, userID, startDate, endDate)
}

func (s *AnalyticsService) ExportOTPLogs(
	ctx context.Context,
	filter clickhouse.OTPSearchFilter,
	format string,
) ([]byte, string, error) {
	logs, _, err := s.ListOTPLogs(ctx, filter)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch OTP logs: %w", err)
	}
	return s.exportOTPAsFormat(logs, format)
}

// ---- MPIN Logs ----

func (s *AnalyticsService) ListMPINLogs(
	ctx context.Context,
	filter clickhouse.MPINSearchFilter,
) ([]*models.MPINLogEvent, int, error) {
	s.logger.Debug("listing MPIN logs", zap.Any("filter", filter))
	return s.chRepo.ListMPIN(ctx, filter)
}

func (s *AnalyticsService) GetMPINStats(
	ctx context.Context,
	userID *string,
	startDate, endDate *time.Time,
) (map[string]interface{}, error) {
	s.logger.Debug("getting MPIN stats", zap.Any("userID", userID), zap.Any("start", startDate), zap.Any("end", endDate))
	return s.queryMPINStats(ctx, userID, startDate, endDate)
}

func (s *AnalyticsService) ExportMPINLogs(
	ctx context.Context,
	filter clickhouse.MPINSearchFilter,
	format string,
) ([]byte, string, error) {
	logs, _, err := s.ListMPINLogs(ctx, filter)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch MPIN logs: %w", err)
	}
	return s.exportMPINAsFormat(logs, format)
}

// ---- Device Logs ----

func (s *AnalyticsService) ListDeviceLogs(
	ctx context.Context,
	filter clickhouse.DeviceSearchFilter,
) ([]*models.DeviceLogEvent, int, error) {
	s.logger.Debug("listing device logs", zap.Any("filter", filter))
	return s.chRepo.ListDevice(ctx, filter)
}

func (s *AnalyticsService) GetDeviceStats(
	ctx context.Context,
	userID *string,
	startDate, endDate *time.Time,
) (map[string]interface{}, error) {
	s.logger.Debug("getting device stats", zap.Any("userID", userID), zap.Any("start", startDate), zap.Any("end", endDate))
	return s.queryDeviceStats(ctx, userID, startDate, endDate)
}

func (s *AnalyticsService) ExportDeviceLogs(
	ctx context.Context,
	filter clickhouse.DeviceSearchFilter,
	format string,
) ([]byte, string, error) {
	logs, _, err := s.ListDeviceLogs(ctx, filter)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch device logs: %w", err)
	}
	return s.exportDeviceAsFormat(logs, format)
}

// ---- Security Logs (from ClickHouse) ----

func (s *AnalyticsService) ListSecurityLogs(
	ctx context.Context,
	filter clickhouse.SecuritySearchFilter,
) ([]*models.SecurityLogEvent, int, error) {
	s.logger.Debug("listing security logs (CH)", zap.Any("filter", filter))
	return s.chRepo.ListSecurity(ctx, filter)
}

func (s *AnalyticsService) GetSecurityStats(
	ctx context.Context,
	userID *string,
	startDate, endDate *time.Time,
) (map[string]interface{}, error) {
	s.logger.Debug("getting security stats", zap.Any("userID", userID), zap.Any("start", startDate), zap.Any("end", endDate))
	return s.querySecurityStats(ctx, userID, startDate, endDate)
}

func (s *AnalyticsService) ExportSecurityLogs(
	ctx context.Context,
	filter clickhouse.SecuritySearchFilter,
	format string,
) ([]byte, string, error) {
	logs, _, err := s.ListSecurityLogs(ctx, filter)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch security logs: %w", err)
	}
	return s.exportSecurityAsFormat(logs, format)
}

// ---- Security Risk Logs ----

func (s *AnalyticsService) ListSecurityRiskLogs(
	ctx context.Context,
	filter clickhouse.SecurityRiskSearchFilter,
) ([]*models.SecurityEvent, int, error) {
	s.logger.Debug("listing security risk logs", zap.Any("filter", filter))
	return s.chRepo.ListSecurityRisk(ctx, filter)
}

func (s *AnalyticsService) GetSecurityRiskStats(
	ctx context.Context,
	phoneNumber *string,
	startDate, endDate *time.Time,
) (map[string]interface{}, error) {
	s.logger.Debug("getting security risk stats", zap.Any("phoneNumber", phoneNumber), zap.Any("start", startDate), zap.Any("end", endDate))
	return s.querySecurityRiskStats(ctx, phoneNumber, startDate, endDate)
}

func (s *AnalyticsService) ExportSecurityRiskLogs(
	ctx context.Context,
	filter clickhouse.SecurityRiskSearchFilter,
	format string,
) ([]byte, string, error) {
	logs, _, err := s.ListSecurityRiskLogs(ctx, filter)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch security risk logs: %w", err)
	}
	return s.exportSecurityRiskAsFormat(logs, format)
}

// =============================================================================
// ELASTICSEARCH-BASED LOGS (Search-Oriented)
// =============================================================================

// ---- Admin Logs ----

func (s *AnalyticsService) SearchAdminLogs(
	ctx context.Context,
	filter esrepo.AdminSearchFilter,
) ([]models.AdminLogEvent, int, error) {
	s.logger.Debug("searching admin logs", zap.Any("filter", filter))
	return s.esRepo.SearchAdminLogs(ctx, filter)
}

// ---- Session Logs ----

func (s *AnalyticsService) SearchSessionLogs(
	ctx context.Context,
	filter esrepo.SessionSearchFilter,
) ([]models.SessionLogEvent, int, error) {
	s.logger.Debug("searching session logs", zap.Any("filter", filter))
	return s.esRepo.SearchSessionLogs(ctx, filter)
}

// ---- User Logs ----

func (s *AnalyticsService) SearchUserLogs(
	ctx context.Context,
	filter esrepo.UserSearchFilter,
) ([]models.UserLogEvent, int, error) {
	s.logger.Debug("searching user logs", zap.Any("filter", filter))
	return s.esRepo.SearchUserLogs(ctx, filter)
}

// ---- Security Logs (from Elasticsearch) ----

func (s *AnalyticsService) SearchSecurityLogsES(
	ctx context.Context,
	filter esrepo.SecuritySearchFilter,
) ([]models.SecurityLogEvent, int, error) {
	s.logger.Debug("searching security logs (ES)", zap.Any("filter", filter))
	return s.esRepo.SearchSecurityLogs(ctx, filter)
}

// ---- Global Search ----

func (s *AnalyticsService) GlobalSearch(
	ctx context.Context,
	filter esrepo.GlobalSearchFilter,
) ([]map[string]interface{}, int, error) {
	s.logger.Debug("global search", zap.Any("filter", filter))
	return s.esRepo.GlobalSearch(ctx, filter)
}

// =============================================================================
// DASHBOARD STATS (Combined)
// =============================================================================

func (s *AnalyticsService) GetDashboardStats(
	ctx context.Context,
	userID *string,
	startDate, endDate *time.Time,
) (map[string]interface{}, error) {
	s.logger.Debug("getting dashboard stats", zap.Any("userID", userID), zap.Any("start", startDate), zap.Any("end", endDate))

	stats := make(map[string]interface{})

	otpStats, err := s.GetOTPStats(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Warn("failed to get OTP stats", zap.Error(err))
		otpStats = map[string]interface{}{"error": err.Error()}
	}
	stats["otp"] = otpStats

	mpinStats, err := s.GetMPINStats(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Warn("failed to get MPIN stats", zap.Error(err))
		mpinStats = map[string]interface{}{"error": err.Error()}
	}
	stats["mpin"] = mpinStats

	deviceStats, err := s.GetDeviceStats(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Warn("failed to get device stats", zap.Error(err))
		deviceStats = map[string]interface{}{"error": err.Error()}
	}
	stats["device"] = deviceStats

	securityStats, err := s.GetSecurityStats(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Warn("failed to get security stats", zap.Error(err))
		securityStats = map[string]interface{}{"error": err.Error()}
	}
	stats["security"] = securityStats

	riskStats, err := s.GetSecurityRiskStats(ctx, nil, startDate, endDate)
	if err != nil {
		s.logger.Warn("failed to get security risk stats", zap.Error(err))
		riskStats = map[string]interface{}{"error": err.Error()}
	}
	stats["security_risk"] = riskStats

	return stats, nil
}

// =============================================================================
// HEALTH CHECK
// =============================================================================

func (s *AnalyticsService) HealthCheck(ctx context.Context) error {
	if err := s.chClient.HealthCheck(ctx); err != nil {
		return fmt.Errorf("ClickHouse health check failed: %w", err)
	}
	res, err := s.esClient.Info()
	if err != nil {
		return fmt.Errorf("Elasticsearch health check failed: %w", err)
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("Elasticsearch returned error: %s", res.Status())
	}
	return nil
}

// =============================================================================
// MULTI-TENANCY HELPERS (Optional)
// =============================================================================

func (s *AnalyticsService) EnsureCompanyAccess(ctx context.Context, companyID string, userID string) error {
	if s.companySvc == nil {
		return nil
	}
	// Placeholder – implement using your company service.
	return nil
}

// =============================================================================
// PRIVATE STATS QUERIES (direct ClickHouse)
// =============================================================================

func (s *AnalyticsService) queryOTPStats(ctx context.Context, userID *string, startDate, endDate *time.Time) (map[string]interface{}, error) {
	conditions, args := buildCHConditions(
		cond("user_id", userID),
		condDateRange("timestamp", startDate, endDate),
	)
	where := whereClauseCH(conditions)

	query := fmt.Sprintf(`
		SELECT 
			count() AS total,
			sumIf(1, status='success') AS success_count,
			sumIf(1, status='failed') AS failed_count,
			avg(duration_ms) AS avg_duration,
			toStartOfDay(timestamp) AS day,
			count() AS daily_count
		FROM auth_analytics.otp_events
		%s
		GROUP BY day
		ORDER BY day DESC
		LIMIT 30
	`, where)

	rows, err := s.chClient.QueryRows(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query OTP stats: %w", err)
	}
	defer rows.Close()

	stats := map[string]interface{}{
		"total":         0,
		"success_count": 0,
		"failed_count":  0,
		"avg_duration":  0.0,
		"daily":         []map[string]interface{}{},
	}
	var total, success, failed int
	var avgDur float64
	var daily []map[string]interface{}
	for rows.Next() {
		var day time.Time
		var dailyCount int
		if err := rows.Scan(&total, &success, &failed, &avgDur, &day, &dailyCount); err != nil {
			continue
		}
		daily = append(daily, map[string]interface{}{
			"date":  day.Format("2006-01-02"),
			"count": dailyCount,
		})
	}
	stats["total"] = total
	stats["success_count"] = success
	stats["failed_count"] = failed
	stats["avg_duration"] = avgDur
	stats["daily"] = daily
	return stats, nil
}

func (s *AnalyticsService) queryMPINStats(ctx context.Context, userID *string, startDate, endDate *time.Time) (map[string]interface{}, error) {
	conditions, args := buildCHConditions(
		cond("user_id", userID),
		condDateRange("timestamp", startDate, endDate),
	)
	where := whereClauseCH(conditions)

	query := fmt.Sprintf(`
		SELECT 
			count() AS total,
			sumIf(1, status='success') AS success_count,
			sumIf(1, status='failed') AS failed_count,
			avg(attempts) AS avg_attempts,
			sumIf(1, is_locked=1) AS locked_count,
			toStartOfDay(timestamp) AS day,
			count() AS daily_count
		FROM auth_analytics.mpin_events
		%s
		GROUP BY day
		ORDER BY day DESC
		LIMIT 30
	`, where)

	rows, err := s.chClient.QueryRows(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query MPIN stats: %w", err)
	}
	defer rows.Close()

	stats := map[string]interface{}{
		"total":         0,
		"success_count": 0,
		"failed_count":  0,
		"avg_attempts":  0.0,
		"locked_count":  0,
		"daily":         []map[string]interface{}{},
	}
	var total, success, failed, locked int
	var avgAtt float64
	var daily []map[string]interface{}
	for rows.Next() {
		var day time.Time
		var dailyCount int
		if err := rows.Scan(&total, &success, &failed, &avgAtt, &locked, &day, &dailyCount); err != nil {
			continue
		}
		daily = append(daily, map[string]interface{}{
			"date":  day.Format("2006-01-02"),
			"count": dailyCount,
		})
	}
	stats["total"] = total
	stats["success_count"] = success
	stats["failed_count"] = failed
	stats["avg_attempts"] = avgAtt
	stats["locked_count"] = locked
	stats["daily"] = daily
	return stats, nil
}

func (s *AnalyticsService) queryDeviceStats(ctx context.Context, userID *string, startDate, endDate *time.Time) (map[string]interface{}, error) {
	conditions, args := buildCHConditions(
		cond("user_id", userID),
		condDateRange("timestamp", startDate, endDate),
	)
	where := whereClauseCH(conditions)

	query := fmt.Sprintf(`
		SELECT 
			count() AS total,
			sumIf(1, status='success') AS success_count,
			sumIf(1, status='failed') AS failed_count,
			avg(duration_ms) AS avg_duration,
			toStartOfDay(timestamp) AS day,
			count() AS daily_count
		FROM auth_analytics.device_events
		%s
		GROUP BY day
		ORDER BY day DESC
		LIMIT 30
	`, where)

	rows, err := s.chClient.QueryRows(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query device stats: %w", err)
	}
	defer rows.Close()

	stats := map[string]interface{}{
		"total":         0,
		"success_count": 0,
		"failed_count":  0,
		"avg_duration":  0.0,
		"daily":         []map[string]interface{}{},
	}
	var total, success, failed int
	var avgDur float64
	var daily []map[string]interface{}
	for rows.Next() {
		var day time.Time
		var dailyCount int
		if err := rows.Scan(&total, &success, &failed, &avgDur, &day, &dailyCount); err != nil {
			continue
		}
		daily = append(daily, map[string]interface{}{
			"date":  day.Format("2006-01-02"),
			"count": dailyCount,
		})
	}
	stats["total"] = total
	stats["success_count"] = success
	stats["failed_count"] = failed
	stats["avg_duration"] = avgDur
	stats["daily"] = daily
	return stats, nil
}

func (s *AnalyticsService) querySecurityStats(ctx context.Context, userID *string, startDate, endDate *time.Time) (map[string]interface{}, error) {
	conditions, args := buildCHConditions(
		cond("user_id", userID),
		condDateRange("timestamp", startDate, endDate),
	)
	where := whereClauseCH(conditions)

	query := fmt.Sprintf(`
		SELECT 
			count() AS total,
			sumIf(1, severity='high') AS high_count,
			sumIf(1, severity='medium') AS medium_count,
			sumIf(1, severity='low') AS low_count,
			avg(risk_score) AS avg_risk,
			toStartOfDay(timestamp) AS day,
			count() AS daily_count
		FROM auth_analytics.security_events
		%s
		GROUP BY day
		ORDER BY day DESC
		LIMIT 30
	`, where)

	rows, err := s.chClient.QueryRows(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query security stats: %w", err)
	}
	defer rows.Close()

	stats := map[string]interface{}{
		"total":        0,
		"high_count":   0,
		"medium_count": 0,
		"low_count":    0,
		"avg_risk":     0.0,
		"daily":        []map[string]interface{}{},
	}
	var total, high, medium, low int
	var avgRisk float64
	var daily []map[string]interface{}
	for rows.Next() {
		var day time.Time
		var dailyCount int
		if err := rows.Scan(&total, &high, &medium, &low, &avgRisk, &day, &dailyCount); err != nil {
			continue
		}
		daily = append(daily, map[string]interface{}{
			"date":  day.Format("2006-01-02"),
			"count": dailyCount,
		})
	}
	stats["total"] = total
	stats["high_count"] = high
	stats["medium_count"] = medium
	stats["low_count"] = low
	stats["avg_risk"] = avgRisk
	stats["daily"] = daily
	return stats, nil
}

func (s *AnalyticsService) querySecurityRiskStats(ctx context.Context, phoneNumber *string, startDate, endDate *time.Time) (map[string]interface{}, error) {
	conditions, args := buildCHConditions(
		cond("phone_number", phoneNumber),
		condDateRange("timestamp", startDate, endDate),
	)
	where := whereClauseCH(conditions)

	query := fmt.Sprintf(`
		SELECT 
			count() AS total,
			avg(risk_score) AS avg_risk,
			max(risk_score) AS max_risk,
			sumIf(1, action_taken='block') AS blocked_count,
			sumIf(1, action_taken='flag') AS flagged_count,
			toStartOfDay(timestamp) AS day,
			count() AS daily_count
		FROM auth_analytics.security_risk_events
		%s
		GROUP BY day
		ORDER BY day DESC
		LIMIT 30
	`, where)

	rows, err := s.chClient.QueryRows(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query security risk stats: %w", err)
	}
	defer rows.Close()

	stats := map[string]interface{}{
		"total":         0,
		"avg_risk":      0.0,
		"max_risk":      0,
		"blocked_count": 0,
		"flagged_count": 0,
		"daily":         []map[string]interface{}{},
	}
	var total, blocked, flagged, maxRisk int
	var avgRisk float64
	var daily []map[string]interface{}
	for rows.Next() {
		var day time.Time
		var dailyCount int
		if err := rows.Scan(&total, &avgRisk, &maxRisk, &blocked, &flagged, &day, &dailyCount); err != nil {
			continue
		}
		daily = append(daily, map[string]interface{}{
			"date":  day.Format("2006-01-02"),
			"count": dailyCount,
		})
	}
	stats["total"] = total
	stats["avg_risk"] = avgRisk
	stats["max_risk"] = maxRisk
	stats["blocked_count"] = blocked
	stats["flagged_count"] = flagged
	stats["daily"] = daily
	return stats, nil
}

// =============================================================================
// PRIVATE EXPORT HELPERS
// =============================================================================

// exportOTPAsFormat converts a slice of OTPLogEvent to JSON or CSV.
func (s *AnalyticsService) exportOTPAsFormat(logs []*models.OTPLogEvent, format string) ([]byte, string, error) {
	switch strings.ToLower(format) {
	case "json":
		b, err := json.MarshalIndent(logs, "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("json marshal: %w", err)
		}
		return b, "application/json", nil
	case "csv":
		buf := &strings.Builder{}
		writer := csv.NewWriter(buf)
		header := []string{
			"event_id", "event_type", "timestamp", "user_id", "phone_number", "status",
			"attempt_number", "attempts_left", "error_code", "error_message", "ip_address",
			"device_id", "purpose", "otp_provider", "duration_ms", "environment", "version", "message", "service_name",
		}
		if err := writer.Write(header); err != nil {
			return nil, "", fmt.Errorf("csv write header: %w", err)
		}
		for _, e := range logs {
			row := []string{
				e.EventID,
				e.EventType,
				e.Timestamp.Format(time.RFC3339),
				e.UserID,
				e.PhoneNumber,
				e.Status,
				strconv.Itoa(e.AttemptNumber),
				strconv.Itoa(e.AttemptsLeft),
				e.ErrorCode,
				e.ErrorMessage,
				e.IPAddress,
				e.DeviceID,
				e.Purpose,
				e.OTPProvider,
				strconv.FormatInt(e.Duration, 10),
				e.Environment,
				e.Version,
				e.Message,
				e.ServiceName,
			}
			if err := writer.Write(row); err != nil {
				return nil, "", fmt.Errorf("csv write row: %w", err)
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, "", fmt.Errorf("csv flush: %w", err)
		}
		return []byte(buf.String()), "text/csv", nil
	default:
		return nil, "", fmt.Errorf("unsupported format: %s", format)
	}
}

// exportMPINAsFormat converts a slice of MPINLogEvent to JSON or CSV.
func (s *AnalyticsService) exportMPINAsFormat(logs []*models.MPINLogEvent, format string) ([]byte, string, error) {
	switch strings.ToLower(format) {
	case "json":
		b, err := json.MarshalIndent(logs, "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("json marshal: %w", err)
		}
		return b, "application/json", nil
	case "csv":
		buf := &strings.Builder{}
		writer := csv.NewWriter(buf)
		header := []string{
			"event_id", "event_type", "timestamp", "user_id", "status", "attempts", "attempts_left",
			"is_locked", "error_code", "error_message", "device_id", "device_trust", "duration_ms",
			"failure_reason", "environment", "version", "message", "service_name",
		}
		if err := writer.Write(header); err != nil {
			return nil, "", fmt.Errorf("csv write header: %w", err)
		}
		for _, e := range logs {
			row := []string{
				e.EventID,
				e.EventType,
				e.Timestamp.Format(time.RFC3339),
				e.UserID,
				e.Status,
				strconv.Itoa(e.Attempts),
				strconv.Itoa(e.AttemptsLeft),
				strconv.FormatBool(e.IsLocked),
				e.ErrorCode,
				e.ErrorMessage,
				e.DeviceID,
				e.DeviceTrust,
				strconv.FormatInt(e.Duration, 10),
				e.FailureReason,
				e.Environment,
				e.Version,
				e.Message,
				e.ServiceName,
			}
			if err := writer.Write(row); err != nil {
				return nil, "", fmt.Errorf("csv write row: %w", err)
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, "", fmt.Errorf("csv flush: %w", err)
		}
		return []byte(buf.String()), "text/csv", nil
	default:
		return nil, "", fmt.Errorf("unsupported format: %s", format)
	}
}

// exportDeviceAsFormat converts a slice of DeviceLogEvent to JSON or CSV.
func (s *AnalyticsService) exportDeviceAsFormat(logs []*models.DeviceLogEvent, format string) ([]byte, string, error) {
	switch strings.ToLower(format) {
	case "json":
		b, err := json.MarshalIndent(logs, "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("json marshal: %w", err)
		}
		return b, "application/json", nil
	case "csv":
		buf := &strings.Builder{}
		writer := csv.NewWriter(buf)
		header := []string{
			"event_id", "event_type", "timestamp", "user_id", "device_id", "action",
			"status", "bind_token", "error_code", "error_message", "ip_address", "session_id",
			"duration_ms", "environment", "version", "message", "service_name",
		}
		if err := writer.Write(header); err != nil {
			return nil, "", fmt.Errorf("csv write header: %w", err)
		}
		for _, e := range logs {
			row := []string{
				e.EventID,
				e.EventType,
				e.Timestamp.Format(time.RFC3339),
				e.UserID,
				e.DeviceID,
				e.Action,
				e.Status,
				e.BindToken,
				e.ErrorCode,
				e.ErrorMessage,
				e.IPAddress,
				e.SessionID,
				strconv.FormatInt(e.Duration, 10),
				e.Environment,
				e.Version,
				e.Message,
				e.ServiceName,
			}
			if err := writer.Write(row); err != nil {
				return nil, "", fmt.Errorf("csv write row: %w", err)
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, "", fmt.Errorf("csv flush: %w", err)
		}
		return []byte(buf.String()), "text/csv", nil
	default:
		return nil, "", fmt.Errorf("unsupported format: %s", format)
	}
}

// exportSecurityAsFormat converts a slice of SecurityLogEvent to JSON or CSV.
func (s *AnalyticsService) exportSecurityAsFormat(logs []*models.SecurityLogEvent, format string) ([]byte, string, error) {
	switch strings.ToLower(format) {
	case "json":
		b, err := json.MarshalIndent(logs, "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("json marshal: %w", err)
		}
		return b, "application/json", nil
	case "csv":
		buf := &strings.Builder{}
		writer := csv.NewWriter(buf)
		header := []string{
			"event_id", "event_type", "timestamp", "user_id", "event_category", "severity",
			"ip_address", "device_id", "action", "risk_score", "reason",
			"environment", "version", "message", "service_name",
		}
		if err := writer.Write(header); err != nil {
			return nil, "", fmt.Errorf("csv write header: %w", err)
		}
		for _, e := range logs {
			row := []string{
				e.EventID,
				e.EventType,
				e.Timestamp.Format(time.RFC3339),
				e.UserID,
				e.EventCategory,
				e.Severity,
				e.IPAddress,
				e.DeviceID,
				e.Action,
				strconv.FormatFloat(e.RiskScore, 'f', 2, 64),
				e.Reason,
				e.Environment,
				e.Version,
				e.Message,
				e.ServiceName,
			}
			if err := writer.Write(row); err != nil {
				return nil, "", fmt.Errorf("csv write row: %w", err)
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, "", fmt.Errorf("csv flush: %w", err)
		}
		return []byte(buf.String()), "text/csv", nil
	default:
		return nil, "", fmt.Errorf("unsupported format: %s", format)
	}
}

// exportSecurityRiskAsFormat converts a slice of SecurityEvent (risk) to JSON or CSV.
func (s *AnalyticsService) exportSecurityRiskAsFormat(logs []*models.SecurityEvent, format string) ([]byte, string, error) {
	switch strings.ToLower(format) {
	case "json":
		b, err := json.MarshalIndent(logs, "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("json marshal: %w", err)
		}
		return b, "application/json", nil
	case "csv":
		buf := &strings.Builder{}
		writer := csv.NewWriter(buf)
		header := []string{
			"event_id", "event_type", "timestamp", "phone_number", "ip_address", "device_id",
			"user_agent", "risk_score", "event_type_detail", "reasons", "action_taken",
			"environment", "version", "message", "service_name",
		}
		if err := writer.Write(header); err != nil {
			return nil, "", fmt.Errorf("csv write header: %w", err)
		}
		for _, e := range logs {
			row := []string{
				e.EventID,
				e.EventType,
				e.Timestamp.Format(time.RFC3339),
				e.PhoneNumber,
				e.IPAddress,
				e.DeviceID,
				e.UserAgent,
				strconv.Itoa(e.RiskScore), // RiskScore is int in models.SecurityEvent
				e.EventType,
				strings.Join(e.Reasons, "; "),
				e.ActionTaken,
				e.Environment,
				e.Version,
				e.Message,
				e.ServiceName,
			}
			if err := writer.Write(row); err != nil {
				return nil, "", fmt.Errorf("csv write row: %w", err)
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, "", fmt.Errorf("csv flush: %w", err)
		}
		return []byte(buf.String()), "text/csv", nil
	default:
		return nil, "", fmt.Errorf("unsupported format: %s", format)
	}
}

// =============================================================================
// HELPER FUNCTIONS FOR CLICKHOUSE CONDITIONS
// =============================================================================

type chCond struct {
	field string
	value interface{}
}

func cond(field string, val interface{}) chCond {
	if val == nil {
		return chCond{}
	}
	switch v := val.(type) {
	case *string:
		if v == nil {
			return chCond{}
		}
	case *bool:
		if v == nil {
			return chCond{}
		}
	case *time.Time:
		if v == nil {
			return chCond{}
		}
	case *int:
		if v == nil {
			return chCond{}
		}
	}
	return chCond{field: field, value: val}
}

func condDateRange(field string, start, end *time.Time) []chCond {
	var pairs []chCond
	if start != nil {
		pairs = append(pairs, chCond{field: field + " >= ?", value: *start})
	}
	if end != nil {
		pairs = append(pairs, chCond{field: field + " <= ?", value: *end})
	}
	return pairs
}

func buildCHConditions(pairs ...interface{}) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	for _, p := range pairs {
		switch v := p.(type) {
		case chCond:
			if v.field != "" {
				conditions = append(conditions, v.field)
				args = append(args, v.value)
			}
		case []chCond:
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

func whereClauseCH(conditions []string) string {
	if len(conditions) == 0 {
		return ""
	}
	return "WHERE " + strings.Join(conditions, " AND ")
}
