// internal/repository/clickhouse/analytics_stats.go (new file)
package clickhouse

import (
	"context"
	"fmt"
	"time"
)

func (r *AnalyticsRepository) GetOTPStats(ctx context.Context, userID *string, startDate, endDate *time.Time) (map[string]interface{}, error) {
	conditions, args := buildConditions(
		cond("user_id", userID),
		condDateRange("timestamp", startDate, endDate),
	)
	where := whereClause(conditions)

	// Count total, by status, daily breakdown
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

	rows, err := r.ch.QueryRows(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := map[string]interface{}{
		"total":         0,
		"success_count": 0,
		"failed_count":  0,
		"avg_duration":  0,
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
