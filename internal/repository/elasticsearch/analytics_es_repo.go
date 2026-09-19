package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"go.uber.org/zap"

	"auth-service/internal/models"
)

// AnalyticsESRepository provides query methods for Elasticsearch indices.
type AnalyticsESRepository struct {
	client *elasticsearch.Client
	logger *zap.Logger
}

// NewAnalyticsESRepository creates a new repository instance.
func NewAnalyticsESRepository(client *elasticsearch.Client, logger *zap.Logger) *AnalyticsESRepository {
	return &AnalyticsESRepository{
		client: client,
		logger: logger.Named("es_repo"),
	}
}

// --------------------------------------------------------------------------
// Admin Logs (indices: admin-*)
// --------------------------------------------------------------------------

type AdminSearchFilter struct {
	AdminID      *string
	Action       *string
	Status       *string
	ErrorCode    *string
	ResourceType *string
	StartDate    *time.Time
	EndDate      *time.Time
	Limit        int
	Offset       int
}

// SearchAdminLogs searches admin events with filters.
func (r *AnalyticsESRepository) SearchAdminLogs(ctx context.Context, filter AdminSearchFilter) ([]models.AdminLogEvent, int, error) {
	query := r.buildAdminQuery(filter)
	return r.executeAdminSearch(ctx, query, filter.Limit, filter.Offset)
}

func (r *AnalyticsESRepository) buildAdminQuery(filter AdminSearchFilter) map[string]interface{} {
	must := []map[string]interface{}{}

	addMatch := func(field string, value *string) {
		if value != nil {
			must = append(must, map[string]interface{}{
				"match": map[string]interface{}{field: *value},
			})
		}
	}

	addMatch("admin_id", filter.AdminID)
	addMatch("action", filter.Action)
	addMatch("status", filter.Status)
	addMatch("error_code", filter.ErrorCode)
	addMatch("resource_type", filter.ResourceType)

	addDateRange(must, filter.StartDate, filter.EndDate)

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": map[string]string{"order": "desc"}},
		},
	}
	return query
}

func (r *AnalyticsESRepository) executeAdminSearch(ctx context.Context, query map[string]interface{}, limit, offset int) ([]models.AdminLogEvent, int, error) {
	query["size"] = limit
	query["from"] = offset

	res, err := r.executeSearch(ctx, "admin-*", query)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source models.AdminLogEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("failed to decode response: %w", err)
	}

	events := make([]models.AdminLogEvent, len(result.Hits.Hits))
	for i, hit := range result.Hits.Hits {
		events[i] = hit.Source
	}
	return events, result.Hits.Total.Value, nil
}

// --------------------------------------------------------------------------
// Session Logs (indices: session-events-*)
// --------------------------------------------------------------------------

type SessionSearchFilter struct {
	UserID      *string
	SessionType *string
	Status      *string
	StartDate   *time.Time
	EndDate     *time.Time
	Limit       int
	Offset      int
}

func (r *AnalyticsESRepository) SearchSessionLogs(ctx context.Context, filter SessionSearchFilter) ([]models.SessionLogEvent, int, error) {
	must := []map[string]interface{}{}
	addMatch := func(field string, value *string) {
		if value != nil {
			must = append(must, map[string]interface{}{
				"match": map[string]interface{}{field: *value},
			})
		}
	}
	addMatch("user_id", filter.UserID)
	addMatch("session_type", filter.SessionType)
	addMatch("status", filter.Status)
	addDateRange(must, filter.StartDate, filter.EndDate)

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"size": filter.Limit,
		"from": filter.Offset,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]string{"order": "desc"}},
		},
	}

	res, err := r.executeSearch(ctx, "session-events-*", query)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source models.SessionLogEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, err
	}
	events := make([]models.SessionLogEvent, len(result.Hits.Hits))
	for i, hit := range result.Hits.Hits {
		events[i] = hit.Source
	}
	return events, result.Hits.Total.Value, nil
}

// --------------------------------------------------------------------------
// User Logs (indices: user-events-*)
// --------------------------------------------------------------------------

type UserSearchFilter struct {
	UserID    *string
	Action    *string
	Status    *string
	StartDate *time.Time
	EndDate   *time.Time
	Limit     int
	Offset    int
}

func (r *AnalyticsESRepository) SearchUserLogs(ctx context.Context, filter UserSearchFilter) ([]models.UserLogEvent, int, error) {
	must := []map[string]interface{}{}
	addMatch := func(field string, value *string) {
		if value != nil {
			must = append(must, map[string]interface{}{
				"match": map[string]interface{}{field: *value},
			})
		}
	}
	addMatch("user_id", filter.UserID)
	addMatch("action", filter.Action)
	addMatch("status", filter.Status)
	addDateRange(must, filter.StartDate, filter.EndDate)

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"size": filter.Limit,
		"from": filter.Offset,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]string{"order": "desc"}},
		},
	}

	res, err := r.executeSearch(ctx, "user-events-*", query)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source models.UserLogEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, err
	}
	events := make([]models.UserLogEvent, len(result.Hits.Hits))
	for i, hit := range result.Hits.Hits {
		events[i] = hit.Source
	}
	return events, result.Hits.Total.Value, nil
}

// --------------------------------------------------------------------------
// Security Logs (indices: security-events-*)
// --------------------------------------------------------------------------

type SecuritySearchFilter struct {
	UserID        *string
	EventCategory *string
	Severity      *string
	Action        *string
	IPAddress     *string
	StartDate     *time.Time
	EndDate       *time.Time
	Limit         int
	Offset        int
}

func (r *AnalyticsESRepository) SearchSecurityLogs(ctx context.Context, filter SecuritySearchFilter) ([]models.SecurityLogEvent, int, error) {
	must := []map[string]interface{}{}
	addMatch := func(field string, value *string) {
		if value != nil {
			must = append(must, map[string]interface{}{
				"match": map[string]interface{}{field: *value},
			})
		}
	}
	addMatch("user_id", filter.UserID)
	addMatch("event_category", filter.EventCategory)
	addMatch("severity", filter.Severity)
	addMatch("action", filter.Action)
	addMatch("ip_address", filter.IPAddress)
	addDateRange(must, filter.StartDate, filter.EndDate)

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"size": filter.Limit,
		"from": filter.Offset,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]string{"order": "desc"}},
		},
	}

	res, err := r.executeSearch(ctx, "security-events-*", query)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source models.SecurityLogEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, err
	}
	events := make([]models.SecurityLogEvent, len(result.Hits.Hits))
	for i, hit := range result.Hits.Hits {
		events[i] = hit.Source
	}
	return events, result.Hits.Total.Value, nil
}

// --------------------------------------------------------------------------
// Free-text search across all indices (admin only)
// --------------------------------------------------------------------------

type GlobalSearchFilter struct {
	Query     string
	Index     *string // "admin", "session", "user", "security", or nil for all
	StartDate *time.Time
	EndDate   *time.Time
	Limit     int
	Offset    int
}

// GlobalSearch performs a full-text search across the specified indices.
func (r *AnalyticsESRepository) GlobalSearch(ctx context.Context, filter GlobalSearchFilter) ([]map[string]interface{}, int, error) {
	indexPattern := "admin-*,session-events-*,user-events-*,security-events-*"
	if filter.Index != nil {
		switch *filter.Index {
		case "admin":
			indexPattern = "admin-*"
		case "session":
			indexPattern = "session-events-*"
		case "user":
			indexPattern = "user-events-*"
		case "security":
			indexPattern = "security-events-*"
		default:
			indexPattern = "admin-*,session-events-*,user-events-*,security-events-*"
		}
	}

	must := []map[string]interface{}{
		{
			"multi_match": map[string]interface{}{
				"query":  filter.Query,
				"fields": []string{"*"}, // search all fields
			},
		},
	}
	addDateRange(must, filter.StartDate, filter.EndDate)

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"size": filter.Limit,
		"from": filter.Offset,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]string{"order": "desc"}},
		},
	}

	res, err := r.executeSearch(ctx, indexPattern, query)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source map[string]interface{} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, err
	}
	documents := make([]map[string]interface{}, len(result.Hits.Hits))
	for i, hit := range result.Hits.Hits {
		documents[i] = hit.Source
	}
	return documents, result.Hits.Total.Value, nil
}

// --------------------------------------------------------------------------
// Helper: execute search
// --------------------------------------------------------------------------

func (r *AnalyticsESRepository) executeSearch(ctx context.Context, indexPattern string, query map[string]interface{}) (*esapi.Response, error) {
	body, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	res, err := r.client.Search(
		r.client.Search.WithContext(ctx),
		r.client.Search.WithIndex(indexPattern),
		r.client.Search.WithBody(bytes.NewReader(body)),
		r.client.Search.WithTrackTotalHits(true),
	)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	if res.IsError() {
		var e map[string]interface{}
		_ = json.NewDecoder(res.Body).Decode(&e)
		res.Body.Close()
		return nil, fmt.Errorf("elasticsearch error: %s", e["error"])
	}
	return res, nil
}

// --------------------------------------------------------------------------
// Helpers for building queries
// --------------------------------------------------------------------------

func addDateRange(must []map[string]interface{}, start, end *time.Time) {
	if start != nil {
		must = append(must, map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": start.Format(time.RFC3339),
				},
			},
		})
	}
	if end != nil {
		must = append(must, map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"lte": end.Format(time.RFC3339),
				},
			},
		})
	}
}
