package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type HRClient struct {
	BaseURL string
	Client  *http.Client
}

func NewHRClient(baseURL string) *HRClient {
	return &HRClient{
		BaseURL: baseURL,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Do sends an HTTP request to the HR service. The body parameter should be an io.Reader
// (e.g., bytes.Reader) containing the already‑marshalled JSON payload, or nil.
func (c *HRClient) Do(
	ctx context.Context,
	method string,
	path string,
	authHeader string,
	deviceID string,
	companyID string,
	body io.Reader,
) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		method,
		fmt.Sprintf("%s%s", c.BaseURL, path),
		body,
	)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Device-ID", deviceID)
	req.Header.Set("X-Company-ID", companyID)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return data, resp.StatusCode, nil
}
