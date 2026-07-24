// Package forward posts normalized change-event batches to the control plane.
package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/msaad00/agent-bom/runtime/event-collector/internal/normalize"
)

// IngestPath is the intended Phase 2 control-plane route.
// Until that route ships, callers may observe HTTP 404 — that is expected in Phase 1.
const IngestPath = "/v1/cloud/connections/events/ingest"

// Batch is the JSON body for ingest.
type Batch struct {
	Events []*normalize.CloudChangeEvent `json:"events"`
}

// Client POSTs batches to {ControlPlaneURL}{IngestPath}.
type Client struct {
	ControlPlaneURL string
	APIKey          string
	HTTPClient      *http.Client
}

// NewClient builds a forwarder. controlPlaneURL should be a base URL without a trailing slash.
func NewClient(controlPlaneURL, apiKey string) *Client {
	return &Client{
		ControlPlaneURL: strings.TrimRight(controlPlaneURL, "/"),
		APIKey:          apiKey,
		HTTPClient:      &http.Client{Timeout: 30 * time.Second},
	}
}

// ForwardBatch POSTs events to the control plane ingest path.
// Phase 1: a 404 means the OpenAPI route is not shipped yet — callers should
// treat that as "not ready", not as a successful drop.
func (c *Client) ForwardBatch(ctx context.Context, events []*normalize.CloudChangeEvent) error {
	if c == nil || c.ControlPlaneURL == "" {
		return fmt.Errorf("forward: control-plane URL is required")
	}
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(Batch{Events: events})
	if err != nil {
		return fmt.Errorf("forward: marshal: %w", err)
	}
	url := c.ControlPlaneURL + IngestPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("forward: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("forward: post: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("forward: ingest path not found (Phase 2 route pending): %s returned 404: %s", IngestPath, strings.TrimSpace(string(respBody)))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward: control plane returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}
