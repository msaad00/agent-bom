// Package agentbom provides a small Go client for the agent-bom control-plane API.
package agentbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// JSON is the generic object envelope returned by stable control-plane routes.
type JSON map[string]any

// Options configures a control-plane client.
type Options struct {
	BaseURL        string
	APIKey         string
	BearerToken    string
	TenantID       string
	HTTPClient     *http.Client
	DefaultHeaders map[string]string
}

// Client is a synchronous control-plane client for stable agent-bom API routes.
type Client struct {
	baseURL        string
	apiKey         string
	bearerToken    string
	tenantID       string
	httpClient     *http.Client
	defaultHeaders map[string]string
}

// APIError is returned when the control plane responds with a non-2xx status.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("agent-bom request failed: %d", e.StatusCode)
}

// NewClient constructs a control-plane client.
func NewClient(opts Options) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL is required")
	}
	if opts.APIKey != "" && opts.BearerToken != "" {
		return nil, fmt.Errorf("configure either APIKey or BearerToken, not both")
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	headers := map[string]string{}
	for key, value := range opts.DefaultHeaders {
		headers[key] = value
	}
	return &Client{
		baseURL:        baseURL,
		apiKey:         opts.APIKey,
		bearerToken:    opts.BearerToken,
		tenantID:       opts.TenantID,
		httpClient:     httpClient,
		defaultHeaders: headers,
	}, nil
}

// Health returns the control-plane health envelope.
func (c *Client) Health(ctx context.Context) (JSON, error) {
	return c.request(ctx, http.MethodGet, "/health", nil, nil)
}

// ExposurePathQuery filters graph exposure paths.
type ExposurePathQuery struct {
	TenantID string
	Limit    *int
	MinRisk  *int
}

// ExposurePaths lists graph exposure paths for the request tenant.
func (c *Client) ExposurePaths(ctx context.Context, query ExposurePathQuery) (JSON, error) {
	values := url.Values{}
	tenantID := firstNonEmpty(query.TenantID, c.tenantID)
	if tenantID != "" {
		values.Set("tenant_id", tenantID)
	}
	if query.Limit != nil {
		values.Set("limit", fmt.Sprint(*query.Limit))
	}
	if query.MinRisk != nil {
		values.Set("min_risk", fmt.Sprint(*query.MinRisk))
	}
	return c.request(ctx, http.MethodGet, "/v1/graph/exposure-paths", values, nil)
}

// DeployDecisionRequest asks the graph policy engine whether a candidate should deploy.
type DeployDecisionRequest struct {
	Candidate any
	TenantID  string
	BlockRisk *int
	Context   JSON
}

// ShouldIDeploy asks the graph policy engine whether a candidate should deploy.
func (c *Client) ShouldIDeploy(ctx context.Context, req DeployDecisionRequest) (JSON, error) {
	return c.request(ctx, http.MethodPost, "/v1/graph/should-i-deploy", nil, compact(JSON{
		"candidate":  req.Candidate,
		"tenant_id":  firstNonEmpty(req.TenantID, c.tenantID),
		"block_risk": req.BlockRisk,
		"context":    req.Context,
	}))
}

// FindingQuery filters normalized findings.
type FindingQuery struct {
	Severity string
	Sort     string
	Limit    *int
	Offset   *int
}

// ListFindings lists normalized findings from scan jobs and bulk ingests.
func (c *Client) ListFindings(ctx context.Context, query FindingQuery) (JSON, error) {
	values := url.Values{}
	if query.Severity != "" {
		values.Set("severity", query.Severity)
	}
	if query.Sort != "" {
		values.Set("sort", query.Sort)
	}
	if query.Limit != nil {
		values.Set("limit", fmt.Sprint(*query.Limit))
	}
	if query.Offset != nil {
		values.Set("offset", fmt.Sprint(*query.Offset))
	}
	return c.request(ctx, http.MethodGet, "/v1/findings", values, nil)
}

// IngestFindingsRequest posts normalized findings directly into the control plane.
type IngestFindingsRequest struct {
	Findings      []JSON
	Source        string
	SchemaVersion string
	Metadata      JSON
	TenantID      string
}

// IngestFindings posts normalized findings directly into the control plane.
func (c *Client) IngestFindings(ctx context.Context, req IngestFindingsRequest) (JSON, error) {
	return c.request(ctx, http.MethodPost, "/v1/findings/bulk", nil, compact(JSON{
		"findings":       req.Findings,
		"source":         req.Source,
		"schema_version": req.SchemaVersion,
		"metadata":       req.Metadata,
		"tenant_id":      firstNonEmpty(req.TenantID, c.tenantID),
	}))
}

// DatasetVersionRequest registers one dataset version artifact.
type DatasetVersionRequest struct {
	DatasetID       string
	VersionID       string
	ArtifactURI     string
	Digest          string
	DigestAlgorithm string
	Source          string
	Metadata        JSON
	TenantID        string
}

// RegisterDatasetVersion registers one dataset version artifact.
func (c *Client) RegisterDatasetVersion(ctx context.Context, req DatasetVersionRequest) (JSON, error) {
	path := "/v1/datasets/" + url.PathEscape(req.DatasetID) + "/versions"
	return c.request(ctx, http.MethodPost, path, nil, compact(JSON{
		"version_id":       req.VersionID,
		"artifact_uri":     req.ArtifactURI,
		"digest":           req.Digest,
		"digest_algorithm": req.DigestAlgorithm,
		"source":           req.Source,
		"metadata":         req.Metadata,
		"tenant_id":        firstNonEmpty(req.TenantID, c.tenantID),
	}))
}

// DatasetVersions lists versions for a dataset.
func (c *Client) DatasetVersions(ctx context.Context, datasetID string) (JSON, error) {
	return c.request(ctx, http.MethodGet, "/v1/datasets/"+url.PathEscape(datasetID)+"/versions", nil, nil)
}

// DatasetVersion returns one dataset version record.
func (c *Client) DatasetVersion(ctx context.Context, datasetID string, versionID string) (JSON, error) {
	path := "/v1/datasets/" + url.PathEscape(datasetID) + "/versions/" + url.PathEscape(versionID)
	return c.request(ctx, http.MethodGet, path, nil, nil)
}

// AgentManifest returns the tenant-scoped Agent BOM manifest.
func (c *Client) AgentManifest(ctx context.Context, tenantID string) (JSON, error) {
	values := url.Values{}
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID != "" {
		values.Set("tenant_id", tenantID)
	}
	return c.request(ctx, http.MethodGet, "/v1/agent-bom/manifest", values, nil)
}

// RuntimeProductionIndex returns runtime production-index posture.
func (c *Client) RuntimeProductionIndex(ctx context.Context, tenantID string) (JSON, error) {
	values := url.Values{}
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID != "" {
		values.Set("tenant_id", tenantID)
	}
	return c.request(ctx, http.MethodGet, "/v1/runtime/production-index", values, nil)
}

// IntelLookup looks up one advisory by CVE, GHSA, or OSV identifier.
func (c *Client) IntelLookup(ctx context.Context, advisoryID string) (JSON, error) {
	return c.request(ctx, http.MethodGet, "/v1/intel/advisories/"+url.PathEscape(advisoryID), nil, nil)
}

// IntelMatchRequest matches package coordinates against advisory intelligence.
type IntelMatchRequest struct {
	Packages  []JSON
	PURL      string
	Ecosystem string
	Name      string
	Version   string
	Limit     *int
}

// IntelMatch matches package coordinates against advisory intelligence.
func (c *Client) IntelMatch(ctx context.Context, req IntelMatchRequest) (JSON, error) {
	return c.request(ctx, http.MethodPost, "/v1/intel/match", nil, compact(JSON{
		"packages":  req.Packages,
		"purl":      req.PURL,
		"ecosystem": req.Ecosystem,
		"name":      req.Name,
		"version":   req.Version,
		"limit":     req.Limit,
	}))
}

// IntelSources lists configured advisory intelligence sources and freshness.
func (c *Client) IntelSources(ctx context.Context) (JSON, error) {
	return c.request(ctx, http.MethodGet, "/v1/intel/sources", nil, nil)
}

func (c *Client) request(ctx context.Context, method string, path string, values url.Values, body JSON) (JSON, error) {
	endpoint := c.url(path)
	if len(values) > 0 {
		endpoint += "?" + values.Encode()
	}

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(payload)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	for key, value := range c.defaultHeaders {
		request.Header.Set(key, value)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		request.Header.Set("X-API-Key", c.apiKey)
	}
	if c.bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
	if c.tenantID != "" {
		request.Header.Set("X-Agent-Bom-Tenant-ID", c.tenantID)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	text, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &APIError{StatusCode: response.StatusCode, Body: string(text)}
	}
	if len(text) == 0 {
		return JSON{}, nil
	}
	var data JSON
	if err := json.Unmarshal(text, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func (c *Client) url(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return c.baseURL + "/" + strings.TrimLeft(path, "/")
}

func compact(values JSON) JSON {
	result := JSON{}
	for key, value := range values {
		switch typed := value.(type) {
		case nil:
			continue
		case string:
			if typed == "" {
				continue
			}
		case JSON:
			if len(typed) == 0 {
				continue
			}
		}
		result[key] = value
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
