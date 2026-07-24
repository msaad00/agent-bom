package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Forwarder POSTs an authorized JSON-RPC message to an upstream MCP URL.
type Forwarder struct {
	Client    *http.Client
	MaxBytes  int
}

func NewForwarder() *Forwarder {
	return &Forwarder{
		Client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 500,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		MaxBytes: MaxMessageBytes,
	}
}

func (f *Forwarder) Forward(ctx context.Context, req RelayForwardRequest) (RelayForwardResult, error) {
	maxBytes := f.MaxBytes
	if maxBytes <= 0 {
		maxBytes = MaxMessageBytes
	}
	if strings.TrimSpace(req.Upstream.URL) == "" {
		return RelayForwardResult{}, fmt.Errorf("upstream url is required")
	}
	body, err := json.Marshal(req.Message)
	if err != nil {
		return RelayForwardResult{}, fmt.Errorf("marshal message: %w", err)
	}
	if len(body) > maxBytes {
		return RelayForwardResult{}, fmt.Errorf("request body exceeded %d bytes", maxBytes)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.Upstream.URL, bytes.NewReader(body))
	if err != nil {
		return RelayForwardResult{}, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range req.Headers {
		if strings.EqualFold(k, "Content-Type") {
			continue
		}
		httpReq.Header.Set(k, v)
	}

	resp, err := f.Client.Do(httpReq)
	if err != nil {
		return RelayForwardResult{}, fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited := io.LimitReader(resp.Body, int64(maxBytes)+1)
		snippet, _ := io.ReadAll(limited)
		return RelayForwardResult{}, fmt.Errorf("upstream status %d: %s", resp.StatusCode, truncate(string(snippet), 200))
	}

	if cl := resp.Header.Get("Content-Length"); cl != "" {
		var n int
		if _, scanErr := fmt.Sscanf(cl, "%d", &n); scanErr == nil && n > maxBytes {
			return RelayForwardResult{}, fmt.Errorf("upstream response exceeded %d bytes", maxBytes)
		}
	}

	limited := io.LimitReader(resp.Body, int64(maxBytes)+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return RelayForwardResult{}, fmt.Errorf("read upstream body: %w", err)
	}
	if len(raw) > maxBytes {
		return RelayForwardResult{}, fmt.Errorf("upstream response exceeded %d bytes", maxBytes)
	}

	ct := resp.Header.Get("Content-Type")
	var parsed map[string]any
	if strings.HasPrefix(ct, "application/json") {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return RelayForwardResult{}, fmt.Errorf("decode upstream json: %w", err)
		}
	} else {
		parsed = map[string]any{
			"jsonrpc": "2.0",
			"id":      req.Message["id"],
			"result":  map[string]any{"raw": string(raw)},
		}
	}

	return RelayForwardResult{
		Message:      parsed,
		UpstreamName: req.Upstream.Name,
		BytesRead:    len(raw),
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
