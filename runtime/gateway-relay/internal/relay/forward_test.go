package relay_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/msaad00/agent-bom/runtime/gateway-relay/internal/relay"
)

func TestForwardEcho(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("auth header %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		var msg map[string]any
		if err := json.Unmarshal(body, &msg); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      msg["id"],
			"result":  map[string]any{"ok": true},
		})
	}))
	defer upstream.Close()

	f := relay.NewForwarder()
	out, err := f.Forward(context.Background(), relay.RelayForwardRequest{
		Upstream: relay.RelayUpstreamTarget{Name: "echo", URL: upstream.URL},
		Message: map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params":  map[string]any{},
		},
		Headers: map[string]string{"Authorization": "Bearer tok"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.UpstreamName != "echo" {
		t.Fatalf("upstream_name %q", out.UpstreamName)
	}
	if out.BytesRead <= 0 {
		t.Fatalf("bytes_read %d", out.BytesRead)
	}
	if out.Message["id"] != float64(1) && out.Message["id"] != 1 {
		// json.Unmarshal numbers as float64
		if id, ok := out.Message["id"].(float64); !ok || id != 1 {
			t.Fatalf("id %#v", out.Message["id"])
		}
	}
	if _, ok := out.Message["result"]; !ok {
		t.Fatalf("missing result: %#v", out.Message)
	}
}

func TestForwardOversizedResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "2097153")
		payload := `{"` + strings.Repeat("a", relay.MaxMessageBytes+1) + `":1}`
		_, _ = w.Write([]byte(payload))
	}))
	defer upstream.Close()

	f := relay.NewForwarder()
	_, err := f.Forward(context.Background(), relay.RelayForwardRequest{
		Upstream: relay.RelayUpstreamTarget{Name: "big", URL: upstream.URL},
		Message:  map[string]any{"jsonrpc": "2.0", "id": 1, "method": "x"},
	})
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected oversize error, got %v", err)
	}
}

func TestForwardNonJSONWrapped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello-raw"))
	}))
	defer upstream.Close()

	f := relay.NewForwarder()
	out, err := f.Forward(context.Background(), relay.RelayForwardRequest{
		Upstream: relay.RelayUpstreamTarget{Name: "raw", URL: upstream.URL},
		Message:  map[string]any{"jsonrpc": "2.0", "id": "abc", "method": "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, ok := out.Message["result"].(map[string]any)
	if !ok {
		t.Fatalf("result type %#v", out.Message["result"])
	}
	if result["raw"] != "hello-raw" {
		t.Fatalf("raw %#v", result["raw"])
	}
}
