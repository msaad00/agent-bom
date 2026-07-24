package relay_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/msaad00/agent-bom/runtime/gateway-relay/internal/relay"
)

func TestHealthz(t *testing.T) {
	srv := &relay.Server{Forwarder: relay.NewForwarder()}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestV1Forward(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		var msg map[string]any
		_ = json.Unmarshal(body, &msg)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      msg["id"],
			"result":  map[string]any{"echo": true},
		})
	}))
	defer upstream.Close()

	srv := &relay.Server{Forwarder: relay.NewForwarder()}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	payload := map[string]any{
		"upstream": map[string]any{
			"name":                     "echo",
			"url":                      upstream.URL,
			"tenant_id":                "",
			"private_network_approved": true,
		},
		"message": map[string]any{
			"jsonrpc": "2.0",
			"id":      42,
			"method":  "tools/call",
			"params":  map[string]any{"name": "echo"},
		},
		"headers": map[string]string{},
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(ts.URL+"/v1/forward", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d body %s", resp.StatusCode, b)
	}
	var result relay.RelayForwardResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.UpstreamName != "echo" {
		t.Fatalf("upstream %q", result.UpstreamName)
	}
	if _, ok := result.Message["result"]; !ok {
		t.Fatalf("missing result %#v", result.Message)
	}
}

func TestV1ForwardBodyCap(t *testing.T) {
	srv := &relay.Server{Forwarder: relay.NewForwarder(), MaxBytes: 1024}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	big := bytes.Repeat([]byte("a"), 2048)
	resp, err := http.Post(ts.URL+"/v1/forward", "application/json", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 413/400, got %d", resp.StatusCode)
	}
	_ = strings.Builder{} // keep strings imported for clarity in other tests
}
