package agentbom

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(Options{
		BaseURL:  server.URL + "/",
		APIKey:   "secret",
		TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestClientSetsAuthHeadersAndStripsEmptyBodyFields(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/graph/should-i-deploy" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "secret" {
			t.Fatalf("X-API-Key = %q", got)
		}
		if got := r.Header.Get("X-Agent-Bom-Tenant-ID"); got != "tenant-a" {
			t.Fatalf("X-Agent-Bom-Tenant-ID = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
		var body JSON
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode body: %v", err)
		}
		if _, ok := body["context"]; ok {
			t.Fatalf("empty context should be omitted: %#v", body)
		}
		if body["tenant_id"] != "tenant-a" || body["candidate"] != "flask@2.0.0" {
			t.Fatalf("unexpected body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	})

	blockRisk := 80
	result, err := client.ShouldIDeploy(context.Background(), DeployDecisionRequest{
		Candidate: "flask@2.0.0",
		BlockRisk: &blockRisk,
	})
	if err != nil {
		t.Fatalf("ShouldIDeploy: %v", err)
	}
	if result["decision"] != "allow" {
		t.Fatalf("decision = %#v", result["decision"])
	}
}

func TestClientBuildsQueryParams(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/graph/exposure-paths" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		query := r.URL.Query()
		if query.Get("tenant_id") != "tenant-a" || query.Get("limit") != "5" || query.Get("min_risk") != "70" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"paths":[]}`))
	})

	limit := 5
	minRisk := 70
	if _, err := client.ExposurePaths(context.Background(), ExposurePathQuery{Limit: &limit, MinRisk: &minRisk}); err != nil {
		t.Fatalf("ExposurePaths: %v", err)
	}
}

func TestClientExposesHeadlineRoutes(t *testing.T) {
	var seen []string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	ctx := context.Background()
	if _, err := client.AgentManifest(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RuntimeProductionIndex(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.IntelLookup(ctx, "GHSA-xxxx-yyyy-zzzz"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.IntelMatch(ctx, IntelMatchRequest{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.IntelSources(ctx); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"GET /v1/agent-bom/manifest",
		"GET /v1/runtime/production-index",
		"GET /v1/intel/advisories/GHSA-xxxx-yyyy-zzzz",
		"POST /v1/intel/match",
		"GET /v1/intel/sources",
	}
	if len(seen) != len(want) {
		t.Fatalf("seen = %#v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("seen[%d] = %q, want %q", i, seen[i], want[i])
		}
	}
}

func TestClientExposesFindingsAndDatasetLoop(t *testing.T) {
	var seen []string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	ctx := context.Background()
	limit := 10
	if _, err := client.ListFindings(ctx, FindingQuery{Severity: "high", Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.IngestFindings(ctx, IngestFindingsRequest{Findings: []JSON{{"id": "finding-1", "severity": "high"}}, Source: "sdk-test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterDatasetVersion(ctx, DatasetVersionRequest{DatasetID: "dataset-a", VersionID: "v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DatasetVersions(ctx, "dataset-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DatasetVersion(ctx, "dataset-a", "v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterEvaluationRun(ctx, EvaluationRunRequest{EvaluationID: "eval-a", DatasetID: "dataset-a", DatasetVersionID: "v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.EvaluationRuns(ctx, EvaluationRunQuery{DatasetID: "dataset-a", Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.EvaluationRun(ctx, "eval-a"); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"GET /v1/findings",
		"POST /v1/findings/bulk",
		"POST /v1/datasets/dataset-a/versions",
		"GET /v1/datasets/dataset-a/versions",
		"GET /v1/datasets/dataset-a/versions/v1",
		"POST /v1/evaluations",
		"GET /v1/evaluations",
		"GET /v1/evaluations/eval-a",
	}
	if len(seen) != len(want) {
		t.Fatalf("seen = %#v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("seen[%d] = %q, want %q", i, seen[i], want[i])
		}
	}
}

func TestClientRejectsAmbiguousAuth(t *testing.T) {
	_, err := NewClient(Options{BaseURL: "https://agent-bom.example.com", APIKey: "a", BearerToken: "b"})
	if err == nil {
		t.Fatal("expected ambiguous auth error")
	}
}

func TestClientRaisesAPIErrorWithBody(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"forbidden"}`, http.StatusForbidden)
	})

	_, err := client.Health(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden || apiErr.Body == "" {
		t.Fatalf("unexpected APIError: %#v", apiErr)
	}
}

func TestClientRuntimeEventsAndSessions(t *testing.T) {
	var seen []string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		if r.URL.Path == "/v1/runtime/events" {
			var body JSON
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("Decode body: %v", err)
			}
			if body["tenant_id"] != "tenant-a" {
				t.Fatalf("tenant_id = %#v", body["tenant_id"])
			}
			if _, ok := body["events"]; !ok {
				t.Fatalf("events missing: %#v", body)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"runtime.v1"}`))
	})

	ctx := context.Background()
	limit := 5
	if _, err := client.IngestRuntimeEvents(ctx, IngestRuntimeEventsRequest{Events: []JSON{{"kind": "tool_call"}}}); err != nil {
		t.Fatalf("IngestRuntimeEvents: %v", err)
	}
	if _, err := client.RuntimeSessions(ctx, RuntimeSessionQuery{Limit: &limit}); err != nil {
		t.Fatalf("RuntimeSessions: %v", err)
	}
	if _, err := client.RuntimeObservations(ctx, RuntimeObservationQuery{SessionID: "sess-1", Limit: &limit}); err != nil {
		t.Fatalf("RuntimeObservations: %v", err)
	}
	if _, err := client.RuntimeSessionObservations(ctx, "sess/1", RuntimeSessionObservationQuery{Limit: &limit}); err != nil {
		t.Fatalf("RuntimeSessionObservations: %v", err)
	}

	want := []string{
		"POST /v1/runtime/events",
		"GET /v1/runtime/sessions?limit=5&tenant_id=tenant-a",
		"GET /v1/runtime/observations?limit=5&session_id=sess-1&tenant_id=tenant-a",
		"GET /v1/runtime/sessions/sess%2F1/observations?limit=5&tenant_id=tenant-a",
	}
	if len(seen) != len(want) {
		t.Fatalf("seen = %#v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("request %d = %q, want %q", i, seen[i], want[i])
		}
	}
}
