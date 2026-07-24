package forward_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/msaad00/agent-bom/runtime/event-collector/internal/forward"
	"github.com/msaad00/agent-bom/runtime/event-collector/internal/normalize"
)

func TestForwardBatchPostsIngestPath(t *testing.T) {
	t.Parallel()

	var gotPath, gotAuth, gotCT string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	t.Cleanup(srv.Close)

	client := forward.NewClient(srv.URL, "test-api-key")
	client.HTTPClient = srv.Client()

	err := client.ForwardBatch(context.Background(), []*normalize.CloudChangeEvent{
		{
			Provider:     "aws",
			Account:      "123456789012",
			Region:       "us-east-1",
			ResourceType: "s3",
			ResourceID:   "bucket",
			Action:       "PutBucketPolicy",
		},
	})
	if err != nil {
		t.Fatalf("ForwardBatch: %v", err)
	}
	if gotPath != forward.IngestPath {
		t.Fatalf("path=%q want %q", gotPath, forward.IngestPath)
	}
	if gotAuth != "Bearer test-api-key" {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	if !strings.HasPrefix(gotCT, "application/json") {
		t.Fatalf("Content-Type=%q", gotCT)
	}
	events, _ := gotBody["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("events len=%d body=%v", len(events), gotBody)
	}
}

func TestForwardBatchTreats404AsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Not Found"}`))
	}))
	t.Cleanup(srv.Close)

	client := forward.NewClient(srv.URL, "")
	client.HTTPClient = srv.Client()
	err := client.ForwardBatch(context.Background(), []*normalize.CloudChangeEvent{
		{Provider: "aws", Account: "1", Region: "us-east-1", ResourceType: "s3", ResourceID: "b", Action: "x"},
	})
	if err == nil {
		t.Fatal("expected error on 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error=%v", err)
	}
}
