package main

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/msaad00/agent-bom/runtime/event-collector/internal/forward"
)

const (
	inboundToken = "inbound-collector-token-abcdef"
	egressAPIKey = "control-plane-egress-key-123456"
)

// sampleEvent is a CloudTrail record the normalizer recognizes.
const sampleEvent = `{
  "detail": {
    "eventSource": "s3.amazonaws.com",
    "eventName": "PutBucketPolicy",
    "awsRegion": "us-east-1",
    "recipientAccountId": "123456789012",
    "requestParameters": {"bucketName": "my-bucket"}
  }
}`

// fakeControlPlane records every ingest attempt so tests can prove that an
// unauthenticated caller never reaches the control plane.
type fakeControlPlane struct {
	server *httptest.Server
	hits   atomic.Int32
	authHZ atomic.Value // last Authorization header seen
}

func newFakeControlPlane(t *testing.T) *fakeControlPlane {
	t.Helper()
	cp := &fakeControlPlane{}
	cp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cp.hits.Add(1)
		cp.authHZ.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	t.Cleanup(cp.server.Close)
	return cp
}

func (cp *fakeControlPlane) lastAuth() string {
	v, _ := cp.authHZ.Load().(string)
	return v
}

func post(t *testing.T, mux http.Handler, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// --- flag defaults -----------------------------------------------------

// The collector must not bind every interface by default; exposing it is an
// explicit operator decision.
func TestListenDefaultsToLoopback(t *testing.T) {
	opts, err := parseFlags(flag.NewFlagSet("test", flag.ContinueOnError), nil)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if opts.listen != "127.0.0.1:8092" {
		t.Fatalf("default --listen = %q, want 127.0.0.1:8092", opts.listen)
	}
}

func TestDevEndpointsDefaultOffAndTokenFileFlagExists(t *testing.T) {
	opts, err := parseFlags(flag.NewFlagSet("test", flag.ContinueOnError), nil)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if opts.enableDevEndpoints {
		t.Fatal("--enable-dev-endpoints must default to false")
	}
	if opts.inboundTokenFile != "" {
		t.Fatalf("--inbound-token-file default = %q, want empty", opts.inboundTokenFile)
	}
	parsed, err := parseFlags(flag.NewFlagSet("test", flag.ContinueOnError),
		[]string{"--enable-dev-endpoints", "--inbound-token-file=/run/secrets/inbound"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !parsed.enableDevEndpoints || parsed.inboundTokenFile != "/run/secrets/inbound" {
		t.Fatalf("flags not wired: %+v", parsed)
	}
}

// The egress API key must never double as the inbound credential.
func TestInboundTokenFileIsSeparateFromAPIKeyFile(t *testing.T) {
	_, err := parseFlags(flag.NewFlagSet("test", flag.ContinueOnError),
		[]string{"--api-key-file=/run/secrets/key", "--inbound-token-file=/run/secrets/key"})
	if err == nil {
		t.Fatal("parseFlags accepted the same file for the inbound token and the egress key")
	}
}

func writeSecret(t *testing.T, name, value string) string {
	t.Helper()
	path := t.TempDir() + "/" + name
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadCredentialsFailsClosed(t *testing.T) {
	keyPath := writeSecret(t, "egress", egressAPIKey)

	t.Run("dev endpoints without an inbound token", func(t *testing.T) {
		_, _, err := loadCredentials(&options{apiKeyFile: keyPath, enableDevEndpoints: true})
		if err == nil {
			t.Fatal("enabled dev endpoints with no inbound token must be a configuration error")
		}
	})

	t.Run("empty inbound token file", func(t *testing.T) {
		empty := writeSecret(t, "inbound", "   ")
		if _, _, err := loadCredentials(&options{inboundTokenFile: empty, enableDevEndpoints: true}); err == nil {
			t.Fatal("an empty inbound token file must be a configuration error")
		}
	})

	t.Run("inbound token equal to the egress key", func(t *testing.T) {
		same := writeSecret(t, "inbound", egressAPIKey)
		opts := &options{apiKeyFile: keyPath, inboundTokenFile: same, enableDevEndpoints: true}
		if _, _, err := loadCredentials(opts); err == nil {
			t.Fatal("reusing the egress key as the inbound token must be a configuration error")
		}
	})

	t.Run("distinct secrets load", func(t *testing.T) {
		inbound := writeSecret(t, "inbound", inboundToken)
		key, token, err := loadCredentials(&options{
			apiKeyFile: keyPath, inboundTokenFile: inbound, enableDevEndpoints: true,
		})
		if err != nil {
			t.Fatalf("loadCredentials: %v", err)
		}
		if key != egressAPIKey || token != inboundToken {
			t.Fatalf("loadCredentials = (%q, %q), want (%q, %q)", key, token, egressAPIKey, inboundToken)
		}
	})
}

// --- fail-closed gating ------------------------------------------------

// Dev endpoints are off unless the operator opts in.
func TestDevEndpointsNotRegisteredByDefault(t *testing.T) {
	cp := newFakeControlPlane(t)
	mux := newMux("stub", forward.NewClient(cp.server.URL, egressAPIKey), inboundToken, false)

	for _, path := range []string{"/v1/forward/cloudtrail", "/v1/normalize/cloudtrail"} {
		rec := post(t, mux, path, inboundToken, sampleEvent)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s with dev endpoints disabled = %d, want 404", path, rec.Code)
		}
	}
	if got := cp.hits.Load(); got != 0 {
		t.Fatalf("control plane received %d requests, want 0", got)
	}
}

// No inbound token configured must fail closed: the forward endpoint is not
// served at all, rather than served open.
func TestForwardFailsClosedWhenNoInboundTokenConfigured(t *testing.T) {
	cp := newFakeControlPlane(t)
	mux := newMux("stub", forward.NewClient(cp.server.URL, egressAPIKey), "", true)

	for _, token := range []string{"", "any-token"} {
		rec := post(t, mux, "/v1/forward/cloudtrail", token, sampleEvent)
		if rec.Code == http.StatusOK {
			t.Errorf("forward served with no inbound token configured (token=%q): %d", token, rec.Code)
		}
		if rec.Code != http.StatusNotFound {
			t.Errorf("forward with no inbound token configured (token=%q) = %d, want 404", token, rec.Code)
		}
	}
	if got := cp.hits.Load(); got != 0 {
		t.Fatalf("control plane received %d requests, want 0", got)
	}
}

// --- inbound auth ------------------------------------------------------

func TestForwardAcceptsCorrectToken(t *testing.T) {
	cp := newFakeControlPlane(t)
	mux := newMux("stub", forward.NewClient(cp.server.URL, egressAPIKey), inboundToken, true)

	rec := post(t, mux, "/v1/forward/cloudtrail", inboundToken, sampleEvent)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward with correct token = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if got := cp.hits.Load(); got != 1 {
		t.Fatalf("control plane received %d requests, want 1", got)
	}
	// The egress credential is what reaches the control plane, never the
	// inbound token.
	if got, want := cp.lastAuth(), "Bearer "+egressAPIKey; got != want {
		t.Fatalf("forwarded Authorization = %q, want %q", got, want)
	}
}

func TestForwardRejectsMissingAuthorizationHeader(t *testing.T) {
	cp := newFakeControlPlane(t)
	mux := newMux("stub", forward.NewClient(cp.server.URL, egressAPIKey), inboundToken, true)

	rec := post(t, mux, "/v1/forward/cloudtrail", "", sampleEvent)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("forward without Authorization = %d, want 401", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Errorf("401 body = %q, want no detail", body)
	}
	if got := cp.hits.Load(); got != 0 {
		t.Fatalf("control plane received %d requests, want 0", got)
	}
}

func TestForwardRejectsWrongTokenAndDoesNotForward(t *testing.T) {
	cp := newFakeControlPlane(t)
	mux := newMux("stub", forward.NewClient(cp.server.URL, egressAPIKey), inboundToken, true)

	for _, bad := range []string{
		"wrong-token",
		inboundToken + "x",
		inboundToken[:len(inboundToken)-1],
		egressAPIKey, // the egress key must not authenticate inbound callers
		"",
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/forward/cloudtrail", strings.NewReader(sampleEvent))
		if bad != "" {
			req.Header.Set("Authorization", "Bearer "+bad)
		} else {
			req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("forward with token %q = %d, want 401", bad, rec.Code)
		}
	}
	if got := cp.hits.Load(); got != 0 {
		t.Fatalf("control plane received %d requests after rejected attempts, want 0", got)
	}
}

// Auth is checked before configuration state is revealed.
func TestForwardChecksAuthBeforeControlPlaneConfig(t *testing.T) {
	mux := newMux("stub", forward.NewClient("", egressAPIKey), inboundToken, true)

	rec := post(t, mux, "/v1/forward/cloudtrail", "", sampleEvent)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated forward without control-plane URL = %d, want 401", rec.Code)
	}
	rec = post(t, mux, "/v1/forward/cloudtrail", inboundToken, sampleEvent)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("authenticated forward without control-plane URL = %d, want 503", rec.Code)
	}
}

func TestNormalizeRequiresInboundToken(t *testing.T) {
	cp := newFakeControlPlane(t)
	mux := newMux("stub", forward.NewClient(cp.server.URL, egressAPIKey), inboundToken, true)

	if rec := post(t, mux, "/v1/normalize/cloudtrail", "", sampleEvent); rec.Code != http.StatusUnauthorized {
		t.Fatalf("normalize without Authorization = %d, want 401", rec.Code)
	}
	rec := post(t, mux, "/v1/normalize/cloudtrail", inboundToken, sampleEvent)
	if rec.Code != http.StatusOK {
		t.Fatalf("normalize with correct token = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PutBucketPolicy") {
		t.Errorf("normalize body = %q, want the normalized event", rec.Body.String())
	}
}

// Liveness stays reachable without a credential so the kubelet probe works.
func TestHealthzDoesNotRequireToken(t *testing.T) {
	mux := newMux("stub", forward.NewClient("", egressAPIKey), inboundToken, true)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("healthz body = %q", string(body))
	}
}
