// Command event-collector is the Go sidecar for posture change-event collection.
//
// Lane: queue poll → normalize CloudTrail → POST batch to control plane.
// See docs/design/EVENT_COLLECTOR_CONTRACT.md. Python keeps dispatch/CIS/persist.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/msaad00/agent-bom/runtime/event-collector/internal/forward"
	"github.com/msaad00/agent-bom/runtime/event-collector/internal/normalize"
)

// options holds the parsed command-line configuration.
type options struct {
	listen             string
	controlPlaneURL    string
	apiKeyFile         string
	inboundTokenFile   string
	mode               string
	enableDevEndpoints bool
}

func parseFlags(fs *flag.FlagSet, args []string) (*options, error) {
	opts := &options{}
	fs.StringVar(&opts.listen, "listen", "127.0.0.1:8092", "HTTP listen address; exposing beyond loopback is an explicit operator choice")
	fs.StringVar(&opts.controlPlaneURL, "control-plane-url", "", "Control plane base URL (required for forward)")
	fs.StringVar(&opts.apiKeyFile, "api-key-file", "", "Path to file containing Bearer API key for control-plane ingest (egress)")
	fs.StringVar(&opts.inboundTokenFile, "inbound-token-file", "", "Path to file containing the Bearer token inbound callers must present (ingress; must not be the egress key)")
	fs.BoolVar(&opts.enableDevEndpoints, "enable-dev-endpoints", false, "Serve the /v1 dev helper endpoints; requires --inbound-token-file")
	fs.StringVar(&opts.mode, "mode", "stub", "Collector mode: stub (no AWS) or sqs (Phase 2+ bounded poll)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	opts.mode = strings.ToLower(strings.TrimSpace(opts.mode))
	switch opts.mode {
	case "stub", "sqs":
	default:
		return nil, fmt.Errorf("unsupported --mode %q (want stub|sqs)", opts.mode)
	}
	if opts.inboundTokenFile != "" && opts.inboundTokenFile == opts.apiKeyFile {
		return nil, fmt.Errorf("--inbound-token-file must not be the same file as --api-key-file")
	}
	return opts, nil
}

// loadCredentials reads the egress API key and the inbound bearer token.
//
// Fail-closed: enabling the dev endpoints without an inbound token is a
// configuration error, and the inbound token may never be the egress key —
// an ingress credential that equals the control-plane credential would let any
// caller who learns one use the other.
func loadCredentials(opts *options) (apiKey string, inboundToken string, err error) {
	if opts.apiKeyFile != "" {
		b, readErr := os.ReadFile(opts.apiKeyFile)
		if readErr != nil {
			return "", "", fmt.Errorf("read --api-key-file: %w", readErr)
		}
		apiKey = strings.TrimSpace(string(b))
	}
	if opts.inboundTokenFile != "" {
		b, readErr := os.ReadFile(opts.inboundTokenFile)
		if readErr != nil {
			return "", "", fmt.Errorf("read --inbound-token-file: %w", readErr)
		}
		inboundToken = strings.TrimSpace(string(b))
		if inboundToken == "" {
			return "", "", fmt.Errorf("--inbound-token-file is empty")
		}
	}
	if opts.enableDevEndpoints && inboundToken == "" {
		return "", "", fmt.Errorf("--enable-dev-endpoints requires a non-empty --inbound-token-file")
	}
	if inboundToken != "" && apiKey != "" && inboundToken == apiKey {
		return "", "", fmt.Errorf("--inbound-token-file must hold a different secret than --api-key-file")
	}
	return apiKey, inboundToken, nil
}

// tokenMatches compares two bearer tokens without leaking their contents
// through timing. Digesting first keeps the comparison length-independent.
func tokenMatches(got, want string) bool {
	if want == "" || got == "" {
		return false
	}
	gotSum := sha256.Sum256([]byte(got))
	wantSum := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) == 1
}

func bearerToken(header string) string {
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// requireInboundToken rejects callers that do not present the collector's own
// bearer token. It answers 401 with no body so a prober learns nothing about
// the collector's configuration.
func requireInboundToken(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenMatches(bearerToken(r.Header.Get("Authorization")), token) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// newMux builds the collector HTTP surface.
//
// /healthz is unauthenticated so a kubelet probe works. The /v1 dev helpers are
// registered only when the operator enabled them AND an inbound token exists;
// without both they are absent (404), never served open.
func newMux(mode string, fwd *forward.Client, inboundToken string, enableDevEndpoints bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","mode":"` + mode + `"}`))
	})
	if !enableDevEndpoints || inboundToken == "" {
		return mux
	}

	mux.HandleFunc("/v1/normalize/cloudtrail", requireInboundToken(inboundToken, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		ev, err := normalize.ParseCloudTrail(body)
		if err != nil {
			http.Error(w, "parse error", http.StatusBadRequest)
			return
		}
		if ev == nil {
			http.Error(w, "unrecognized or unsupported cloudtrail event", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(true)
		_ = enc.Encode(ev)
	}))
	// Dev/operator helper: normalize CloudTrail then forward to the control plane.
	mux.HandleFunc("/v1/forward/cloudtrail", requireInboundToken(inboundToken, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if fwd.ControlPlaneURL == "" {
			http.Error(w, "control-plane-url is required for forward", http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		ev, err := normalize.ParseCloudTrail(body)
		if err != nil || ev == nil {
			http.Error(w, "unrecognized or unsupported cloudtrail event", http.StatusBadRequest)
			return
		}
		if err := fwd.ForwardBatch(r.Context(), []*normalize.CloudChangeEvent{ev}); err != nil {
			http.Error(w, "forward failed", http.StatusBadGateway)
			log.Printf("forward failed: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"forwarded","path":"` + forward.IngestPath + `"}`))
	}))
	return mux
}

func main() {
	opts, err := parseFlags(flag.CommandLine, os.Args[1:])
	if err != nil {
		log.Fatalf("%v", err)
	}

	apiKey, inboundToken, err := loadCredentials(opts)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fwd := forward.NewClient(opts.controlPlaneURL, apiKey)

	srv := &http.Server{
		Addr:              opts.listen,
		Handler:           newMux(opts.mode, fwd, inboundToken, opts.enableDevEndpoints),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf(
			"event-collector listening on %s mode=%s ingest=%s dev-endpoints=%t",
			opts.listen, opts.mode, forward.IngestPath, opts.enableDevEndpoints,
		)
		if opts.mode == "sqs" {
			log.Printf("mode=sqs: bounded SQS poll not wired yet")
		}
		if !opts.enableDevEndpoints {
			log.Printf("dev endpoints disabled; /v1 helpers require --enable-dev-endpoints and --inbound-token-file")
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	fmt.Fprintln(os.Stderr, "event-collector stopped")
}
