// Command event-collector is the Phase 1 Go stub for posture change-event collection.
//
// Lane: queue poll → normalize CloudTrail → POST batch to control plane.
// See docs/design/EVENT_COLLECTOR_CONTRACT.md. Python keeps dispatch/CIS/persist.
package main

import (
	"context"
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

func main() {
	listen := flag.String("listen", ":8092", "HTTP listen address")
	controlPlaneURL := flag.String("control-plane-url", "", "Control plane base URL (for forward; unused in stub mode)")
	apiKeyFile := flag.String("api-key-file", "", "Path to file containing Bearer API key for control-plane ingest")
	mode := flag.String("mode", "stub", "Collector mode: stub (no AWS) or sqs (Phase 2+)")
	flag.Parse()

	modeVal := strings.ToLower(strings.TrimSpace(*mode))
	switch modeVal {
	case "stub", "sqs":
	default:
		log.Fatalf("unsupported --mode %q (want stub|sqs)", *mode)
	}

	apiKey := ""
	if *apiKeyFile != "" {
		b, err := os.ReadFile(*apiKeyFile)
		if err != nil {
			log.Fatalf("read --api-key-file: %v", err)
		}
		apiKey = strings.TrimSpace(string(b))
	}

	fwd := forward.NewClient(*controlPlaneURL, apiKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","mode":"` + modeVal + `"}`))
	})
	mux.HandleFunc("/v1/normalize/cloudtrail", func(w http.ResponseWriter, r *http.Request) {
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
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("event-collector listening on %s mode=%s (ingest path %s; may 404 until Phase 2)", *listen, modeVal, forward.IngestPath)
		if modeVal == "sqs" {
			log.Printf("mode=sqs: Phase 1 stub does not poll AWS; configure SQS in Phase 2")
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	// Keep forward client referenced so operators can wire Phase 2 without API churn.
	_ = fwd

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	fmt.Fprintln(os.Stderr, "event-collector stopped")
}
