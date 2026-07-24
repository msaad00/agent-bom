// Command gateway-relay is the optional Go pure-relay sidecar (ADR-009 Phase 3 spike).
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/msaad00/agent-bom/runtime/gateway-relay/internal/relay"
)

func main() {
	addr := flag.String("listen", envOr("GATEWAY_RELAY_LISTEN", "127.0.0.1:8091"), "listen address")
	flag.Parse()

	srv := &relay.Server{Forwarder: relay.NewForwarder()}
	log.Printf("gateway-relay listening on http://%s", *addr)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
