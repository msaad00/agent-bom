package relay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Server serves /healthz and /v1/forward.
type Server struct {
	Forwarder *Forwarder
	MaxBytes  int
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /v1/forward", s.handleForward)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleForward(w http.ResponseWriter, r *http.Request) {
	maxBytes := s.MaxBytes
	if maxBytes <= 0 {
		maxBytes = MaxMessageBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var req RelayForwardRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "invalid RelayForwardRequest JSON", http.StatusBadRequest)
		return
	}
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	if req.Message == nil {
		http.Error(w, "message is required", http.StatusBadRequest)
		return
	}

	fwd := s.Forwarder
	if fwd == nil {
		fwd = NewForwarder()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := fwd.Forward(ctx, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
