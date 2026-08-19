package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/your-org/breachsentinel/services/osint/internal/config"
	"github.com/your-org/breachsentinel/services/osint/internal/scanner"
	"github.com/your-org/breachsentinel/services/osint/internal/sites"
)

type Server struct {
	Cfg     config.Config
	Catalog *sites.Catalog
	Engine  *scanner.Engine
}

type scanRequest struct {
	Username       string   `json:"username"`
	Sites          []string `json:"sites"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	OnlyFound      bool     `json:"only_found"`
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/sites", s.handleSites)
	mux.HandleFunc("/api/v1/scan", s.handleScan)
	return withSecurityHeaders(withCORS(mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"service":     "breachsentinel-osint",
		"phase":       4,
		"sites":       s.Catalog.Count(),
		"concurrency": s.Cfg.MaxConcurrency,
		"ts":          time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleSites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	list := s.Catalog.All()
	type siteDTO struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		URL      string `json:"url_template"`
	}
	out := make([]siteDTO, 0, len(list))
	for _, site := range list {
		out = append(out, siteDTO{
			Name:     site.Name,
			Category: site.Category,
			URL:      site.URL,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(out),
		"sites": out,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req scanRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if err := scanner.ValidateUsername(req.Username); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_username", err.Error())
		return
	}

	selected, err := s.Catalog.Filter(req.Sites)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "unknown_sites", err.Error())
		return
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	summary := s.Engine.Scan(ctx, req.Username, selected)
	if req.OnlyFound {
		filtered := make([]scanner.Result, 0, summary.Found)
		for _, item := range summary.Results {
			if item.Status == scanner.StatusFound {
				filtered = append(filtered, item)
			}
		}
		summary.Results = filtered
	}
	writeJSON(w, http.StatusOK, summary)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, code int, errCode, message string) {
	writeJSON(w, code, map[string]any{
		"error":   errCode,
		"message": message,
		"phase":   4,
	})
}
