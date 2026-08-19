package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/your-org/breachsentinel/services/osint/internal/api"
	"github.com/your-org/breachsentinel/services/osint/internal/config"
	"github.com/your-org/breachsentinel/services/osint/internal/scanner"
	"github.com/your-org/breachsentinel/services/osint/internal/sites"
)

func main() {
	cfg := config.Load()

	catalogPath := getenv("OSINT_SITES_PATH", defaultSitesPath())
	catalog, err := sites.LoadFile(catalogPath)
	if err != nil {
		log.Fatalf("load site catalog %s: %v", catalogPath, err)
	}

	engine := &scanner.Engine{
		Client: &http.Client{
			Timeout: cfg.HTTPTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		MaxConcurrency: cfg.MaxConcurrency,
		UserAgent:      cfg.UserAgent,
	}

	srvAPI := &api.Server{Cfg: cfg, Catalog: catalog, Engine: engine}
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srvAPI.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      130 * time.Second,
	}

	log.Printf(
		"BreachSentinel OSINT Phase 4 listening on %s (sites=%d concurrency=%d)",
		cfg.ListenAddr, catalog.Count(), cfg.MaxConcurrency,
	)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func defaultSitesPath() string {
	candidates := []string{
		"data/sites.json",
		"/app/data/sites.json",
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append([]string{
			filepath.Join(filepath.Dir(exe), "data", "sites.json"),
			filepath.Join(filepath.Dir(exe), "..", "data", "sites.json"),
		}, candidates...)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "data/sites.json"
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
