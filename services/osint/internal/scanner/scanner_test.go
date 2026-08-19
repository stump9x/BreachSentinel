package scanner_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/your-org/breachsentinel/services/osint/internal/scanner"
	"github.com/your-org/breachsentinel/services/osint/internal/sites"
)

func TestValidateUsername(t *testing.T) {
	if err := scanner.ValidateUsername("ok_user-1"); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
	if err := scanner.ValidateUsername("bad user"); err == nil {
		t.Fatal("expected invalid username with space")
	}
	if err := scanner.ValidateUsername("x"); err == nil {
		t.Fatal("expected too short")
	}
}

func TestScanConcurrentFoundAndNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/exists/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("profile ok"))
	})
	mux.HandleFunc("/missing/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("missing"))
	})
	mux.HandleFunc("/msg/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "ghost") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("No such user"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("welcome"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	catalog := []sites.Site{
		{Name: "Exists", Category: "test", URL: srv.URL + "/exists/{}", ErrorType: "status_code", ErrorCode: 404},
		{Name: "Missing", Category: "test", URL: srv.URL + "/missing/{}", ErrorType: "status_code", ErrorCode: 404},
		{Name: "MsgGone", Category: "test", URL: srv.URL + "/msg/{}", ErrorType: "message", ErrorMsg: "No such user"},
	}

	engine := &scanner.Engine{
		Client:         srv.Client(),
		MaxConcurrency: 4,
		UserAgent:      "test-agent",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sum := engine.Scan(ctx, "ghost", catalog)
	if sum.Total != 3 {
		t.Fatalf("total=%d", sum.Total)
	}
	if sum.Found != 1 {
		t.Fatalf("found=%d want 1 (results=%v)", sum.Found, sum.Results)
	}
	if sum.NotFound != 2 {
		t.Fatalf("not_found=%d want 2 (results=%v)", sum.NotFound, sum.Results)
	}
}

func TestCatalogFilter(t *testing.T) {
	raw := []byte(`[
	  {"name":"Alpha","url":"https://a.example/{}","error_type":"status_code","error_code":404},
	  {"name":"Beta","url":"https://b.example/{}","error_type":"status_code","error_code":404}
	]`)
	cat, err := sites.LoadJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := cat.Filter([]string{"beta"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].Name != "Beta" {
		t.Fatalf("unexpected filter result: %#v", filtered)
	}
	if _, err := cat.Filter([]string{"Nope"}); err == nil {
		t.Fatal("expected unknown site error")
	}
}
