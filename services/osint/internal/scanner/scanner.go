package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/your-org/breachsentinel/services/osint/internal/sites"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{2,64}$`)

type Status string

const (
	StatusFound    Status = "found"
	StatusNotFound Status = "not_found"
	StatusError    Status = "error"
	StatusUnknown  Status = "unknown"
)

type Result struct {
	Site     string `json:"site"`
	Category string `json:"category"`
	URL      string `json:"url"`
	Status   Status `json:"status"`
	HTTPCode int    `json:"http_code,omitempty"`
	Error    string `json:"error,omitempty"`
	LatencyMS int64 `json:"latency_ms"`
}

type Summary struct {
	Username   string        `json:"username"`
	Total      int           `json:"total"`
	Found      int           `json:"found"`
	NotFound   int           `json:"not_found"`
	Errors     int           `json:"errors"`
	Unknown    int           `json:"unknown"`
	DurationMS int64         `json:"duration_ms"`
	Results    []Result      `json:"results"`
}

type Engine struct {
	Client         *http.Client
	MaxConcurrency int
	UserAgent      string
}

func ValidateUsername(username string) error {
	u := strings.TrimSpace(username)
	if !usernamePattern.MatchString(u) {
		return fmt.Errorf("invalid username: use 2-64 chars [A-Za-z0-9._-]")
	}
	return nil
}

func (e *Engine) Scan(ctx context.Context, username string, catalog []sites.Site) Summary {
	start := time.Now()
	username = strings.TrimSpace(username)
	results := make([]Result, len(catalog))

	workers := e.MaxConcurrency
	if workers <= 0 {
		workers = 20
	}
	if workers > len(catalog) && len(catalog) > 0 {
		workers = len(catalog)
	}

	jobs := make(chan int, len(catalog))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = e.checkSite(ctx, username, catalog[idx])
			}
		}()
	}
	for i := range catalog {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	summary := Summary{
		Username:   username,
		Total:      len(catalog),
		DurationMS: time.Since(start).Milliseconds(),
		Results:    results,
	}
	for _, r := range results {
		switch r.Status {
		case StatusFound:
			summary.Found++
		case StatusNotFound:
			summary.NotFound++
		case StatusError:
			summary.Errors++
		default:
			summary.Unknown++
		}
	}
	return summary
}

func (e *Engine) checkSite(ctx context.Context, username string, site sites.Site) Result {
	start := time.Now()
	target := strings.ReplaceAll(site.URL, "{}", username)
	res := Result{
		Site:     site.Name,
		Category: site.Category,
		URL:      target,
		Status:   StatusUnknown,
	}

	method := strings.ToUpper(site.Method)
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		res.Status = StatusError
		res.Error = err.Error()
		res.LatencyMS = time.Since(start).Milliseconds()
		return res
	}
	ua := e.UserAgent
	if ua == "" {
		ua = "BreachSentinel-OSINT/0.4"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")

	client := e.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		res.Status = StatusError
		res.Error = err.Error()
		res.LatencyMS = time.Since(start).Milliseconds()
		return res
	}
	defer resp.Body.Close()

	res.HTTPCode = resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(body)

	switch strings.ToLower(site.ErrorType) {
	case "message":
		if site.ErrorMsg != "" && strings.Contains(bodyStr, site.ErrorMsg) {
			res.Status = StatusNotFound
		} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			res.Status = StatusFound
		} else if resp.StatusCode == 404 {
			res.Status = StatusNotFound
		} else {
			res.Status = StatusUnknown
		}
	default: // status_code
		code := site.ErrorCode
		if code == 0 {
			code = 404
		}
		if resp.StatusCode == code {
			res.Status = StatusNotFound
		} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			res.Status = StatusFound
		} else {
			res.Status = StatusUnknown
			res.Error = fmt.Sprintf("unexpected status %d", resp.StatusCode)
		}
	}

	res.LatencyMS = time.Since(start).Milliseconds()
	return res
}
