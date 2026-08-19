package sites

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

type Site struct {
	Name      string `json:"name"`
	Category  string `json:"category"`
	URL       string `json:"url"`
	Method    string `json:"method"`
	ErrorType string `json:"error_type"` // status_code | message
	ErrorCode int    `json:"error_code"`
	ErrorMsg  string `json:"error_msg"`
}

type Catalog struct {
	mu    sync.RWMutex
	sites []Site
	byName map[string]Site
}

func LoadFile(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadJSON(raw)
}

func LoadJSON(raw []byte) (*Catalog, error) {
	var list []Site
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	c := &Catalog{
		sites:  make([]Site, 0, len(list)),
		byName: make(map[string]Site, len(list)),
	}
	for _, s := range list {
		if strings.TrimSpace(s.Name) == "" || !strings.Contains(s.URL, "{}") {
			continue
		}
		if s.Method == "" {
			s.Method = "GET"
		}
		if s.ErrorType == "" {
			s.ErrorType = "status_code"
			if s.ErrorCode == 0 {
				s.ErrorCode = 404
			}
		}
		c.sites = append(c.sites, s)
		c.byName[strings.ToLower(s.Name)] = s
	}
	if len(c.sites) == 0 {
		return nil, fmt.Errorf("site catalog is empty")
	}
	return c, nil
}

func (c *Catalog) All() []Site {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Site, len(c.sites))
	copy(out, c.sites)
	return out
}

func (c *Catalog) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sites)
}

func (c *Catalog) Filter(names []string) ([]Site, error) {
	if len(names) == 0 {
		return c.All(), nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Site, 0, len(names))
	missing := make([]string, 0)
	for _, n := range names {
		s, ok := c.byName[strings.ToLower(strings.TrimSpace(n))]
		if !ok {
			missing = append(missing, n)
			continue
		}
		out = append(out, s)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("unknown sites: %s", strings.Join(missing, ", "))
	}
	return out, nil
}
