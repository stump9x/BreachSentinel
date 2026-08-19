package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr     string
	MaxConcurrency int
	HTTPTimeout    time.Duration
	UserAgent      string
}

func Load() Config {
	return Config{
		ListenAddr:     getenv("OSINT_LISTEN_ADDR", ":8080"),
		MaxConcurrency: getenvInt("OSINT_MAX_CONCURRENCY", 50),
		HTTPTimeout:    time.Duration(getenvInt("OSINT_HTTP_TIMEOUT_SEC", 8)) * time.Second,
		UserAgent:      getenv("OSINT_USER_AGENT", "BreachSentinel-OSINT/0.4 (+local; research)"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
