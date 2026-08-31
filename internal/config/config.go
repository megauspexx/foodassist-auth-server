package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	Port           string
	GoogleClientID string        // Web-type OAuth client ID from Google Cloud Console
	AppleBundleID  string        // Your app's bundle identifier (aud claim in Apple's token)
	JWTSecret      string        // Secret used to sign the app's own session JWTs
	SessionTTL     time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:           getEnv("PORT", "8080"),
		GoogleClientID: os.Getenv("GOOGLE_CLIENT_ID"),
		AppleBundleID:  os.Getenv("APPLE_BUNDLE_ID"),
		JWTSecret:      os.Getenv("JWT_SECRET"),
		SessionTTL:     30 * 24 * time.Hour,
	}

	if cfg.GoogleClientID == "" {
		return nil, fmt.Errorf("GOOGLE_CLIENT_ID env var is required")
	}
	if cfg.AppleBundleID == "" {
		return nil, fmt.Errorf("APPLE_BUNDLE_ID env var is required")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET env var is required")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
