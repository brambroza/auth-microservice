// Package config reads settings from environment variables.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr     string
	DatabaseURL  string
	DBMaxConns   int32
	AutoMigrate  bool
	Issuer       string
	Audience     string
	MasterKey    []byte
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
	SessionMax   time.Duration
	ChallengeTTL time.Duration
	// Brute-force protection.
	MaxFailedLogins int
	LockDuration    time.Duration
	LoginRatePerMin int
	// TrustProxy makes the service read the client IP from X-Forwarded-For.
	// Turn it on only when the service is reachable solely through your gateway.
	TrustProxy  bool
	CORSOrigins []string
}

// Load reads and validates the configuration.
func Load() (Config, error) {
	c := Config{
		HTTPAddr:        env("AUTH_HTTP_ADDR", ":8080"),
		DatabaseURL:     os.Getenv("AUTH_DATABASE_URL"),
		Issuer:          strings.TrimRight(os.Getenv("AUTH_ISSUER"), "/"),
		Audience:        env("AUTH_AUDIENCE", "goalong"),
		AutoMigrate:     envBool("AUTH_AUTO_MIGRATE", true),
		TrustProxy:      envBool("AUTH_TRUST_PROXY", false),
		MaxFailedLogins: envInt("AUTH_MAX_FAILED_LOGINS", 10),
		LoginRatePerMin: envInt("AUTH_LOGIN_RATE_PER_MIN", 60),
		DBMaxConns:      int32(envInt("AUTH_DB_MAX_CONNS", 10)),
	}
	var err error
	if c.AccessTTL, err = envDur("AUTH_ACCESS_TTL", 10*time.Minute); err != nil {
		return c, err
	}
	if c.RefreshTTL, err = envDur("AUTH_REFRESH_TTL", 30*24*time.Hour); err != nil {
		return c, err
	}
	if c.SessionMax, err = envDur("AUTH_SESSION_MAX_TTL", 90*24*time.Hour); err != nil {
		return c, err
	}
	if c.ChallengeTTL, err = envDur("AUTH_MFA_CHALLENGE_TTL", 5*time.Minute); err != nil {
		return c, err
	}
	if c.LockDuration, err = envDur("AUTH_LOCK_DURATION", 15*time.Minute); err != nil {
		return c, err
	}
	for _, o := range strings.Split(os.Getenv("AUTH_CORS_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.CORSOrigins = append(c.CORSOrigins, o)
		}
	}

	if c.DatabaseURL == "" {
		return c, errors.New("AUTH_DATABASE_URL is required")
	}
	if c.Issuer == "" {
		return c, errors.New("AUTH_ISSUER is required (the public URL of this service)")
	}
	raw := os.Getenv("AUTH_MASTER_KEY")
	if raw == "" {
		return c, errors.New("AUTH_MASTER_KEY is required (generate with: openssl rand -base64 32)")
	}
	c.MasterKey, err = base64.StdEncoding.DecodeString(raw)
	if err != nil || len(c.MasterKey) != 32 {
		return c, errors.New("AUTH_MASTER_KEY must be 32 bytes, base64-encoded")
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v, err := strconv.ParseBool(os.Getenv(k))
	if err != nil {
		return def
	}
	return v
}

func envInt(k string, def int) int {
	v, err := strconv.Atoi(os.Getenv(k))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func envDur(k string, def time.Duration) (time.Duration, error) {
	s := os.Getenv(k)
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: invalid duration %q", k, s)
	}
	return d, nil
}
