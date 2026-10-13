package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/time/rate"
)

// AuthConfig enables bearer API keys for the HTTP server. Rates are requests
// per minute per key; zero disables the default per-key limit.
type AuthConfig struct {
	Enabled      bool           `mapstructure:"enabled"`
	RateRequests int            `mapstructure:"rate_requests"`
	RateBurst    int            `mapstructure:"rate_burst"`
	Keys         []APIKeyConfig `mapstructure:"keys"`
}

type APIKeyConfig struct {
	ID           string `json:"id" mapstructure:"id"`
	Tenant       string `json:"tenant" mapstructure:"tenant"`
	KeyHash      string `json:"key_hash" mapstructure:"key_hash"`
	RateRequests int    `json:"rate_requests,omitempty" mapstructure:"rate_requests"`
	RateBurst    int    `json:"rate_burst,omitempty" mapstructure:"rate_burst"`
}

var apiKeyIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func DefaultAuthConfig() AuthConfig {
	return AuthConfig{RateRequests: 60, RateBurst: 3}
}

// GenerateAPIKey returns a random 256-bit bearer key and its SHA-256 hash.
// Only the hash needs to be retained by the server.
func GenerateAPIKey() (key, hash string, err error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", "", err
	}
	key = "os_" + base64.RawURLEncoding.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(key))
	return key, "sha256:" + hex.EncodeToString(digest[:]), nil
}

// NormalizeAuthConfig validates configured keys without retaining plaintext.
func NormalizeAuthConfig(cfg AuthConfig) (AuthConfig, error) {
	if !cfg.Enabled {
		return cfg, nil
	}
	if len(cfg.Keys) == 0 {
		return cfg, fmt.Errorf("auth.enabled requires at least one auth.keys entry")
	}
	if cfg.RateRequests < 0 || cfg.RateBurst < 0 {
		return cfg, fmt.Errorf("auth rate_requests and rate_burst must be non-negative")
	}
	cfg.Keys = append([]APIKeyConfig(nil), cfg.Keys...)
	ids := make(map[string]bool)
	hashes := make(map[string]bool)
	for i := range cfg.Keys {
		key := &cfg.Keys[i]
		key.ID = strings.TrimSpace(key.ID)
		key.Tenant = strings.TrimSpace(key.Tenant)
		if key.Tenant == "" {
			key.Tenant = key.ID
		}
		if !apiKeyIdentityPattern.MatchString(key.ID) || !apiKeyIdentityPattern.MatchString(key.Tenant) {
			return cfg, fmt.Errorf("auth.keys[%d]: id and tenant must be 1-128 letters, digits, dots, underscores or hyphens", i)
		}
		key.KeyHash = strings.ToLower(strings.TrimSpace(key.KeyHash))
		digest, err := hex.DecodeString(strings.TrimPrefix(key.KeyHash, "sha256:"))
		if err != nil || len(digest) != sha256.Size {
			return cfg, fmt.Errorf("auth.keys[%d]: key_hash must be a SHA-256 hash from openserp keygen", i)
		}
		key.KeyHash = "sha256:" + hex.EncodeToString(digest)
		if ids[key.ID] || hashes[key.KeyHash] {
			return cfg, fmt.Errorf("auth.keys[%d]: duplicate key id or hash", i)
		}
		ids[key.ID], hashes[key.KeyHash] = true, true
		if key.RateRequests < 0 || key.RateBurst < 0 {
			return cfg, fmt.Errorf("auth.keys[%d]: rate_requests and rate_burst must be non-negative", i)
		}
		if key.RateRequests == 0 {
			key.RateRequests = cfg.RateRequests
		}
		if key.RateBurst == 0 {
			key.RateBurst = max(cfg.RateBurst, 1)
		}
	}
	return cfg, nil
}

// APIKeyMiddleware validates Authorization: Bearer and derives the trusted
// tenant from the configured key. Health and documentation GETs stay public.
func APIKeyMiddleware(cfg AuthConfig) (fiber.Handler, error) {
	cfg, err := NormalizeAuthConfig(cfg)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return func(c *fiber.Ctx) error { return c.Next() }, nil
	}
	type identity struct {
		id, tenant string
		limiter    *rate.Limiter
	}
	keys := make(map[[sha256.Size]byte]identity, len(cfg.Keys))
	for _, key := range cfg.Keys {
		decoded, _ := hex.DecodeString(strings.TrimPrefix(key.KeyHash, "sha256:"))
		var digest [sha256.Size]byte
		copy(digest[:], decoded)
		entry := identity{id: key.ID, tenant: key.Tenant}
		if key.RateRequests > 0 {
			entry.limiter = rate.NewLimiter(rate.Limit(key.RateRequests)/60, key.RateBurst)
		}
		keys[digest] = entry
	}
	return func(c *fiber.Ctx) error {
		if publicAuthEndpoint(c.Method(), c.Path()) {
			return c.Next()
		}
		parts := strings.Fields(c.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 512 {
			return apiKeyUnauthorized(c)
		}
		entry, ok := keys[sha256.Sum256([]byte(parts[1]))]
		if !ok {
			return apiKeyUnauthorized(c)
		}
		ctx := WithTenant(c.UserContext(), entry.tenant)
		ctx = context.WithValue(ctx, apiKeyIDContextKey, entry.id)
		c.SetUserContext(ctx)
		c.Request().Header.Set("X-Tenant", entry.tenant)
		if entry.limiter != nil && !entry.limiter.Allow() {
			seconds := max(1, int(math.Ceil((1-entry.limiter.Tokens())/float64(entry.limiter.Limit()))))
			c.Set("Retry-After", strconv.Itoa(seconds))
			return &APIError{HTTPStatus: fiber.StatusTooManyRequests, ErrorCode: "rate_limited", Reason: "API_KEY_RATE_LIMIT", Message: "API key request limit exceeded"}
		}
		return c.Next()
	}, nil
}

func publicAuthEndpoint(method, path string) bool {
	if method != fiber.MethodGet && method != fiber.MethodHead {
		return false
	}
	switch path {
	case "/health", "/ready", "/docs", "/docs/", "/openapi.yaml":
		return true
	}
	return false
}

func apiKeyUnauthorized(c *fiber.Ctx) error {
	c.Set("WWW-Authenticate", `Bearer realm="openserp"`)
	return &APIError{HTTPStatus: fiber.StatusUnauthorized, ErrorCode: "unauthorized", Message: "valid bearer API key required"}
}
