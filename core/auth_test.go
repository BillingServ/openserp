package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

const authTestKeyA = "os_test-customer-a"
const authTestKeyB = "os_test-customer-b"

func authTestHash(key string) string {
	digest := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func authTestConfig() AuthConfig {
	return AuthConfig{Enabled: true, Keys: []APIKeyConfig{
		{ID: "key-a", Tenant: "customer-a", KeyHash: authTestHash(authTestKeyA)},
		{ID: "key-b", Tenant: "customer-b", KeyHash: authTestHash(authTestKeyB)},
	}}
}

func TestGenerateAPIKey(t *testing.T) {
	key, hash, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "os_") || len(key) != 46 || hash != authTestHash(key) {
		t.Fatal("invalid generated key or hash")
	}
	other, _, err := GenerateAPIKey()
	if err != nil || key == other {
		t.Fatal("API keys are not independently generated")
	}
}

func TestNormalizeAuthConfigRejectsInvalidEnabledConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*AuthConfig)
	}{
		{"no keys", func(c *AuthConfig) { c.Keys = nil }},
		{"empty id", func(c *AuthConfig) { c.Keys[0].ID = "" }},
		{"unsafe tenant", func(c *AuthConfig) { c.Keys[0].Tenant = "customer:other" }},
		{"bad hash", func(c *AuthConfig) { c.Keys[0].KeyHash = authTestKeyA }},
		{"duplicate id", func(c *AuthConfig) { c.Keys[1].ID = c.Keys[0].ID }},
		{"duplicate hash", func(c *AuthConfig) { c.Keys[1].KeyHash = c.Keys[0].KeyHash }},
		{"negative rate", func(c *AuthConfig) { c.RateRequests = -1 }},
		{"negative burst", func(c *AuthConfig) { c.RateBurst = -1 }},
		{"negative key rate", func(c *AuthConfig) { c.Keys[0].RateRequests = -1 }},
		{"negative key burst", func(c *AuthConfig) { c.Keys[0].RateBurst = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := authTestConfig()
			tc.edit(&cfg)
			_, err := NormalizeAuthConfig(cfg)
			if err == nil || strings.Contains(err.Error(), authTestKeyA) || strings.Contains(err.Error(), authTestHash(authTestKeyA)) {
				t.Fatalf("validation did not reject safely: %v", err)
			}
		})
	}
	if _, err := NormalizeAuthConfig(AuthConfig{}); err != nil {
		t.Fatal("default local mode should remain unauthenticated")
	}
}

func TestNormalizeAuthConfigInheritsLimitsAndTenant(t *testing.T) {
	cfg := authTestConfig()
	cfg.RateRequests, cfg.RateBurst = 60, 3
	cfg.Keys[0].Tenant = ""
	cfg.Keys[1].RateRequests, cfg.Keys[1].RateBurst = 5, 1
	got, err := NormalizeAuthConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.Keys[0].Tenant != "key-a" || got.Keys[0].RateRequests != 60 || got.Keys[0].RateBurst != 3 || got.Keys[1].RateRequests != 5 || got.Keys[1].RateBurst != 1 {
		t.Fatalf("incorrect inherited config: %+v", got)
	}
	if cfg.Keys[0].Tenant != "" {
		t.Fatal("normalization mutated the caller's key entries")
	}
}

func TestAPIKeyMiddlewareAuthenticationAndTrustedTenant(t *testing.T) {
	middleware, err := APIKeyMiddleware(authTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{ErrorHandler: JSONErrorMiddleware()})
	app.Use(RequestContextMiddleware(), middleware)
	app.Get("/search", func(c *fiber.Ctx) error {
		return c.JSON(WithRequest(c.UserContext()).Data)
	})
	for _, tc := range []struct {
		name, authorization string
		status              int
	}{
		{"missing", "", 401},
		{"unknown", "Bearer unknown-secret", 401},
		{"wrong scheme", "Basic " + authTestKeyA, 401},
		{"empty bearer", "Bearer ", 401},
		{"extra fields", "Bearer " + authTestKeyA + " extra", 401},
		{"valid", "Bearer " + authTestKeyA, 200},
		{"case insensitive scheme", "bearer " + authTestKeyA, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/search?api_key="+authTestKeyA, nil)
			req.Header.Set("Authorization", tc.authorization)
			req.Header.Set("X-Tenant", "customer-b")
			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d body=%s", resp.StatusCode, body)
			}
			if strings.Contains(string(body), authTestKeyA) || strings.Contains(string(body), authTestHash(authTestKeyA)) {
				t.Fatal("response leaked a credential")
			}
			if tc.status == 200 {
				var fields map[string]interface{}
				if err := json.Unmarshal(body, &fields); err != nil {
					t.Fatal(err)
				}
				if fields["tenant"] != "customer-a" || fields["api_key_id"] != "key-a" {
					t.Fatalf("caller spoofed the tenant: %s", body)
				}
			} else if resp.Header.Get("WWW-Authenticate") != `Bearer realm="openserp"` || resp.Header.Get("X-Request-ID") == "" {
				t.Fatal("unauthorized response lacks authentication or request metadata")
			}
		})
	}
}

func TestServerAPIKeysProtectRoutesAndKeepHealthDocsPublic(t *testing.T) {
	opts := DefaultServerOptions()
	opts.Auth = authTestConfig()
	opts.EnableDebugEndpoints = true
	srv := NewServerWithOptions("127.0.0.1", 7000, opts, &engineMock{name: "google", initialized: true})
	for _, path := range []string{"/google/search?text=test", "/google/image?text=test", "/mega/search?text=test", "/mega/image?text=test", "/mega/engines", "/extract?url=https://example.com", "/stats", "/stats/cache", "/stats/proxy", "/stats/cb", "/debug/fingerprint-check"} {
		resp := request(t, srv, path)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("unprotected route %s: %d", path, resp.StatusCode)
		}
	}
	for _, path := range []string{"/google/parse", "/extract", "/extract/batch"} {
		resp, err := srv.app.Test(httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")), -1)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("unprotected POST %s: %d", path, resp.StatusCode)
		}
	}
	for _, path := range []string{"/health", "/ready", "/docs", "/docs/", "/openapi.yaml"} {
		resp := request(t, srv, path)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("public route %s requires a key: %d", path, resp.StatusCode)
		}
	}
	preflight, err := srv.app.Test(httptest.NewRequest(http.MethodOptions, "/google/search", nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	preflight.Body.Close()
	if preflight.StatusCode != 204 {
		t.Fatal("CORS preflight requires authentication")
	}
}

func TestServerAPIKeyLimitsApplyToCacheHitsAndArePerKey(t *testing.T) {
	opts := DefaultServerOptions()
	opts.Auth = authTestConfig()
	opts.Auth.RateRequests, opts.Auth.RateBurst = 1, 1
	srv := NewServerWithOptions("127.0.0.1", 7000, opts, &engineMock{name: "google", initialized: true})
	for _, key := range []string{authTestKeyA, authTestKeyB} {
		first := requestWithHeader(t, srv, "/google/search?text=test", "Authorization", "Bearer "+key)
		first.Body.Close()
		if first.StatusCode != 200 {
			t.Fatalf("one user's limit exhausted another's: %d", first.StatusCode)
		}
		second := requestWithHeader(t, srv, "/google/search?text=test", "Authorization", "Bearer "+key)
		body, _ := io.ReadAll(second.Body)
		second.Body.Close()
		if second.StatusCode != 429 || second.Header.Get("Retry-After") == "" || !strings.Contains(string(body), "API_KEY_RATE_LIMIT") {
			t.Fatalf("limit bypassed on cache hit: status=%d body=%s", second.StatusCode, body)
		}
	}
}

func TestServerAuthenticatedCachesAreTenantScoped(t *testing.T) {
	opts := DefaultServerOptions()
	opts.Auth = authTestConfig()
	engine := &engineMock{name: "google", initialized: true, searchFn: func(ctx context.Context, q Query) ([]SearchResult, error) {
		return []SearchResult{{Rank: 1, URL: "https://example.com/" + TenantFromContext(ctx), Title: "result"}}, nil
	}}
	srv := NewServerWithOptions("127.0.0.1", 7000, opts, engine)
	for i, key := range []string{authTestKeyA, authTestKeyB, authTestKeyA} {
		resp := requestWithHeader(t, srv, "/google/search?text=test", "Authorization", "Bearer "+key)
		var env Envelope
		err := json.NewDecoder(resp.Body).Decode(&env)
		resp.Body.Close()
		if err != nil || len(env.Results) != 1 {
			t.Fatalf("invalid response: %v", err)
		}
		wantTenant, wantCache := "customer-a", "MISS"
		if key == authTestKeyB {
			wantTenant = "customer-b"
		}
		if i == 2 {
			wantCache = "HIT"
		}
		if env.Results[0].URL != "https://example.com/"+wantTenant || resp.Header.Get("X-Cache") != wantCache {
			t.Fatalf("cache crossed tenant boundary: result=%q cache=%q", env.Results[0].URL, resp.Header.Get("X-Cache"))
		}
	}
}

func TestServerAuthDisabledAndInvalidConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		auth   AuthConfig
		status int
	}{
		{"local default", AuthConfig{}, 200},
		{"enabled without keys", AuthConfig{Enabled: true}, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := DefaultServerOptions()
			opts.Auth = tc.auth
			srv := NewServerWithOptions("127.0.0.1", 7000, opts, &engineMock{name: "google", initialized: true})
			resp := request(t, srv, "/google/search?text=test")
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}
