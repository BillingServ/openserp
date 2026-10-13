package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/karust/openserp/core"
)

func TestInitializeAuthConfigFromFileAndEnvironment(t *testing.T) {
	_, hash, err := core.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, useEnv := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "environment"}[useEnv], func(t *testing.T) {
			isolateConfig(t)
			t.Setenv("OPENSERP_AUTH_ENABLED", "")
			t.Setenv("OPENSERP_AUTH_KEYS", "")
			if useEnv {
				t.Setenv("OPENSERP_AUTH_ENABLED", "true")
				t.Setenv("OPENSERP_AUTH_KEYS", `[{"id":"customer-a","key_hash":"`+hash+`"}]`)
			} else {
				body := "auth:\n  enabled: true\n  keys:\n    - id: customer-a\n      key_hash: " + hash + "\n"
				if err := os.WriteFile("config.yaml", []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := configCommand(t, "")
			cmd.Use = "serve"
			if err := initializeConfig(cmd); err != nil {
				t.Fatal(err)
			}
			if !config.Auth.Enabled || len(config.Auth.Keys) != 1 || config.Auth.Keys[0].KeyHash != hash || config.Auth.Keys[0].Tenant != "customer-a" || config.Auth.Keys[0].RateRequests != 60 {
				t.Fatal("authentication settings were not loaded")
			}
			sanitized, _ := json.Marshal(sanitizedConfigForLog(config))
			if strings.Contains(string(sanitized), hash) || strings.Contains(string(sanitized), "key_hash") {
				t.Fatal("debug configuration leaks key hashes")
			}
			opts := buildServerOptions(core.DefaultCORSConfig(), core.DefaultProxyConfig(), core.BrowserOpts{})
			if !opts.Auth.Enabled || len(opts.Auth.Keys) != 1 {
				t.Fatal("serve did not pass authentication to the HTTP server")
			}
		})
	}
}

func TestServeRejectsEnabledAuthWithoutKeys(t *testing.T) {
	isolateConfig(t)
	t.Setenv("OPENSERP_AUTH_ENABLED", "true")
	t.Setenv("OPENSERP_AUTH_KEYS", "[]")
	cmd := configCommand(t, "")
	cmd.Use = "serve"
	if err := initializeConfig(cmd); err == nil || !strings.Contains(err.Error(), "requires at least one") {
		t.Fatalf("invalid auth config was not rejected before startup: %v", err)
	}
	// Key generation remains available before the first server key is configured.
	cmd.Use = "keygen"
	if err := initializeConfig(cmd); err != nil {
		t.Fatal(err)
	}
}
