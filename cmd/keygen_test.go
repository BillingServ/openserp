package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/karust/openserp/core"
)

func TestKeygenCommand(t *testing.T) {
	cmd := newKeygenCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"customer-a"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var result struct {
		APIKey string            `json:"api_key"`
		Config core.APIKeyConfig `json:"config"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(result.APIKey))
	if !strings.HasPrefix(result.APIKey, "os_") || result.Config.KeyHash != "sha256:"+hex.EncodeToString(digest[:]) || result.Config.ID != "customer-a" || result.Config.Tenant != "customer-a" {
		t.Fatal("generated credential does not match its config entry")
	}
	if result.Config.RateRequests != 0 || result.Config.RateBurst != 0 {
		t.Fatal("generated key should inherit configured request limits")
	}
}

func TestKeygenRejectsInvalidIdentity(t *testing.T) {
	cmd := newKeygenCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"invalid:tenant"})
	if err := cmd.Execute(); err == nil || strings.Contains(output.String(), "os_") {
		t.Fatal("invalid key identity was accepted or a credential was printed")
	}
}
