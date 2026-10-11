//go:build integration
// +build integration

package google

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karust/openserp/core"
	"github.com/karust/openserp/testutil"
	"github.com/karust/openserp/testutil/ithelper"
)

// This regression test uses a local consent page; it never sends a Google search.
func TestGoogleCookieConsent(t *testing.T) {
	testutil.RequireIntegration(t)
	body, err := os.ReadFile("testdata/search_consent.html")
	if err != nil {
		t.Fatal(err)
	}
	b := ithelper.CreateBrowser(t)
	engine := New(*b, core.SearchEngineOptions{})
	for _, tc := range []struct {
		name string
		html string
	}{
		{"two buttons", string(body)},
		{"localized button", strings.ReplaceAll(string(body), "Accept all", "Alle akzeptieren")},
		{"text fallback", strings.ReplaceAll(string(body), `id="L2AGLb"`, `id="accept-consent"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(tc.html))
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			page, err := b.Navigate(ctx, srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer core.DeferClosePage(ctx, page, b)()
			if err := engine.classifyPage(page, ""); err != nil {
				t.Fatalf("consent page classified as a challenge: %v", err)
			}
			engine.acceptCookies(page)
			if has, _, err := page.Has("div[role='dialog'][aria-modal]"); err != nil || has {
				t.Fatalf("consent dialog still present: has=%v err=%v", has, err)
			}
			if err := engine.classifyPage(page, ""); err != nil {
				t.Fatalf("SERP classified as a challenge after consent: %v", err)
			}
		})
	}
}

func TestSearchGoogle(t *testing.T) {
	ithelper.RunEngineTests(t, func(b *core.Browser) core.SearchEngine {
		return New(*b, ithelper.EngineOptions())
	})
}
