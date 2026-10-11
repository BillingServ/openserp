package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestResolveGoogleDestination(t *testing.T) {
	const wrapped = "https://www.google.com/goto?url=opaque-token"
	const destination = "https://example.com/billing?plan=hosting&currency=GBP"
	for _, tc := range []struct {
		name       string
		url        string
		status     int
		location   string
		requestErr error
		want       string
		wantCalls  int
	}{
		{"opaque token", wrapped, 302, destination, nil, destination, 1},
		{"plaintext q", "https://www.google.com/url?q=https%3A%2F%2Fexample.com%2Fbilling%3Fplan%3Dhosting%26currency%3DGBP", 0, "", nil, destination, 0},
		{"plaintext adurl", "https://www.googleadservices.com/pagead/aclk?adurl=https%3A%2F%2Fexample.com%2F", 0, "", nil, "https://example.com/", 0},
		{"plaintext url", "https://www.google.com/url?url=https%3A%2F%2Fexample.com%2F", 0, "", nil, "https://example.com/", 0},
		{"relative wrapper hop", wrapped, 302, "/url?q=https%3A%2F%2Fexample.com%2F", nil, "https://example.com/", 1},
		{"protocol relative destination", wrapped, 301, "//example.com/billing", nil, "https://example.com/billing", 1},
		{"blocked", wrapped, 403, "", nil, "", 1},
		{"rate limited", wrapped, 429, "", nil, "", 1},
		{"missing location", wrapped, 302, "", nil, "", 1},
		{"non redirect", wrapped, 200, destination, nil, "", 1},
		{"unsafe scheme", wrapped, 302, "javascript:alert(1)", nil, "", 1},
		{"credentials in destination", wrapped, 302, "https://user:pass@example.com/", nil, "", 1},
		{"malformed destination", wrapped, 302, "https://example.com/%ZZ", nil, "", 1},
		{"captcha redirect", wrapped, 302, "https://www.google.com/sorry/index", nil, "", 1},
		{"consent redirect", wrapped, 302, "https://consent.google.com/m", nil, "", 1},
		{"search redirect", wrapped, 302, "/search?q=retry", nil, "", 1},
		{"redirect loop", wrapped, 302, wrapped, nil, "", googleURLResolutionMaxHops},
		{"network failure", wrapped, 0, "", errors.New("connection failed"), "", 1},
		{"non Google host", "https://google.example.org/goto?url=token", 0, "", nil, "", 0},
		{"custom port", "https://www.google.com:8080/goto?url=token", 0, "", nil, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var bodies []*trackingBody
			request := func(ctx context.Context, raw string, query Query) (*http.Response, error) {
				calls++
				if !isGoogleResolutionURL(raw) {
					t.Errorf("requested a destination rather than a Google wrapper: %s", raw)
				}
				if tc.requestErr != nil {
					return nil, tc.requestErr
				}
				body := &trackingBody{Reader: strings.NewReader("redirect")}
				bodies = append(bodies, body)
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Location": {tc.location}}, Body: body}, nil
			}
			got, err := resolveGoogleDestination(context.Background(), Query{}, tc.url, request)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("destination=%q err=%v, want %q", got, err, tc.want)
			}
			if calls != tc.wantCalls {
				t.Fatalf("requests=%d, want %d", calls, tc.wantCalls)
			}
			for _, body := range bodies {
				if !body.closed {
					t.Error("redirect response body was not closed")
				}
			}
		})
	}
}

func TestResolveGoogleResultURLsPreservesRankingAndResolvesFeatures(t *testing.T) {
	query := Query{ProxyURL: "http://proxy.example:8080", ProxySessionID: "session", LangCode: "en-GB", Insecure: true}
	results := []SearchResult{
		{Rank: 11, AbsoluteRank: 12, Title: "Hosting", URL: "/goto?url=token", DisplayURL: "example.com › billing", Features: []SerpFeature{{
			Links: []FeatureLink{{URL: "https://www.google.co.uk/goto?url=token"}},
			Items: []FeatureItem{{Link: "/goto?url=token"}},
		}}},
		{Rank: 12, AbsoluteRank: 13, Title: "Direct", URL: "https://direct.example/"},
		{Rank: 1, AbsoluteRank: 11, Title: "Ad", Ad: true, URL: "/goto?url=token"},
		{Rank: 13, AbsoluteRank: 14, Title: "Broken", URL: "/goto?url=broken"},
	}
	var mu sync.Mutex
	calls := make(map[string]int)
	request := func(ctx context.Context, raw string, gotQuery Query) (*http.Response, error) {
		if !reflect.DeepEqual(gotQuery, query) {
			t.Error("proxy/session/locale/TLS settings changed during resolution")
		}
		mu.Lock()
		calls[raw]++
		mu.Unlock()
		if strings.Contains(raw, "broken") {
			return nil, errors.New("blocked")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://example.com/billing"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	resolveGoogleResultURLs(context.Background(), query, "https://www.google.co.uk/search?q=hosting", results, request)
	if len(calls) != 2 || calls["https://www.google.co.uk/goto?url=token"] != 1 {
		t.Fatalf("duplicate wrapper was not resolved once: %v", calls)
	}
	wantURLs := []string{"https://example.com/billing", "https://direct.example/", "https://example.com/billing", "/goto?url=broken"}
	for i, result := range results {
		if result.URL != wantURLs[i] {
			t.Errorf("result %d URL=%q, want %q", i, result.URL, wantURLs[i])
		}
	}
	if results[0].Rank != 11 || results[0].AbsoluteRank != 12 || results[1].Rank != 12 || results[2].Rank != 1 || !results[2].Ad {
		t.Fatal("result ordering or ranking changed")
	}
	feature := results[0].Features[0]
	if feature.Links[0].URL != wantURLs[0] || feature.Items[0].Link != wantURLs[0] {
		t.Fatal("feature links still carry Google wrappers")
	}
	output := EnrichResult(results[0], EnrichContext{Engine: "google"})
	if output.URL != wantURLs[0] || output.Domain != "example.com" || output.Rank != 11 || output.Position.Absolute != 12 {
		t.Fatalf("incorrect enriched output: %+v", output)
	}
}

func TestResolveGoogleResultURLsCancellationAndConcurrency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var active, peak atomic.Int32
	started := make(chan struct{}, googleURLResolutionWorkers)
	results := make([]SearchResult, googleURLResolutionWorkers+2)
	for i := range results {
		results[i] = SearchResult{Rank: i + 1, URL: "https://www.google.com/goto?url=" + strings.Repeat("x", i+1)}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		resolveGoogleResultURLs(ctx, Query{}, "https://www.google.com/search", results, func(ctx context.Context, raw string, query Query) (*http.Response, error) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	for i := 0; i < googleURLResolutionWorkers; i++ {
		<-started
	}
	cancel()
	<-done
	if peak.Load() != googleURLResolutionWorkers || active.Load() != 0 {
		t.Fatalf("unbounded or unfinished requests: peak=%d active=%d", peak.Load(), active.Load())
	}
	for i, result := range results {
		if result.Rank != i+1 || !IsWrappedGoogleURL(result.URL) {
			t.Fatal("cancellation discarded or modified a result")
		}
	}
}

func TestResolveGoogleResultURLsUsesConfiguredProxyWithoutFollowingDestination(t *testing.T) {
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		// tls-client tunnels HTTP requests through CONNECT too.
		if r.Method != http.MethodConnect || r.Host != "www.google.com:80" {
			t.Errorf("unexpected proxy request: %s %s", r.Method, r.Host)
		}
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(buffered, "HTTP/1.1 200 Connection established\r\n\r\n")
		if err := buffered.Flush(); err != nil {
			t.Error(err)
			return
		}
		upstream, err := http.ReadRequest(buffered.Reader)
		if err != nil {
			t.Error(err)
			return
		}
		defer upstream.Body.Close()
		if upstream.Method != http.MethodGet || upstream.Host != "www.google.com" || upstream.URL.RequestURI() != "/goto?url=token" {
			t.Errorf("unexpected upstream request: %s %s %s", upstream.Method, upstream.Host, upstream.URL)
		}
		resp := &http.Response{
			StatusCode: http.StatusFound,
			ProtoMajor: 1, ProtoMinor: 1,
			Header:        http.Header{"Location": {"https://example.com/billing"}},
			Body:          io.NopCloser(strings.NewReader("redirect")),
			ContentLength: int64(len("redirect")),
		}
		if err := resp.Write(conn); err != nil {
			t.Error(err)
		}
	}))
	defer proxy.Close()
	results := []SearchResult{{Rank: 1, URL: "http://www.google.com/goto?url=token"}}
	ctx := WithEngine(WithNetworkUsage(context.Background()), "google")
	ResolveGoogleResultURLs(ctx, Query{ProxyURL: proxy.URL}, "https://www.google.com/search", results)
	if results[0].URL != "https://example.com/billing" || requests.Load() != 1 {
		t.Fatalf("proxy was bypassed or destination fetched: result=%q requests=%d", results[0].URL, requests.Load())
	}
	if NetworkBytesFromContext(ctx) != int64(len("redirect")) {
		t.Fatal("redirect traffic was not counted")
	}
}
