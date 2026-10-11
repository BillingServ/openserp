package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	googleURLResolutionTimeout = 5 * time.Second
	googleURLResolutionWorkers = 3
	googleURLResolutionMaxHops = 3
)

type googleRedirectRequest func(context.Context, string, Query) (*http.Response, error)

// ResolveGoogleResultURLs replaces Google redirect wrappers in results and
// feature links with their destinations. It preserves ranks, order, and URLs
// that cannot be resolved within the request's remaining time budget.
func ResolveGoogleResultURLs(ctx context.Context, query Query, searchURL string, results []SearchResult) {
	resolveGoogleResultURLs(ctx, query, searchURL, results, rawGoogleRedirectRequest)
}

func resolveGoogleResultURLs(ctx context.Context, query Query, searchURL string, results []SearchResult, request googleRedirectRequest) {
	base, err := url.Parse(searchURL)
	if err != nil {
		return
	}
	type job struct {
		url     string
		targets []*string
	}
	var jobs []*job
	byURL := make(map[string]*job)
	add := func(target *string) {
		parsed, err := url.Parse(strings.TrimSpace(*target))
		if err != nil {
			return
		}
		absolute := base.ResolveReference(parsed).String()
		if !isGoogleResolutionURL(absolute) {
			return
		}
		if existing := byURL[absolute]; existing != nil {
			existing.targets = append(existing.targets, target)
			return
		}
		entry := &job{url: absolute, targets: []*string{target}}
		byURL[absolute] = entry
		jobs = append(jobs, entry)
	}
	// Prioritize result destinations before optional feature citations.
	for i := range results {
		add(&results[i].URL)
	}
	for i := range results {
		for f := range results[i].Features {
			feature := &results[i].Features[f]
			for l := range feature.Links {
				add(&feature.Links[l].URL)
			}
			for item := range feature.Items {
				add(&feature.Items[item].Link)
			}
		}
	}
	if len(jobs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(EnsureContext(ctx), googleURLResolutionTimeout)
	defer cancel()
	queue := make(chan *job)
	var workers sync.WaitGroup
	for i := 0; i < min(len(jobs), googleURLResolutionWorkers); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for entry := range queue {
				destination, err := resolveGoogleDestination(ctx, query, entry.url, request)
				if err != nil {
					WithRequest(ctx).WithError(err).Debug("Google result URL resolution skipped")
					continue
				}
				for _, target := range entry.targets {
					*target = destination
				}
			}
		}()
	}
dispatch:
	for _, entry := range jobs {
		select {
		case queue <- entry:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(queue)
	workers.Wait()
}

// Only Google wrapper URLs are fetched. The final destination is read from
// Location and returned without visiting it.
func resolveGoogleDestination(ctx context.Context, query Query, current string, request googleRedirectRequest) (string, error) {
	for hop := 0; hop < googleURLResolutionMaxHops; hop++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		parsed, err := url.Parse(current)
		if err != nil || !isGoogleResolutionURL(current) {
			return "", fmt.Errorf("invalid Google redirect URL")
		}
		// Older /url and ad wrappers carry a plaintext, URL-encoded destination.
		for _, key := range []string{"url", "q", "adurl"} {
			if destination := parsed.Query().Get(key); isGoogleDestinationURL(destination) {
				return destination, nil
			}
		}
		resp, err := request(ctx, current, query)
		if err != nil {
			return "", err
		}
		location, ok := redirectLocation(resp)
		if resp != nil && resp.Body != nil {
			// Redirect bodies are small; cap draining when Google returns a block
			// page or other unexpected response.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
			_ = resp.Body.Close()
		}
		if !ok {
			return "", fmt.Errorf("Google redirect returned no destination")
		}
		next, err := resolveRedirectURL(current, location)
		if err != nil {
			return "", err
		}
		if isGoogleDestinationURL(next) {
			return next, nil
		}
		current = next
	}
	return "", fmt.Errorf("Google redirect exceeded %d hops", googleURLResolutionMaxHops)
}

func isGoogleResolutionURL(raw string) bool {
	u, err := validateHTTPURL(raw)
	return err == nil && u.User == nil && u.Port() == "" && isGoogleRedirectURL(u)
}

func isGoogleDestinationURL(raw string) bool {
	u, err := validateHTTPURL(raw)
	if err != nil || u.User != nil || isGoogleRedirectURL(u) {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	path := strings.ToLower(u.Path)
	if strings.HasPrefix(host, "consent.") && isGoogleHost(strings.TrimPrefix(host, "consent.")) {
		return false
	}
	return !isGoogleHost(host) || (path != "/search" && !strings.HasPrefix(path, "/sorry"))
}

func rawGoogleRedirectRequest(ctx context.Context, rawURL string, query Query) (*http.Response, error) {
	if query.GuardPrivateNetworks {
		if err := ValidatePublicHTTPURL(ctx, rawURL); err != nil {
			return nil, err
		}
	}
	profile := rawRequestProfileFor(ctx, query)
	client, err := cachedRawHTTPClient(query, profile.cacheKey(), profile.tlsProfile)
	if err != nil {
		return nil, err
	}
	// The pooled TLS client does not follow redirects. Calling doRawRequest
	// directly also avoids the guarded search path following the destination.
	return doRawRequest(ctx, client, rawURL, profile, query)
}
