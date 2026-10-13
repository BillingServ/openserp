package google

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/karust/openserp/core"
)

func paginationResults(first, count int) []core.SearchResult {
	results := make([]core.SearchResult, count)
	for i := range results {
		results[i] = core.SearchResult{
			URL:   fmt.Sprintf("https://example.com/%d", first+i),
			Title: fmt.Sprintf("Result %d", first+i),
			Rank:  first + i,
		}
	}
	return results
}

func TestCollectGoogleSearchPagesFillsShortPageAndDeduplicates(t *testing.T) {
	query := core.Query{Text: "test query", Limit: 11, Features: true, Region: "US", ProxyURL: "http://proxy.example:3128"}
	first := paginationResults(1, 9)
	first = append(first,
		core.SearchResult{URL: first[0].URL, Title: "Ad", Ad: true},
		core.SearchResult{URL: "https://answers.example.com/", Title: "Question", Rank: -1, Type: core.ResultTypePeopleAlsoAsk},
	)
	second := append([]core.SearchResult{first[8]}, paginationResults(10, 3)...)
	var requests []core.Query
	results, err := collectGoogleSearchPages(context.Background(), query, func(_ context.Context, q core.Query) (googleSearchPage, error) {
		requests = append(requests, q)
		switch q.Start {
		case 0:
			return googleSearchPage{results: first, nextStart: 10}, nil
		case 10:
			return googleSearchPage{results: second, nextStart: 20}, nil
		default:
			t.Fatalf("unexpected extra page at start=%d", q.Start)
			return googleSearchPage{}, nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0].Limit != 10 || requests[1].Limit != 10 {
		t.Fatalf("unexpected page requests: %+v", requests)
	}
	if !requests[0].Features || requests[1].Features {
		t.Fatalf("features should only be requested on the first page: %+v", requests)
	}
	for _, request := range requests {
		if request.ProxyURL != query.ProxyURL || request.Region != query.Region || request.Text != query.Text {
			t.Fatalf("pagination lost query options: %+v", request)
		}
	}
	organic := 0
	ads := 0
	questions := 0
	for _, result := range results {
		switch {
		case result.Ad:
			ads++
		case result.Type == core.ResultTypePeopleAlsoAsk:
			questions++
			if result.Rank != -1 {
				t.Fatalf("feature rank changed: %+v", result)
			}
		default:
			organic++
			if result.Rank != organic || result.URL != fmt.Sprintf("https://example.com/%d", organic) {
				t.Fatalf("duplicate or incorrect rank: %+v", result)
			}
		}
	}
	if organic != 11 || ads != 1 || questions != 1 {
		t.Fatalf("want 11 organic results plus ad and question, got organic=%d ads=%d questions=%d", organic, ads, questions)
	}
}

func TestCollectGoogleSearchPagesReaches100AcrossShortPages(t *testing.T) {
	var starts []int
	results, err := collectGoogleSearchPages(context.Background(), core.Query{Limit: 100}, func(_ context.Context, q core.Query) (googleSearchPage, error) {
		starts = append(starts, q.Start)
		return googleSearchPage{results: paginationResults(len(starts)*9-8, 9), nextStart: q.Start + 10}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 100 || len(starts) != 12 || results[99].Rank != 100 {
		t.Fatalf("want 100 results from 12 short pages, got results=%d starts=%v", len(results), starts)
	}
}

func TestCollectGoogleSearchPagesFillsTenFromEightResults(t *testing.T) {
	var starts []int
	results, err := collectGoogleSearchPages(context.Background(), core.Query{Limit: 10}, func(_ context.Context, q core.Query) (googleSearchPage, error) {
		starts = append(starts, q.Start)
		switch q.Start {
		case 0:
			return googleSearchPage{results: paginationResults(1, 8), nextStart: 10}, nil
		case 10:
			return googleSearchPage{results: paginationResults(9, 10), nextStart: 20}, nil
		default:
			t.Fatalf("unnecessary page fetched at start=%d", q.Start)
			return googleSearchPage{}, nil
		}
	})
	if err != nil || len(results) != 10 || len(starts) != 2 {
		t.Fatalf("want ten results from two pages, got results=%d starts=%v err=%v", len(results), starts, err)
	}
	for i, result := range results {
		if result.Rank != i+1 || result.URL != fmt.Sprintf("https://example.com/%d", i+1) {
			t.Fatalf("unexpected result at %d: %+v", i, result)
		}
	}
}

func TestCollectGoogleSearchPagesStopsWhenExhausted(t *testing.T) {
	for _, limit := range []int{0, 10, 100} {
		t.Run(fmt.Sprintf("limit_%d", limit), func(t *testing.T) {
			calls := 0
			results, err := collectGoogleSearchPages(context.Background(), core.Query{Limit: limit}, func(_ context.Context, q core.Query) (googleSearchPage, error) {
				calls++
				if calls == 1 {
					return googleSearchPage{results: paginationResults(1, 9), nextStart: 10}, nil
				}
				// Google may ignore an offset and return the previous page.
				return googleSearchPage{results: paginationResults(1, 9), nextStart: 20}, nil
			})
			wantCalls := 1
			if limit > 0 {
				wantCalls = 2
			}
			if err != nil || len(results) != 9 || calls != wantCalls {
				t.Fatalf("unexpected exhaustion behavior: calls=%d results=%d err=%v", calls, len(results), err)
			}
		})
	}
	for _, nextStart := range []int{0, 20} {
		calls := 0
		results, err := collectGoogleSearchPages(context.Background(), core.Query{Limit: 100, Start: 20}, func(_ context.Context, q core.Query) (googleSearchPage, error) {
			calls++
			return googleSearchPage{results: paginationResults(1, 4), nextStart: nextStart}, nil
		})
		if err != nil || calls != 1 || len(results) != 4 || results[0].Rank != 21 {
			t.Fatalf("missing/backwards next page should stop and preserve offset: results=%+v calls=%d err=%v", results, calls, err)
		}
	}
}

func TestCollectGoogleSearchPagesReturnsPartialResultsAndError(t *testing.T) {
	for _, pageErr := range []error{core.ErrCaptcha, core.ErrProxyConnect, context.DeadlineExceeded} {
		calls := 0
		results, err := collectGoogleSearchPages(context.Background(), core.Query{Limit: 100}, func(_ context.Context, q core.Query) (googleSearchPage, error) {
			calls++
			if calls == 1 {
				return googleSearchPage{results: paginationResults(1, 9), nextStart: 10}, nil
			}
			return googleSearchPage{}, pageErr
		})
		if !errors.Is(err, pageErr) || len(results) != 9 {
			t.Fatalf("lost partial results or error: results=%d err=%v", len(results), err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := collectGoogleSearchPages(ctx, core.Query{Limit: 100}, func(context.Context, core.Query) (googleSearchPage, error) {
		t.Fatal("cancelled request must not fetch a page")
		return googleSearchPage{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancellation, got %v", err)
	}
}

func TestCollectGoogleSearchPagesCapsPageRequests(t *testing.T) {
	calls := 0
	_, err := collectGoogleSearchPages(context.Background(), core.Query{Limit: 100}, func(_ context.Context, q core.Query) (googleSearchPage, error) {
		calls++
		return googleSearchPage{results: paginationResults(calls, 1), nextStart: q.Start + 10}, nil
	})
	if err != nil || calls != maxGoogleSearchPages {
		t.Fatalf("page cap not enforced: calls=%d err=%v", calls, err)
	}
}

func TestGoogleNextSearchStart(t *testing.T) {
	for _, tc := range []struct {
		href    string
		current int
		want    int
		ok      bool
	}{
		{"/search?q=test&start=10", 0, 10, true},
		{"https://www.google.co.uk/search?q=test&start=30", 20, 30, true},
		{"/search?q=test&start=%32%30", 10, 20, true},
		{"/search?q=test", 0, 0, false},
		{"/search?start=10", 10, 0, false},
		{"/search?start=0", 10, 0, false},
		{"/search?start=-10", 0, 0, false},
		{"/search?start=garbage", 0, 0, false},
		{"%broken", 0, 0, false},
	} {
		got, ok := googleNextSearchStart(tc.href, tc.current)
		if got != tc.want || ok != tc.ok {
			t.Errorf("googleNextSearchStart(%q, %d) = (%d, %t), want (%d, %t)", tc.href, tc.current, got, ok, tc.want, tc.ok)
		}
	}
}
