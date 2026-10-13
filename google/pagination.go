package google

import (
	"context"
	"net/url"
	"strconv"

	"github.com/karust/openserp/core"
)

const maxGoogleSearchPages = 20

type googleSearchPage struct {
	results   []core.SearchResult
	nextStart int
}

type googleSearchPageFetcher func(context.Context, core.Query) (googleSearchPage, error)

// collectGoogleSearchPages follows Google's actual page offsets, since a page
// can contain fewer than ten organic results or ignore the num parameter.
func collectGoogleSearchPages(ctx context.Context, query core.Query, fetch googleSearchPageFetcher) ([]core.SearchResult, error) {
	results := []core.SearchResult{}
	seen := map[string]bool{}
	rank := core.NewRankStateAt(query.Start, query.Start+1)
	organicCount := 0
	pageQuery := query
	if query.Limit > 10 {
		pageQuery.Limit = 10
	}

	for pageIndex := 0; pageIndex < maxGoogleSearchPages; pageIndex++ {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		page, err := fetch(ctx, pageQuery)
		if err != nil {
			return results, err
		}

		before := organicCount
		for _, result := range page.results {
			kind := "organic"
			organic := isGoogleOrganicResult(result)
			if result.Ad {
				kind = "ad"
			} else if !organic {
				kind = "feature:" + string(result.Type)
			}
			key := kind + "\x00" + result.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			if organic && query.Limit > 0 && organicCount >= query.Limit {
				continue
			}
			if organic || result.Ad {
				result.Rank, result.AbsoluteRank = rank.Next(result.Ad)
			}
			results = append(results, result)
			if organic {
				organicCount++
			}
		}

		// Every positive web-search limit is a target count, including the
		// default ten when Google's first page only contains eight or nine.
		if query.Limit <= 0 || organicCount >= query.Limit ||
			organicCount == before || page.nextStart <= pageQuery.Start {
			break
		}
		pageQuery.Start = page.nextStart
		// SERP features belong to the first requested page. Later pages only
		// contribute additional organic results and ads.
		pageQuery.Features = false
	}
	return results, nil
}

func isGoogleOrganicResult(result core.SearchResult) bool {
	return !result.Ad && result.Rank >= 0 &&
		(result.Type == "" || result.Type == core.ResultTypeOrganic)
}

func googleNextSearchStart(href string, currentStart int) (int, bool) {
	parsed, err := url.Parse(href)
	if err != nil {
		return 0, false
	}
	nextStart, err := strconv.Atoi(parsed.Query().Get("start"))
	if err != nil || nextStart <= currentStart {
		return 0, false
	}
	return nextStart, true
}
