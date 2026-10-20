// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Listed is a release a release source lists: its version and whether it is a pre-release.
type Listed struct {
	Version    string
	Prerelease bool
}

// A Lister lists the releases of the release source, newest first.
type Lister interface {
	List(ctx context.Context) ([]Listed, error)
}

// RateLimitedError means the release source refused a request for its rate limit; Until is when
// it accepts requests again.
type RateLimitedError struct{ Until time.Time }

func (e *RateLimitedError) Error() string {
	return "release: the release source is rate-limited until " + e.Until.UTC().Format(time.RFC3339)
}

// maxList bounds the answer of a release listing.
const maxList = 4 << 20

// GitHubReleases lists the releases of felix-homelab/rpmgr through GitHub's REST API: one page,
// the newest releases first. The request sends no data but the page size (D4).
type GitHubReleases struct {
	API    string // https://api.github.com/repos/felix-homelab/rpmgr/releases
	Client *http.Client
	Now    func() time.Time
}

// List returns the published releases of the first page; drafts and tags that are no release
// version are left out.
func (g GitHubReleases) List(ctx context.Context) ([]Listed, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.API+"?per_page=30", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		now := time.Now
		if g.Now != nil {
			now = g.Now
		}
		if until, ok := rateLimited(resp, now()); ok {
			return nil, &RateLimitedError{Until: until}
		}
		return nil, fmt.Errorf("release: listing the releases: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxList+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxList {
		return nil, fmt.Errorf("release: the release listing is larger than %d bytes", maxList)
	}
	var page []struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(b, &page); err != nil {
		return nil, fmt.Errorf("release: the release listing: %w", err)
	}
	var out []Listed
	for _, r := range page {
		v, ok := strings.CutPrefix(r.Tag, "v")
		if r.Draft || !ok || !Releasable(v) {
			continue
		}
		out = append(out, Listed{Version: v, Prerelease: r.Prerelease})
	}
	return out, nil
}

// rateLimited reports whether a response refuses a request for a rate limit, and until when:
// 429, or 403 with no requests remaining. Retry-After (seconds) wins over X-RateLimit-Reset (Unix
// time); without either the source is asked again in an hour.
func rateLimited(resp *http.Response, now time.Time) (time.Time, bool) {
	limited := resp.StatusCode == http.StatusTooManyRequests ||
		(resp.StatusCode == http.StatusForbidden && (resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != ""))
	if !limited {
		return time.Time{}, false
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
		return now.Add(time.Duration(s) * time.Second), true
	}
	if s, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && s > 0 {
		return time.Unix(s, 0), true
	}
	return now.Add(time.Hour), true
}
