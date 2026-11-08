package updater

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"imuslab.com/zoraxy/mod/offline"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultRepo is the GitHub repository releases are fetched from. It can be
// overridden with the -update_repo startup flag.
const DefaultRepo = "TheTractorHacker/zoraxy"

// DefaultAPIBase is the GitHub REST API root.
const DefaultAPIBase = "https://api.github.com"

const (
	maxSmallAsset = 1 << 20   // SHA256SUMS / signature / release list
	maxBinary     = 512 << 20 // sanity cap for a downloaded binary
)

// source talks to the GitHub Releases API.
type source struct {
	repo, apiBase string
	client        *http.Client
	allowHTTP     bool
	token         func() string // optional GitHub token; only ever sent to the API host
}

// RateLimitError is returned when GitHub refuses a request because the unauthenticated
// (or token) rate limit was used up.
type RateLimitError struct {
	ResetAt       time.Time // zero when GitHub did not say
	Authenticated bool      // the request carried a token
}

func (e *RateLimitError) Error() string {
	msg := "GitHub rate limit reached"
	if !e.ResetAt.IsZero() {
		msg += ", try again at " + e.ResetAt.Local().Format("15:04")
	} else {
		msg += ", try again later"
	}
	if !e.Authenticated {
		msg += " (a GitHub token in the update settings raises the limit)"
	}
	return msg
}

// rateLimited inspects a non-OK response and returns a *RateLimitError if it is one.
func rateLimited(resp *http.Response, authenticated bool, now time.Time) *RateLimitError {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return nil
	}
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	retryAfter := resp.Header.Get("Retry-After")
	if resp.StatusCode == http.StatusForbidden && remaining != "0" && retryAfter == "" {
		return nil //an ordinary 403, not a rate limit
	}
	e := &RateLimitError{Authenticated: authenticated}
	if n, err := strconv.ParseInt(retryAfter, 10, 64); err == nil && n >= 0 {
		e.ResetAt = now.Add(time.Duration(n) * time.Second)
	} else if n, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && n > 0 {
		e.ResetAt = time.Unix(n, 0)
	}
	return e
}

func (s *source) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && !(s.allowHTTP && u.Scheme == "http") {
		return fmt.Errorf("refusing non-https URL %q", raw)
	}
	return nil
}

// do performs a GET without judging the status code.
func (s *source) do(ctx context.Context, rawurl string, hdr map[string]string) (*http.Response, bool, error) {
	if err := offline.Check(); err != nil {
		return nil, false, err
	}
	if err := s.checkURL(rawurl); err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "zoraxy-updater")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	authed := false
	if s.token != nil {
		// The token goes to the API host only, never to asset download hosts.
		if tok := s.token(); tok != "" && sameHost(rawurl, s.apiBase) {
			req.Header.Set("Authorization", "Bearer "+tok)
			authed = true
		}
	}
	resp, err := s.client.Do(req)
	return resp, authed, err
}

func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Host == ub.Host && ua.Scheme == ub.Scheme
}

func (s *source) get(ctx context.Context, rawurl string) (*http.Response, error) {
	resp, authed, err := s.do(ctx, rawurl, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if rl := rateLimited(resp, authed, time.Now()); rl != nil {
			return nil, rl
		}
		return nil, fmt.Errorf("GET %s: HTTP %d", rawurl, resp.StatusCode)
	}
	return resp, nil
}

// fetchReleases downloads the raw release list. If etag is not empty it is sent as
// If-None-Match; notModified is true on a 304 (which GitHub does not count against the rate limit).
func (s *source) fetchReleases(ctx context.Context, etag string, now time.Time) (body []byte, newETag string, notModified bool, err error) {
	hdr := map[string]string{}
	if etag != "" {
		hdr["If-None-Match"] = etag
	}
	resp, authed, err := s.do(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=30", strings.TrimRight(s.apiBase, "/"), s.repo), hdr)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, true, nil
	case http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(resp.Body, 8*maxSmallAsset))
		return b, resp.Header.Get("ETag"), false, err
	}
	if rl := rateLimited(resp, authed, now); rl != nil {
		return nil, "", false, rl
	}
	return nil, "", false, fmt.Errorf("GET releases: HTTP %d", resp.StatusCode)
}

// parseReleases decodes a GitHub release list, skipping drafts.
func parseReleases(body []byte) ([]Release, error) {
	var raw []struct {
		Tag        string    `json:"tag_name"`
		Name       string    `json:"name"`
		Body       string    `json:"body"`
		HTMLURL    string    `json:"html_url"`
		Draft      bool      `json:"draft"`
		Prerelease bool      `json:"prerelease"`
		Published  time.Time `json:"published_at"`
		Assets     []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decoding release list: %w", err)
	}
	var out []Release
	for _, r := range raw {
		if r.Draft {
			continue
		}
		rel := Release{Tag: r.Tag, Name: r.Name, Notes: r.Body, URL: r.HTMLURL, Prerelease: r.Prerelease, Published: r.Published}
		for _, a := range r.Assets {
			rel.Assets = append(rel.Assets, Asset{Name: a.Name, Size: a.Size, URL: a.URL})
		}
		rel.MarkEarlyAccess()
		out = append(out, rel)
	}
	return out, nil
}

// fetchSmall downloads a small asset fully into memory.
func (s *source) fetchSmall(ctx context.Context, a Asset) ([]byte, error) {
	resp, err := s.get(ctx, a.URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSmallAsset+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSmallAsset {
		return nil, fmt.Errorf("%s is unexpectedly large", a.Name)
	}
	return b, nil
}

// download streams an asset to dst, returning its SHA-256 and size.
func (s *source) download(ctx context.Context, a Asset, dst string, progress func(done, total int64)) ([sha256.Size]byte, int64, error) {
	var sum [sha256.Size]byte
	resp, err := s.get(ctx, a.URL)
	if err != nil {
		return sum, 0, err
	}
	defer resp.Body.Close()
	total := resp.ContentLength
	if total <= 0 {
		total = a.Size
	}
	if total > maxBinary {
		return sum, 0, errors.New("asset exceeds the size limit")
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return sum, 0, err
	}
	h := sha256.New()
	var done int64
	buf := make([]byte, 128<<10)
	var werr error
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if done += int64(n); done > maxBinary {
				werr = errors.New("asset exceeds the size limit")
				break
			}
			h.Write(buf[:n])
			if _, err := f.Write(buf[:n]); err != nil {
				werr = err
				break
			}
			if progress != nil {
				progress(done, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			werr = rerr
			break
		}
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil && total > 0 && resp.ContentLength > 0 && done != resp.ContentLength {
		werr = fmt.Errorf("short download: %d of %d bytes", done, resp.ContentLength)
	}
	if werr != nil {
		os.Remove(dst)
		return sum, done, werr
	}
	copy(sum[:], h.Sum(nil))
	return sum, done, nil
}
