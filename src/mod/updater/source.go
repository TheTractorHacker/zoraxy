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

func (s *source) get(ctx context.Context, rawurl string) (*http.Response, error) {
	if err := offline.Check(); err != nil {
		return nil, err
	}
	if err := s.checkURL(rawurl); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "zoraxy-updater")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", rawurl, resp.StatusCode)
	}
	return resp, nil
}

// releases lists the most recent non-draft releases.
func (s *source) releases(ctx context.Context) ([]Release, error) {
	resp, err := s.get(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=30", strings.TrimRight(s.apiBase, "/"), s.repo))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8*maxSmallAsset)).Decode(&raw); err != nil {
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
