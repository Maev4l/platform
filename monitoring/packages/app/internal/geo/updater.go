package geo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const editionID = "GeoLite2-City"

// baseURL is a var so tests can point it at an httptest server.
var baseURL = "https://download.maxmind.com/app/geoip_download"

// httpGet fetches one download "suffix" from the MaxMind permalink. This
// endpoint (download.maxmind.com/app/geoip_download) authenticates ONLY via the
// `license_key` query parameter — it does not accept HTTP basic auth, so the
// account id is not used here (basic auth against it returns 401).
func httpGet(ctx context.Context, licenseKey, suffix string) ([]byte, error) {
	u := fmt.Sprintf("%s?edition_id=%s&license_key=%s&suffix=%s", baseURL, editionID, licenseKey, suffix)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", suffix, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// remoteSHA returns the published sha256 of the current tar.gz (first token of
// the ".sha256" body, which is "<hex>  <filename>").
func remoteSHA(ctx context.Context, licenseKey string) (string, error) {
	b, err := httpGet(ctx, licenseKey, "tar.gz.sha256")
	if err != nil {
		return "", err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return "", fmt.Errorf("empty sha256 response")
	}
	return f[0], nil
}

// Update downloads + extracts GeoLite2-City to dbPath when the local DB is
// missing or the remote tar.gz.sha256 differs from the <dbPath>.sha256 sidecar.
// Returns changed=true when it wrote a new DB.
func Update(ctx context.Context, licenseKey, dbPath string) (bool, error) {
	remote, err := remoteSHA(ctx, licenseKey)
	if err != nil {
		return false, fmt.Errorf("remote sha: %w", err)
	}
	sidecar := dbPath + ".sha256"
	if _, statErr := os.Stat(dbPath); statErr == nil {
		if cur, _ := os.ReadFile(sidecar); strings.TrimSpace(string(cur)) == remote {
			return false, nil // already up to date
		}
	}

	gz, err := httpGet(ctx, licenseKey, "tar.gz")
	if err != nil {
		return false, fmt.Errorf("download: %w", err)
	}
	sum := sha256.Sum256(gz)
	if hex.EncodeToString(sum[:]) != remote {
		return false, fmt.Errorf("sha256 mismatch: archive does not match published checksum")
	}

	mmdb, err := extractMMDB(gz)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return false, err
	}
	tmp := dbPath + ".tmp"
	defer os.Remove(tmp) // no-op after a successful rename; cleans up on any error path
	if err := os.WriteFile(tmp, mmdb, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, dbPath); err != nil {
		return false, err
	}
	if err := os.WriteFile(sidecar, []byte(remote), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// extractMMDB pulls the single *.mmdb entry out of a gzipped tar archive.
func extractMMDB(gzBytes []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no .mmdb entry in archive")
		}
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(h.Name, ".mmdb") {
			return io.ReadAll(tr)
		}
	}
}
