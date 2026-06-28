package geo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeArchive(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "GeoLite2-City_20260101/GeoLite2-City.mmdb", Mode: 0o644, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	tw.Write(payload)
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestUpdateDownloadsThenDetectsUpToDate(t *testing.T) {
	payload := []byte("fake-mmdb-bytes")
	archive := makeArchive(t, payload)
	sum := sha256.Sum256(archive)
	shaHex := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("suffix") {
		case "tar.gz.sha256":
			w.Write([]byte(shaHex + "  GeoLite2-City_20260101.tar.gz\n"))
		case "tar.gz":
			w.Write(archive)
		default:
			http.Error(w, "bad suffix", 400)
		}
	}))
	defer srv.Close()

	old := baseURL
	baseURL = srv.URL
	defer func() { baseURL = old }()

	dbPath := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")

	changed, err := Update(context.Background(), "k", dbPath)
	if err != nil || !changed {
		t.Fatalf("first update: changed=%v err=%v", changed, err)
	}
	if got, _ := os.ReadFile(dbPath); !bytes.Equal(got, payload) {
		t.Fatalf("extracted mmdb mismatch: %q", got)
	}
	if cur, _ := os.ReadFile(dbPath + ".sha256"); strings.TrimSpace(string(cur)) != shaHex {
		t.Fatalf("sidecar not written")
	}

	changed, err = Update(context.Background(), "k", dbPath)
	if err != nil || changed {
		t.Fatalf("second update should be a no-op: changed=%v err=%v", changed, err)
	}
}
