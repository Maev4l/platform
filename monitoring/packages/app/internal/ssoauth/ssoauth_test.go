package ssoauth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTokenCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sso.json")
	want := cachedToken{AccessToken: "abc", ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
	if err := saveToken(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "abc" || !got.valid() {
		t.Fatalf("round-trip failed: %+v", got)
	}
}

func TestExpiredTokenInvalid(t *testing.T) {
	if (cachedToken{AccessToken: "x", ExpiresAt: time.Now().Add(-time.Minute)}).valid() {
		t.Fatal("expired token should be invalid")
	}
}
