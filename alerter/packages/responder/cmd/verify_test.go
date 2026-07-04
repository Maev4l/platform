package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

const testSecret = "shhh-signing-secret"

// slackSign reproduces Slack's v0 signature over "v0:{ts}:{body}".
func slackSign(ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	fmt.Fprintf(mac, "v0:%s:%s", ts, body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature_Valid(t *testing.T) {
	body := []byte("payload=%7B%7D")
	ts := fmt.Sprintf("%d", time.Now().Unix())
	headers := map[string]string{
		"x-slack-request-timestamp": ts,
		"x-slack-signature":         slackSign(ts, body),
	}
	if err := verifySignature(headers, body, testSecret); err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
}

func TestVerifySignature_BadSignature(t *testing.T) {
	body := []byte("payload=%7B%7D")
	ts := fmt.Sprintf("%d", time.Now().Unix())
	headers := map[string]string{
		"x-slack-request-timestamp": ts,
		"x-slack-signature":         "v0=deadbeef",
	}
	if err := verifySignature(headers, body, testSecret); err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestVerifySignature_StaleTimestamp(t *testing.T) {
	body := []byte("payload=%7B%7D")
	ts := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
	headers := map[string]string{
		"x-slack-request-timestamp": ts,
		"x-slack-signature":         slackSign(ts, body),
	}
	if err := verifySignature(headers, body, testSecret); err == nil {
		t.Fatal("expected error for stale timestamp (replay window)")
	}
}
