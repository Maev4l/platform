package main

import (
	"net/http"

	"github.com/slack-go/slack"
)

// verifySignature validates Slack's request signature and rejects stale
// requests (>5 min). slack.NewSecretsVerifier enforces the timestamp window
// and HMAC comparison; we only adapt the Function URL header map to http.Header.
func verifySignature(headers map[string]string, body []byte, signingSecret string) error {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v) // http.Header canonicalises keys; Function URL sends them lowercased
	}
	sv, err := slack.NewSecretsVerifier(h, signingSecret)
	if err != nil {
		return err
	}
	if _, err := sv.Write(body); err != nil {
		return err
	}
	return sv.Ensure()
}
