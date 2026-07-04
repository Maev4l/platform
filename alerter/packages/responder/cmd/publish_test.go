package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildResponsePayload(t *testing.T) {
	c := clickContext{Source: "idp", CallbackID: "req-1", Payload: "tok"}
	b, err := buildResponsePayload(c, "approve", "U1", "jsue", "C05", "169.1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"source", "callbackId", "action", "payload", "user", "channel", "ts"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing key %q in %s", k, b)
		}
	}
	if !strings.Contains(string(b), `"action":"approve"`) {
		t.Fatalf("action not set: %s", b)
	}
}
