package notifications

import (
	"encoding/json"
	"strings"
	"testing"
)

// The JSON tags are the SNS wire contract shared with the alerter consumer.
// This test fails loudly if a tag or field order regresses.
func TestMessage_WireContract(t *testing.T) {
	m := Message{Target: "slack", Source: "svc", SourceDescription: "desc", Content: "hello"}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Format is omitempty: an unset format must NOT appear, keeping the bytes
	// byte-for-byte identical to what v1.0.0 producers emit.
	want := `{"target":"slack","source":"svc","sourceDescription":"desc","content":"hello"}`
	if string(b) != want {
		t.Fatalf("wire mismatch:\n got=%s\nwant=%s", b, want)
	}

	var rt Message
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rt != m {
		t.Fatalf("round-trip mismatch: %+v != %+v", rt, m)
	}
}

func TestMessage_FormatField(t *testing.T) {
	m := Message{Target: "slack", Source: "svc", SourceDescription: "desc", Content: "hi", Format: "plain"}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"target":"slack","source":"svc","sourceDescription":"desc","content":"hi","format":"plain"}`
	if string(b) != want {
		t.Fatalf("wire mismatch:\n got=%s\nwant=%s", b, want)
	}

	// An old-contract message (no "format" key) must default to the zero value.
	var old Message
	if err := json.Unmarshal([]byte(`{"target":"slack","source":"s","sourceDescription":"d","content":"c"}`), &old); err != nil {
		t.Fatalf("unmarshal old: %v", err)
	}
	if old.Format != "" {
		t.Fatalf("expected empty Format for old message, got %q", old.Format)
	}
}

func TestMessage_InteractiveOmittedWhenNil(t *testing.T) {
	// A message with no Interactive block must serialise byte-identically to v1.1.0.
	m := Message{Target: "slack", Source: "svc", SourceDescription: "desc", Content: "hi"}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"target":"slack","source":"svc","sourceDescription":"desc","content":"hi"}`
	if string(b) != want {
		t.Fatalf("wire mismatch:\n got=%s\nwant=%s", b, want)
	}
}

func TestMessage_InteractiveRoundTrip(t *testing.T) {
	m := Message{
		Target: "slack", Source: "idp", SourceDescription: "IdP", Content: "Approve?",
		Interactive: &Interactive{
			CallbackID: "req-1",
			Payload:    "token-abc",
			Actions: []Action{
				{ID: "approve", Label: "OK", Style: "primary"},
				{ID: "reject", Label: "Cancel", Style: "danger"},
			},
		},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// omitempty on Payload/Style must not drop the set values.
	if !strings.Contains(string(b), `"interactive":{"callbackId":"req-1","payload":"token-abc"`) {
		t.Fatalf("interactive not serialised: %s", b)
	}
	var rt Message
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Pointer field => compare via re-marshal, not struct equality.
	rb, _ := json.Marshal(rt)
	if string(rb) != string(b) {
		t.Fatalf("round-trip mismatch:\n got=%s\nwant=%s", rb, b)
	}
}
