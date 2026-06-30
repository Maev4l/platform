package notifications

import (
	"encoding/json"
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
