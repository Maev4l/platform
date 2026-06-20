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
