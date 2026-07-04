package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Maev4l/platform/notifications"
)

func blocksJSON(t *testing.T, m *notifications.Message) string {
	t.Helper()
	b, err := json.Marshal(buildMessageBlocks(m))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestBuildBlocks_MarkdownWithContext(t *testing.T) {
	js := blocksJSON(t, &notifications.Message{
		SourceDescription: "CI", Content: "**Deploy failed**",
	})
	if !strings.Contains(js, `"type":"context"`) {
		t.Fatalf("expected context block: %s", js)
	}
	if !strings.Contains(js, `"text":"*Deploy failed*"`) {
		t.Fatalf("markdown not rendered: %s", js)
	}
}

func TestBuildBlocks_PlainFormatIsLiteral(t *testing.T) {
	js := blocksJSON(t, &notifications.Message{
		SourceDescription: "CI", Content: "*.isnan.eu renewed", Format: "plain",
	})
	if !strings.Contains(js, `"type":"plain_text"`) {
		t.Fatalf("expected plain_text section: %s", js)
	}
	if !strings.Contains(js, `*.isnan.eu renewed`) {
		t.Fatalf("plain content altered: %s", js)
	}
}

func TestBuildBlocks_EmptyRenderFallsBackToPlain(t *testing.T) {
	// Whitespace-only markdown yields no blocks -> fallback to a plain section.
	js := blocksJSON(t, &notifications.Message{Content: "   "})
	if !strings.Contains(js, `"type":"plain_text"`) {
		t.Fatalf("expected plain fallback: %s", js)
	}
}

func TestBuildBlocks_InteractiveButtons(t *testing.T) {
	js := blocksJSON(t, &notifications.Message{
		Source: "idp", SourceDescription: "IdP", Content: "Approve deploy?",
		Interactive: &notifications.Interactive{
			CallbackID: "req-1", Payload: "tok",
			Actions: []notifications.Action{
				{ID: "approve", Label: "OK", Style: "primary"},
				{ID: "reject", Label: "Cancel", Style: "danger"},
			},
		},
	})
	if !strings.Contains(js, `"type":"actions"`) {
		t.Fatalf("expected actions block: %s", js)
	}
	// action_id carries the decision; style is passed through from the producer.
	if !strings.Contains(js, `"action_id":"approve"`) || !strings.Contains(js, `"style":"primary"`) {
		t.Fatalf("approve button not rendered: %s", js)
	}
	if !strings.Contains(js, `"action_id":"reject"`) || !strings.Contains(js, `"style":"danger"`) {
		t.Fatalf("reject button not rendered: %s", js)
	}
	// button value carries the routing context as compact JSON.
	if !strings.Contains(js, `{\"s\":\"idp\",\"c\":\"req-1\",\"p\":\"tok\"}`) {
		t.Fatalf("button value context missing: %s", js)
	}
}

func TestBuildBlocks_NoActionsWhenNotInteractive(t *testing.T) {
	js := blocksJSON(t, &notifications.Message{Source: "svc", Content: "plain alert"})
	if strings.Contains(js, `"type":"actions"`) {
		t.Fatalf("unexpected actions block: %s", js)
	}
}
