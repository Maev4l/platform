package targets

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

func TestBuildBlocks_RenderFailureFallsBackToPlain(t *testing.T) {
	// Whitespace-only markdown yields no blocks -> fallback to a plain section.
	js := blocksJSON(t, &notifications.Message{Content: "   "})
	if !strings.Contains(js, `"type":"plain_text"`) {
		t.Fatalf("expected plain fallback: %s", js)
	}
}
