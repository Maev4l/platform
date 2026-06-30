package mdslack

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// jsonOf marshals the rendered blocks for structural comparison against the
// exact Block Kit payload Slack will receive.
// SetEscapeHTML(false) so angle-bracket URLs like <https://x|txt> survive
// round-trip as-is (json.Marshal would produce <...> otherwise).
func jsonOf(t *testing.T, src string) string {
	t.Helper()
	blocks, err := Render(src)
	if err != nil {
		t.Fatalf("Render(%q) error: %v", src, err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(blocks); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return strings.TrimRight(buf.String(), "\n")
}

func TestRender_InlineFormatting(t *testing.T) {
	got := jsonOf(t, "**bold** and *italic* and ~~strike~~ and `code` and [txt](https://x)")
	want := `[{"type":"section","text":{"type":"mrkdwn","text":"*bold* and _italic_ and ~strike~ and ` + "`code`" + ` and <https://x|txt>"}}]`
	if got != want {
		t.Fatalf("inline mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestRender_HeadingBecomesBold(t *testing.T) {
	got := jsonOf(t, "# Deploy failed")
	if !strings.Contains(got, `"text":"*Deploy failed*"`) {
		t.Fatalf("heading not bolded: %s", got)
	}
}

func TestRender_ListsAndQuote(t *testing.T) {
	got := jsonOf(t, "- one\n- two\n\n> note")
	if !strings.Contains(got, `• one\n• two`) {
		t.Fatalf("bullets wrong: %s", got)
	}
	if !strings.Contains(got, `> note`) && !strings.Contains(got, `> note`) {
		t.Fatalf("quote wrong: %s", got)
	}
}

func TestRender_OrderedList(t *testing.T) {
	got := jsonOf(t, "1. a\n2. b")
	if !strings.Contains(got, `1. a\n2. b`) {
		t.Fatalf("ordered list wrong: %s", got)
	}
}

func TestRender_FencedCode(t *testing.T) {
	got := jsonOf(t, "```\nline1\nline2\n```")
	if !strings.Contains(got, "```") || !strings.Contains(got, `line1\nline2`) {
		t.Fatalf("code block wrong: %s", got)
	}
}

func TestRender_EmptyIsError(t *testing.T) {
	if _, err := Render("   "); err == nil {
		t.Fatalf("expected error for blank content")
	}
}

func TestRender_LongTextSplitsSections(t *testing.T) {
	blocks, err := Render(strings.Repeat("a", 7000))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(blocks) < 3 {
		t.Fatalf("expected >=3 sections for 7000 chars, got %d", len(blocks))
	}
}
