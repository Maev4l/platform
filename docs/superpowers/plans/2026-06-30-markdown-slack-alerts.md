# Markdown-formatted Slack alerts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let producers publish **standard Markdown** in `content`; the alerter renders it as Slack Block Kit (mrkdwn sections + native table blocks), defaulting to Markdown with a `plain` opt-out.

**Architecture:** Add an optional `Format` field to the shared `notifications.Message` contract. In the alerter's Slack target, route on `Format`: `"plain"` → a single plain-text section; otherwise → a new pure `mdslack` package that parses Markdown with goldmark (GFM) and emits `[]slack.Block`. Tables become native Slack `table` blocks with rich_text cells; over-limit tables and any parse failure fall back so an alert is never dropped.

**Tech Stack:** Go 1.26 (alerter), goldmark v1.8.2, slack-go v0.27.0, AWS Lambda (arm64), SNS.

## Global Constraints

- Alerter module `isnan.eu/alerting`, `go 1.26`; shared module `github.com/Maev4l/platform/notifications`, `go 1.24` floor (must stay ≤ every consumer — do not raise).
- Strict dependency versions (no `latest` ranges in committed go.mod): `github.com/slack-go/slack v0.27.0`, `github.com/yuin/goldmark v1.8.2`.
- `notifications` is consumed via git tag (current `notifications/v1.0.0`); contract change ships as `notifications/v1.1.0`. Other consumers (e.g. users-management) stay on v1.0.0 and are unaffected by `omitempty`.
- `mdslack` is a **pure** package: returns `[]slack.Block` and `error`, performs **no logging**.
- Slack limits: section text ≤ 3000 chars; table ≤ 100 rows, ≤ 20 cols, ≤ 10000 chars/table. Only `raw_text` and `rich_text` cells are postable.
- Lambda build is arm64 (`Makefile` `GOOS=linux GOARCH=arm64`); do not change build flags.
- Format every changed Go file with `gofmt -w` and verify `gofmt -l <files>` prints nothing before each commit; run `go vet ./...`. (Go agents routinely skip gofmt — do not.)
- Match surrounding file conventions: the alerter logs with `github.com/sirupsen/logrus` — keep using it in alerter files; do not introduce a second logger.
- Never commit or push automatically except where a step explicitly says to commit; the tag **push** in Task 7 is performed by the user.

---

### Task 1: Add `Format` field to the shared contract

**Files:**
- Modify: `notifications/message.go`
- Test: `notifications/message_test.go`

**Interfaces:**
- Produces: `notifications.Message` gains `Format string` with json tag `format,omitempty`. Semantics: `""`/`"markdown"` → Markdown; `"plain"` → literal text.

- [ ] **Step 1: Update the wire-contract test for the new field**

Replace the body of `TestMessage_WireContract` in `notifications/message_test.go` and add a second test:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd notifications && go test ./...`
Expected: FAIL — `Message` has no field `Format` (compile error in `TestMessage_FormatField`).

- [ ] **Step 3: Add the field**

In `notifications/message.go`, add the field to the struct (keep the existing comments):

```go
type Message struct {
	Target            string `json:"target"`             // routing key, e.g. "slack"
	Source            string `json:"source"`             // producer id
	SourceDescription string `json:"sourceDescription"`  // human label (Slack context)
	Content           string `json:"content"`            // message body (Markdown by default)
	// Format selects rendering: "" or "markdown" (default) => Markdown;
	// "plain" => literal text. omitempty keeps v1.0.0 producers' bytes unchanged.
	Format string `json:"format,omitempty"`
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd notifications && go test ./... && gofmt -l message.go message_test.go && go vet ./...`
Expected: PASS; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add notifications/message.go notifications/message_test.go
git commit -m "feat(notifications): add optional Format field (markdown default, plain opt-out)"
```

---

### Task 2: Wire alerter dependencies (goldmark + slack-go bump + local notifications)

**Files:**
- Modify: `alerter/function/go.mod`, `alerter/function/go.sum`

**Interfaces:**
- Produces: alerter compiles against the local (new-field) `notifications` and against slack-go v0.27.0 (table blocks) + goldmark v1.8.2.

- [ ] **Step 1: Add a temporary local replace for notifications**

Append to `alerter/function/go.mod` (TEMPORARY — removed in Task 7 once the tag is published):

```
// TEMP (removed in release Task 7): build against in-repo notifications so the
// new Format field is available before notifications/v1.1.0 is tagged/pushed.
replace github.com/Maev4l/platform/notifications => ../../notifications
```

- [ ] **Step 2: Bump slack-go and add goldmark**

Run:
```bash
cd alerter/function
go get github.com/slack-go/slack@v0.27.0
go get github.com/yuin/goldmark@v1.8.2
go mod tidy
```

- [ ] **Step 3: Verify the module graph compiles**

Run: `cd alerter/function && go build ./...`
Expected: builds with no errors. Confirm `go.mod` pins `github.com/slack-go/slack v0.27.0` and `github.com/yuin/goldmark v1.8.2` (exact versions, no ranges).

- [ ] **Step 4: Commit**

```bash
git add alerter/function/go.mod alerter/function/go.sum
git commit -m "build(alerter): bump slack-go to v0.27.0, add goldmark; temp local notifications replace"
```

---

### Task 3: `mdslack` — inline + prose rendering (no tables yet)

**Files:**
- Create: `alerter/function/cmd/targets/mdslack/mdslack.go`
- Test: `alerter/function/cmd/targets/mdslack/mdslack_test.go`

**Interfaces:**
- Produces:
  - `func Render(src string) ([]slack.Block, error)` — Markdown → blocks; returns an error if there is no renderable content (caller falls back).
  - unexported helpers `renderBlock`, `renderList`, `inline`, `inlineNode`, `inlineText`, `codeText`, `sectionsFromText`, `splitChars` (table support is added in Task 4; `tableBlock` is referenced there).
- Consumes: `notifications` is **not** imported here (pure renderer); only `slack` + goldmark.

- [ ] **Step 1: Write failing tests for inline + prose**

Create `alerter/function/cmd/targets/mdslack/mdslack_test.go`:

```go
package mdslack

import (
	"encoding/json"
	"strings"
	"testing"
)

// jsonOf marshals the rendered blocks for structural comparison against the
// exact Block Kit payload Slack will receive.
func jsonOf(t *testing.T, src string) string {
	t.Helper()
	blocks, err := Render(src)
	if err != nil {
		t.Fatalf("Render(%q) error: %v", src, err)
	}
	b, err := json.Marshal(blocks)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd alerter/function && go test ./cmd/targets/mdslack/...`
Expected: FAIL — package/`Render` does not exist.

- [ ] **Step 3: Implement the renderer (prose only)**

Create `alerter/function/cmd/targets/mdslack/mdslack.go`:

```go
// Package mdslack converts standard (CommonMark/GFM) Markdown into Slack Block
// Kit blocks: mrkdwn section blocks for prose and native table blocks for GFM
// tables. It is intentionally pure — no logging, no I/O — so the alerter can
// unit-test the exact payload and fall back on error.
package mdslack

import (
	"fmt"
	"strings"

	"github.com/slack-go/slack"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
)

const (
	maxSectionChars = 3000  // Slack section text limit
	maxTableRows    = 100   // Slack table-block limits
	maxTableCols    = 20
	maxTableChars   = 10000
)

// extension.GFM bundles tables + strikethrough + autolinks, matching what
// producers expect from "standard" Markdown.
var md = goldmark.New(goldmark.WithExtensions(extension.GFM))

// Render parses Markdown and returns Slack blocks. It returns an error when the
// source has no renderable content so the caller can fall back to plain text.
func Render(src string) ([]slack.Block, error) {
	source := []byte(src)
	doc := md.Parser().Parse(text.NewReader(source))

	var blocks []slack.Block
	var prose strings.Builder

	flush := func() {
		if prose.Len() == 0 {
			return
		}
		blocks = append(blocks, sectionsFromText(prose.String())...)
		prose.Reset()
	}

	for n := doc.FirstChild(); n != nil; n = n.NextSibling() {
		if tbl, ok := n.(*east.Table); ok {
			flush()
			blocks = append(blocks, tableBlock(tbl, source))
			continue
		}
		s := renderBlock(n, source)
		if strings.TrimSpace(s) == "" {
			continue
		}
		if prose.Len() > 0 {
			prose.WriteString("\n\n")
		}
		prose.WriteString(s)
	}
	flush()

	if len(blocks) == 0 {
		return nil, fmt.Errorf("mdslack: no renderable content")
	}
	return blocks, nil
}

// renderBlock turns a block-level node into a Slack mrkdwn string.
func renderBlock(n ast.Node, src []byte) string {
	switch b := n.(type) {
	case *ast.Heading:
		// Slack mrkdwn has no headings; bold the line so it still stands out.
		return "*" + inline(n, src) + "*"
	case *ast.Blockquote:
		var lines []string
		for c := n.FirstChild(); c != nil; c = c.NextSibling() {
			lines = append(lines, renderBlock(c, src))
		}
		var qb strings.Builder
		for i, line := range strings.Split(strings.Join(lines, "\n"), "\n") {
			if i > 0 {
				qb.WriteString("\n")
			}
			qb.WriteString("> " + line)
		}
		return qb.String()
	case *ast.List:
		return renderList(b, src)
	case *ast.FencedCodeBlock:
		return "```\n" + codeText(n, src) + "```"
	case *ast.CodeBlock:
		return "```\n" + codeText(n, src) + "```"
	case *ast.ThematicBreak:
		return "──────────"
	default: // Paragraph, TextBlock, etc.
		return inline(n, src)
	}
}

// renderList renders ordered/unordered lists, indenting nested lists.
func renderList(l *ast.List, src []byte) string {
	var sb strings.Builder
	idx := l.Start
	if idx == 0 {
		idx = 1
	}
	for li := l.FirstChild(); li != nil; li = li.NextSibling() {
		marker := "• "
		if l.IsOrdered() {
			marker = fmt.Sprintf("%d. ", idx)
			idx++
		}
		var parts []string
		for c := li.FirstChild(); c != nil; c = c.NextSibling() {
			if nested, ok := c.(*ast.List); ok {
				parts = append(parts, indentLines(renderList(nested, src), "    "))
			} else {
				parts = append(parts, renderBlock(c, src))
			}
		}
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(marker + strings.Join(parts, "\n"))
	}
	return sb.String()
}

func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

// inline concatenates the inline rendering of a node's children.
func inline(n ast.Node, src []byte) string {
	var sb strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		sb.WriteString(inlineNode(c, src))
	}
	return sb.String()
}

func inlineNode(n ast.Node, src []byte) string {
	switch v := n.(type) {
	case *ast.Text:
		s := string(v.Segment.Value(src))
		if v.SoftLineBreak() || v.HardLineBreak() {
			s += "\n"
		}
		return s
	case *ast.String:
		return string(v.Value)
	case *ast.CodeSpan:
		return "`" + inlineText(n, src) + "`"
	case *ast.Emphasis:
		inner := inline(n, src)
		if v.Level >= 2 {
			return "*" + inner + "*" // bold
		}
		return "_" + inner + "_" // italic
	case *east.Strikethrough:
		return "~" + inline(n, src) + "~"
	case *ast.Link:
		return "<" + string(v.Destination) + "|" + inline(n, src) + ">"
	case *ast.AutoLink:
		url := string(v.URL(src))
		return "<" + url + ">"
	default:
		return inline(n, src)
	}
}

// inlineText extracts raw text (no markup) — used for code spans and link/cell text.
func inlineText(n ast.Node, src []byte) string {
	var sb strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if t, ok := c.(*ast.Text); ok {
			sb.Write(t.Segment.Value(src))
		} else {
			sb.WriteString(inlineText(c, src))
		}
	}
	return sb.String()
}

// codeText returns the literal lines of a (fenced) code block.
func codeText(n ast.Node, src []byte) string {
	var sb strings.Builder
	lines := n.Lines()
	for i := 0; i < lines.Len(); i++ {
		seg := lines.At(i)
		sb.Write(seg.Value(src))
	}
	return sb.String()
}

// sectionsFromText wraps text in one or more mrkdwn section blocks under the limit.
func sectionsFromText(s string) []slack.Block {
	var blocks []slack.Block
	for _, chunk := range splitChars(s, maxSectionChars) {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, chunk, false, false), nil, nil))
	}
	return blocks
}

// splitChars splits s into pieces of at most max runes, preferring to break at
// the last newline so formatting is not severed mid-line.
func splitChars(s string, max int) []string {
	r := []rune(s)
	if len(r) <= max {
		return []string{s}
	}
	var out []string
	for len(r) > max {
		cut := max
		if nl := lastIndexRune(r[:max], '\n'); nl > 0 {
			cut = nl
		}
		out = append(out, string(r[:cut]))
		r = r[cut:]
	}
	if len(r) > 0 {
		out = append(out, string(r))
	}
	return out
}

func lastIndexRune(r []rune, target rune) int {
	for i := len(r) - 1; i >= 0; i-- {
		if r[i] == target {
			return i
		}
	}
	return -1
}
```

> Note: this file references `tableBlock` (added in Task 4). It will not compile until Task 4 adds `table.go` in the same package — that is expected; run this task's tests together with Task 4, OR temporarily stub `func tableBlock(_ *east.Table, _ []byte) slack.Block { return nil }` at the end of `mdslack.go`, then delete the stub in Task 4 Step 3. Use the stub so Task 3 is independently testable.

- [ ] **Step 4: Add the temporary stub and run tests**

Add at the end of `mdslack.go` (deleted in Task 4):

```go
// TEMP stub (replaced in Task 4): keeps the package compilable before table.go.
func tableBlock(_ *east.Table, _ []byte) slack.Block {
	return slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, "(table)", false, false), nil, nil)
}
```

Run: `cd alerter/function && go test ./cmd/targets/mdslack/... && gofmt -l ./cmd/targets/mdslack/ && go vet ./cmd/targets/mdslack/...`
Expected: PASS; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add alerter/function/cmd/targets/mdslack/mdslack.go alerter/function/cmd/targets/mdslack/mdslack_test.go
git commit -m "feat(alerter): mdslack renders Markdown prose to Slack mrkdwn section blocks"
```

---

### Task 4: `mdslack` — native Slack table blocks

**Files:**
- Create: `alerter/function/cmd/targets/mdslack/table.go`
- Modify: `alerter/function/cmd/targets/mdslack/mdslack.go` (remove the Task 3 stub)
- Test: `alerter/function/cmd/targets/mdslack/table_test.go`

**Interfaces:**
- Produces: `func tableBlock(t *east.Table, src []byte) slack.Block` — returns a `*slack.TableBlock` with rich_text cells + column alignment, or a code-block section when the table exceeds Slack limits.
- Consumes: slack-go v0.27.0 table API verified as: `slack.NewTableBlock(id)`, `(*TableBlock).AddRow(cells ...slack.TableCell)`, `(*TableBlock).WithColumnSettings(...slack.ColumnSetting)`, `slack.NewTableRichTextCell(elements ...slack.RichTextElement)`, `slack.NewRichTextSection(...slack.RichTextSectionElement)`, `slack.NewRichTextSectionTextElement(text string, *slack.RichTextSectionTextStyle)`, `slack.NewRichTextSectionLinkElement(url, text string, *slack.RichTextSectionTextStyle)`, `slack.ColumnSetting{Align: slack.ColumnAlignment{Left,Center,Right}}`.

- [ ] **Step 1: Verify the slack-go table API in the resolved module**

Run:
```bash
cd alerter/function
go doc github.com/slack-go/slack TableBlock
go doc github.com/slack-go/slack NewTableRichTextCell
go doc github.com/slack-go/slack NewRichTextSectionTextElement
```
Expected: signatures match the Consumes block above. If any differ, adapt the code in Step 3 accordingly (the JSON tests in Step 2 are the source of truth).

- [ ] **Step 2: Write failing table tests**

Create `alerter/function/cmd/targets/mdslack/table_test.go`:

```go
package mdslack

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRender_SimpleTable(t *testing.T) {
	src := "| Svc | Status |\n|-----|--------|\n| api | down |"
	blocks, err := Render(src)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	b, _ := json.Marshal(blocks)
	js := string(b)
	if !strings.Contains(js, `"type":"table"`) {
		t.Fatalf("expected a table block: %s", js)
	}
	if !strings.Contains(js, `"type":"rich_text"`) {
		t.Fatalf("expected rich_text cells: %s", js)
	}
	if !strings.Contains(js, `"text":"Svc"`) || !strings.Contains(js, `"text":"api"`) {
		t.Fatalf("cell text missing: %s", js)
	}
}

func TestRender_TableAlignmentAndRichCells(t *testing.T) {
	src := "| Name | Count |\n|:-----|------:|\n| **api** | [1](https://x) |"
	blocks, err := Render(src)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	b, _ := json.Marshal(blocks)
	js := string(b)
	if !strings.Contains(js, `"align":"left"`) || !strings.Contains(js, `"align":"right"`) {
		t.Fatalf("column alignment missing: %s", js)
	}
	if !strings.Contains(js, `"bold":true`) {
		t.Fatalf("bold cell text missing: %s", js)
	}
	if !strings.Contains(js, `"type":"link"`) || !strings.Contains(js, `https://x`) {
		t.Fatalf("link cell missing: %s", js)
	}
}

func TestRender_TableProseInterleaving(t *testing.T) {
	src := "before\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\nafter"
	blocks, err := Render(src)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(blocks) != 3 {
		t.Fatalf("expected section,table,section (3 blocks), got %d", len(blocks))
	}
}

func TestRender_OverLimitTableFallsBackToCodeBlock(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("| a |\n|---|\n")
	for i := 0; i < 150; i++ { // > maxTableRows
		sb.WriteString("| x |\n")
	}
	blocks, err := Render(sb.String())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	b, _ := json.Marshal(blocks)
	js := string(b)
	if strings.Contains(js, `"type":"table"`) {
		t.Fatalf("over-limit table should not produce a table block: %s", js)
	}
	if !strings.Contains(js, "```") {
		t.Fatalf("over-limit table should fall back to a code block: %s", js)
	}
}
```

- [ ] **Step 3: Remove the stub and implement tables**

Delete the temporary `tableBlock` stub at the end of `mdslack.go` (added in Task 3 Step 4).

Create `alerter/function/cmd/targets/mdslack/table.go`:

```go
package mdslack

import (
	"fmt"
	"strings"

	"github.com/slack-go/slack"
	"github.com/yuin/goldmark/ast"
	east "github.com/yuin/goldmark/extension/ast"
)

// tableBlock converts a GFM table to a native Slack table block with rich_text
// cells. If the table exceeds Slack's limits, it degrades to a fenced code block
// (monospace, space-padded) so the data is never lost.
func tableBlock(t *east.Table, src []byte) slack.Block {
	rows := collectRows(t)

	cols, chars := 0, 0
	for _, row := range rows {
		if len(row) > cols {
			cols = len(row)
		}
		for _, cell := range row {
			chars += len(inline(cell, src))
		}
	}
	if len(rows) > maxTableRows || cols > maxTableCols || chars > maxTableChars {
		return slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, tableToCodeBlock(rows, src), false, false), nil, nil)
	}

	tb := slack.NewTableBlock("")
	for _, row := range rows {
		cells := make([]slack.TableCell, 0, len(row))
		for _, cell := range row {
			cells = append(cells, richCell(cell, src))
		}
		tb.AddRow(cells...)
	}
	if cs := columnSettings(t.Alignments); len(cs) > 0 {
		tb.WithColumnSettings(cs...)
	}
	return tb
}

func collectRows(t *east.Table) [][]*east.TableCell {
	var rows [][]*east.TableCell
	for r := t.FirstChild(); r != nil; r = r.NextSibling() {
		var cells []*east.TableCell
		for c := r.FirstChild(); c != nil; c = c.NextSibling() {
			if cell, ok := c.(*east.TableCell); ok {
				cells = append(cells, cell)
			}
		}
		rows = append(rows, cells)
	}
	return rows
}

// richCell builds a rich_text cell preserving inline bold/italic/strike/code/links.
func richCell(cell ast.Node, src []byte) slack.TableCell {
	var elems []slack.RichTextSectionElement
	collectRich(cell, src, &elems, slack.RichTextSectionTextStyle{})
	if len(elems) == 0 {
		elems = append(elems, slack.NewRichTextSectionTextElement("", nil))
	}
	return slack.NewTableRichTextCell(slack.NewRichTextSection(elems...))
}

func collectRich(n ast.Node, src []byte, out *[]slack.RichTextSectionElement, style slack.RichTextSectionTextStyle) {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch v := c.(type) {
		case *ast.Text:
			st := style
			*out = append(*out, slack.NewRichTextSectionTextElement(string(v.Segment.Value(src)), &st))
		case *ast.String:
			st := style
			*out = append(*out, slack.NewRichTextSectionTextElement(string(v.Value), &st))
		case *ast.CodeSpan:
			st := style
			st.Code = true
			*out = append(*out, slack.NewRichTextSectionTextElement(inlineText(c, src), &st))
		case *ast.Emphasis:
			st := style
			if v.Level >= 2 {
				st.Bold = true
			} else {
				st.Italic = true
			}
			collectRich(c, src, out, st)
		case *east.Strikethrough:
			st := style
			st.Strike = true
			collectRich(c, src, out, st)
		case *ast.Link:
			st := style
			*out = append(*out, slack.NewRichTextSectionLinkElement(string(v.Destination), inlineText(c, src), &st))
		case *ast.AutoLink:
			st := style
			url := string(v.URL(src))
			*out = append(*out, slack.NewRichTextSectionLinkElement(url, url, &st))
		default:
			collectRich(c, src, out, style)
		}
	}
}

func columnSettings(aligns []east.Alignment) []slack.ColumnSetting {
	cs := make([]slack.ColumnSetting, 0, len(aligns))
	for _, a := range aligns {
		col := slack.ColumnSetting{Align: slack.ColumnAlignmentLeft}
		switch a {
		case east.AlignCenter:
			col.Align = slack.ColumnAlignmentCenter
		case east.AlignRight:
			col.Align = slack.ColumnAlignmentRight
		}
		cs = append(cs, col)
	}
	return cs
}

// tableToCodeBlock renders an over-limit table as a space-padded monospace block.
func tableToCodeBlock(rows [][]*east.TableCell, src []byte) string {
	text := make([][]string, len(rows))
	widths := []int{}
	for i, row := range rows {
		text[i] = make([]string, len(row))
		for j, cell := range row {
			s := inline(cell, src)
			text[i][j] = s
			if j >= len(widths) {
				widths = append(widths, 0)
			}
			if len(s) > widths[j] {
				widths[j] = len(s)
			}
		}
	}
	var sb strings.Builder
	sb.WriteString("```\n")
	for _, row := range text {
		cells := make([]string, len(row))
		for j, s := range row {
			cells[j] = fmt.Sprintf("%-*s", widths[j], s)
		}
		sb.WriteString(strings.Join(cells, " | "))
		sb.WriteString("\n")
	}
	sb.WriteString("```")
	return sb.String()
}
```

- [ ] **Step 4: Run all mdslack tests**

Run: `cd alerter/function && go test ./cmd/targets/mdslack/... && gofmt -l ./cmd/targets/mdslack/ && go vet ./cmd/targets/mdslack/...`
Expected: PASS (Task 3 + Task 4 tests); `gofmt -l` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add alerter/function/cmd/targets/mdslack/table.go alerter/function/cmd/targets/mdslack/table_test.go alerter/function/cmd/targets/mdslack/mdslack.go
git commit -m "feat(alerter): mdslack renders GFM tables as native Slack table blocks"
```

---

### Task 5: Wire `mdslack` into the Slack target

**Files:**
- Modify: `alerter/function/cmd/targets/slack.go`
- Test: `alerter/function/cmd/targets/slack_blocks_test.go`

**Interfaces:**
- Produces: `func buildMessageBlocks(msg *notifications.Message) []slack.Block` — context block (if `SourceDescription`) + body; body via `mdslack.Render` for markdown, single plain-text section for `format:"plain"` or on render failure.
- Consumes: `mdslack.Render` (Task 3/4); `notifications.Message.Format` (Task 1).

- [ ] **Step 1: Write failing tests for block building**

Create `alerter/function/cmd/targets/slack_blocks_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd alerter/function && go test ./cmd/targets/`
Expected: FAIL — `buildMessageBlocks` undefined.

- [ ] **Step 3: Implement block building and switch the post to blocks**

In `alerter/function/cmd/targets/slack.go`: add the import for the mdslack package and replace the `SendAlert` method, adding the helpers. The new code:

```go
import (
	// ...existing imports...
	"isnan.eu/alerting/cmd/targets/mdslack"
)

// buildMessageBlocks assembles the Slack Block Kit payload: a context block for
// the source label (when present) followed by the rendered body.
func buildMessageBlocks(alert *notifications.Message) []slack.Block {
	var blocks []slack.Block
	if alert.SourceDescription != "" {
		blocks = append(blocks, slack.NewContextBlock("",
			slack.NewTextBlockObject(slack.MarkdownType, alert.SourceDescription, false, false)))
	}
	return append(blocks, bodyBlocks(alert)...)
}

// bodyBlocks renders the content. "plain" sends literal text; otherwise Markdown,
// falling back to a literal section so an alert is never dropped.
func bodyBlocks(alert *notifications.Message) []slack.Block {
	if alert.Format == "plain" {
		return []slack.Block{plainSection(alert.Content)}
	}
	blocks, err := mdslack.Render(alert.Content)
	if err != nil || len(blocks) == 0 {
		log.Warnf("Markdown render failed, falling back to plain text: %v", err)
		return []slack.Block{plainSection(alert.Content)}
	}
	return blocks
}

func plainSection(s string) slack.Block {
	return slack.NewSectionBlock(slack.NewTextBlockObject(slack.PlainTextType, s, false, false), nil, nil)
}

func (n slackNotifier) SendAlert(alert *notifications.Message) error {
	if alert.Content == "" {
		return nil
	}
	blocks := buildMessageBlocks(alert)
	_, _, err := n.slackClient.PostMessage(channelId, slack.MsgOptionBlocks(blocks...))
	if err != nil {
		log.Errorf("Failed to send alert to %s", n.name)
		return err
	}
	return nil
}
```

Remove the now-unused `slack.Attachment` construction from the old `SendAlert`.

- [ ] **Step 4: Run tests + build**

Run: `cd alerter/function && go test ./... && go build ./... && gofmt -l ./cmd/targets/ && go vet ./...`
Expected: PASS; builds; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add alerter/function/cmd/targets/slack.go alerter/function/cmd/targets/slack_blocks_test.go
git commit -m "feat(alerter): post Slack alerts as Block Kit; render content as Markdown (plain opt-out)"
```

---

### Task 6: Documentation

**Files:**
- Modify: `alerter/README.md` (create if absent)

**Interfaces:** none.

- [ ] **Step 1: Document the contract and rendering**

Add/replace the alerter README body with the producer-facing contract:

```markdown
# Alerter

Consumes the alerting SNS topic and routes messages to Slack.

## Message contract

```json
{
  "target": "slack",
  "source": "my-service",
  "sourceDescription": "My Service",
  "content": "**Deploy failed** on `prod` — see [build](https://ci/123)",
  "format": "markdown"
}
```

- `content` is **standard Markdown by default** (`format` omitted or `"markdown"`).
- Set `format: "plain"` to send literal text with no Markdown interpretation
  (use this when content contains `* _ # > ` `` ` `` `[ ] |` that must appear verbatim,
  e.g. wildcard domains like `*.example.com` or emails with underscores).

## Supported Markdown → Slack

bold, italic, strikethrough, inline code, code blocks, links, ordered/unordered
lists, blockquotes, headings (rendered bold), and **GFM tables** (rendered as
native Slack table blocks with per-column alignment and inline-formatted cells).

Tables exceeding Slack limits (100 rows / 20 cols / 10k chars) degrade to a
monospace code block. Any render failure falls back to plain text, so an alert
is never dropped.

## Backward compatibility

Messages without a `format` field render as Markdown. Plain prose is unaffected;
only unescaped Markdown characters may restyle. Producers needing verbatim output
set `format: "plain"`.
```

- [ ] **Step 2: Commit**

```bash
git add alerter/README.md
git commit -m "docs(alerter): document Markdown content, format field, and table support"
```

---

### Task 7: Release — publish `notifications/v1.1.0` and switch the alerter to the tag

**Files:**
- Modify: `alerter/function/go.mod`, `alerter/function/go.sum`

**Interfaces:** finalizes the alerter to consume the published `notifications v1.1.0` instead of the local replace.

- [ ] **Step 1: Publish the new notifications tag (USER action — requires push)**

Ask the user to run (the user performs all pushes per repo policy):

```bash
git tag notifications/v1.1.0
git push origin notifications/v1.1.0
```

Do not proceed until the tag is pushed.

- [ ] **Step 2: Remove the temporary replace and pin v1.1.0**

In `alerter/function/go.mod`: delete the `replace github.com/Maev4l/platform/notifications => ../../notifications` line (and its comment) added in Task 2, then:

```bash
cd alerter/function
go get github.com/Maev4l/platform/notifications@v1.1.0
go mod tidy
```

- [ ] **Step 3: Verify build, tests, and Lambda package**

Run:
```bash
cd alerter/function
go test ./...
go vet ./...
make package
```
Expected: tests PASS; `go.mod` requires `github.com/Maev4l/platform/notifications v1.1.0` with no `replace`; `dist/alerter.zip` is produced (arm64 bootstrap).

- [ ] **Step 4: Commit**

```bash
git add alerter/function/go.mod alerter/function/go.sum
git commit -m "build(alerter): consume notifications v1.1.0; drop temporary local replace"
```

---

## Self-Review

- **Spec coverage:** contract field (Task 1); default-markdown + plain opt-out (Tasks 1,5); blocks output with context block (Task 5); mrkdwn mapping incl. headings/lists/quote/code/links (Task 3); native table blocks + rich cells + alignment (Task 4); 3000-char section split (Task 3); table over-limit code-block fallback + parse-failure plain fallback (Tasks 4,5); goldmark dep + pure package (Tasks 2,3); slack-go bump for table block (Task 2); wire-contract test (Task 1); README (Task 6); module versioning/tag (Tasks 2,7). All spec sections mapped.
- **Placeholder scan:** none — all steps contain concrete code/commands. The only intentional temporaries (notifications `replace`, `tableBlock` stub) are explicitly added and later removed.
- **Type consistency:** `Render`, `tableBlock`, `inline`, `inlineText`, `buildMessageBlocks`, `bodyBlocks`, `plainSection` names are consistent across tasks; slack-go constructors verified against v0.27.0; goldmark/east node types verified against v1.8.2.
