# Markdown-formatted Slack alerts — design

**Date:** 2026-06-30
**Status:** Approved (pending spec review)

## Problem

Apps and microservices publish alerts to the alerting SNS topic; the alerter
Lambda routes them to Slack. Today `content` is posted as the `Text` of a legacy
Slack **Attachment** — plain text only. Senders cannot send rich formatting
(bold, links, lists, code, tables) that Slack supports.

## Goal

Let senders write **standard Markdown** in `content` and have the alerter render
it as proper Slack formatting, including **tables**. Senders stay Slack-agnostic
(they write normal Markdown, not Slack's mrkdwn dialect or Block Kit JSON); the
alerter owns the translation.

## Decisions (settled during brainstorming)

- **Format model:** senders write **standard/CommonMark Markdown**; the alerter
  translates. (Not Slack mrkdwn strings, not raw Block Kit from senders.)
- **Opt-in:** a new optional `format` field. **Unset/empty → `markdown` (default).**
  `format: "plain"` forces literal text (no parsing).
- **Slack output:** a Block Kit **`blocks` array** — section blocks (mrkdwn) for
  prose, and a **native `table` block** wherever a Markdown table appears.
- **Translator:** Go, **goldmark** (CommonMark parser, GFM table extension) plus
  a custom renderer we own. No runtime change; no third-party Slack-conversion
  lib. (A Node/`slackify-markdown` rewrite was rejected: it emits mrkdwn text
  only and cannot produce the native table block.)
- **Table cells:** **rich_text** cells — inline bold/links/code inside cells are
  preserved.
- **Backward compatibility:** default-markdown; delivery always guaranteed by a
  fallback. Producers needing literal output opt into `format: "plain"`.

## Contract change (`notifications` module)

Add one optional field to `Message`:

```go
type Message struct {
    Target            string `json:"target"`
    Source            string `json:"source"`
    SourceDescription string `json:"sourceDescription"`
    Content           string `json:"content"`
    Format            string `json:"format,omitempty"` // "markdown" (default/unset) | "plain"
}
```

- `omitempty` keeps existing producers' wire bytes **byte-for-byte unchanged**.
- The existing wire-contract test gains cases: `format` omitted (must not appear
  in JSON) and `format: "plain"` round-trip.

## Alerter flow (Slack target)

Replace the legacy Attachment post with a Block Kit `blocks` post:

1. `sourceDescription` → a leading **context block** (small, muted) — replaces
   the old attachment pretext.
2. Resolve effective format: `""` or `"markdown"` → markdown path; `"plain"` →
   plain path.
3. **markdown path:** `content` → `mdslack.Render(content)` → `[]slack.Block`,
   appended after the context block.
4. **plain path:** `content` → a single `plain_text` section (no parsing),
   appended after the context block.
5. `PostMessage(channelId, slack.MsgOptionBlocks(blocks...))`.

## Markdown → blocks (new `mdslack` package in the alerter)

goldmark (with the GFM table extension) parses `content` to an AST; a custom
renderer walks it and produces `[]slack.Block`:

| Markdown | Slack output |
|---|---|
| `**bold**` | `*bold*` (mrkdwn) |
| `*italic*` / `_italic_` | `_italic_` |
| `~~strike~~` | `~strike~` |
| `` `code` `` | `` `code` `` |
| fenced code block | triple-backtick mrkdwn block |
| `[txt](url)` | `<url\|txt>` |
| `# Heading` (any level) | `*Heading*` (bold line — Slack mrkdwn has no headings) |
| `- item` / `1. item` | `• item` / `1. item` |
| `> quote` | `> quote` |
| GFM table | native **`table` block** (see below) |

- **Coalescing:** consecutive non-table content is grouped into section blocks.
  A section's text caps at **3000 chars** (Slack limit); longer content splits
  into multiple section blocks.
- **Tables:** each GFM table → one `table` block. First row = header. Cells are
  **rich_text** (inline bold/links/code preserved). GFM column alignment
  (`:--`, `:-:`, `--:`) → `column_settings.align` (left/center/right).

## Table limits & fallback

Slack `table` block caps: **100 rows, 20 columns, 10 000 chars/table**.

- If a table exceeds any cap → render **that table** as a fenced code block
  (monospace, columns space-padded for alignment) so no data is lost; log a
  warning. The rest of the message renders normally.
- If the whole Markdown parse/translate fails for any reason → **fall back** to
  posting `content` as a single plain-text section. An alert is **never dropped**.

## Backward compatibility

- Old producers send no `format` field → unmarshals to `Format == ""` →
  **markdown path**. Wire bytes are unaffected; messages still deliver.
- Plain prose renders identically. The **only** effect is cosmetic: legacy text
  containing unescaped Markdown specials (`* _ # > \` [ ] |`, or a leading `-`)
  may be styled. Mis-styling only occurs when delimiters happen to pair up; a
  lone `*` or `_` renders literally.
- Known low-frequency cases: content embedding wildcard domain names (contain
  `*`) or email addresses (may contain `_`), and free-form error strings.
- **Mitigation:** any producer that needs literal output sets `format: "plain"`
  — a one-line change on the producer side, no alerter redeploy required beyond
  this feature. We do **not** pre-pin producers.

## Dependencies / housekeeping

- Add `github.com/yuin/goldmark` to `alerter/function/go.mod` (used with its
  built-in GFM table extension).
- `mdslack` is a **pure** package: it returns `[]slack.Block` and errors, does
  no logging — keeps it decoupled from the alerter's existing logger and easy to
  unit-test.
- Update the alerter README to document the new `format` field, default-markdown
  behavior, the supported Markdown subset, and table support.

## Testing

- `notifications`: extend the wire-contract test for `format` (omitted case +
  `"plain"` round-trip).
- `mdslack` (table-driven):
  - inline: bold, italic, strikethrough, inline code, links;
  - block: headings→bold, ordered/unordered lists, blockquotes, fenced code;
  - section coalescing and 3000-char splitting;
  - tables: header row, column alignment, rich_text cells with inline formatting;
  - over-limit table → code-block fallback;
  - parse/translate failure → plain-text fallback;
  - `format: "plain"` passthrough (no parsing).
- `gofmt -l` clean; `go vet` clean.

## Out of scope

- Other targets (Slack is the only registered target).
- Block Kit interactive elements (buttons, inputs), images, and per-message
  channel overrides.
- Reverse direction (Slack → producers).
