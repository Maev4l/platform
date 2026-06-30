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
