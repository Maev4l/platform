# Alerter

Consumes the alerting SNS topic and routes messages to Slack.

## Layout

```
alerter/
├── packages
│     ├── notifier       # Lambda: alerting-events SNS -> Slack message (+ buttons)
│     ├── responder      # Lambda: Slack interactivity Function URL -> alerting-responses SNS
│     └── infrastructure # Terraform: SNS topics, both Lambdas, responder CDN, IAM
├── Makefile             # root orchestrator: packages both zips, then applies infra
└── README.md
```

- `notifier` renders alert messages (Markdown + optional action buttons) and posts to Slack.
- `responder` receives Slack button clicks, verifies the request signature, checks the
  clicking user against an allow-list, and relays the decision to the `alerting-responses`
  SNS topic.

### Responder endpoint

Slack calls the responder at the stable custom domain
**`https://platform-slack-responder.isnan.eu/`** (CloudFront → the responder's Lambda
Function URL). CloudFront gives a URL that never changes even if the underlying Function
URL id is regenerated, and locks the origin: the Function URL is `AWS_IAM`-auth and only
the CloudFront distribution may invoke it (via Origin Access Control), so the raw
`*.lambda-url.on.aws` URL is not directly reachable. Defense-in-depth on top of the in-code
Slack signature check.

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

## Interactive alerts (buttons)

Attach buttons by adding an `interactive` block to the message:

```json
{
  "target": "slack",
  "source": "idp",
  "sourceDescription": "IdP",
  "content": "Approve deploy to **prod**?",
  "interactive": {
    "callbackId": "deploy-123",
    "payload": "opaque-token-echoed-back",
    "actions": [
      { "id": "approve", "label": "OK", "style": "primary" },
      { "id": "reject",  "label": "Cancel", "style": "danger" }
    ]
  }
}
```

- `id` is echoed back as the decision's `action`. `style` (`primary`/`danger`) is the producer's choice.
- Keep `payload` small — it rides inside the Slack button value (2000-char cap).

### Response contract (SNS topic `alerting-responses`)

On a click by an allow-listed operator, the responder publishes (with a `source` message attribute):

```json
{
  "source": "idp", "callbackId": "deploy-123", "action": "approve",
  "payload": "opaque-token-echoed-back",
  "user": { "id": "U123", "name": "jsue" }, "channel": "C05...", "ts": "169..."
}
```

Subscribe your own Lambda/SQS to the topic with a filter policy
`{"source":["<your-source>"]}`. Discover the topic ARN from the `responses_topic_arn`
Terraform output, or resolve it in your own stack with a data source:

```hcl
data "aws_sns_topic" "alerting_responses" {
  name = "alerting-responses"
}
```

### One-time Slack setup

1. Set the Slack app **Interactivity → Request URL** to `https://platform-slack-responder.isnan.eu/`
   (also available as the `responder_public_url` Terraform output). CloudFront + the DNS record
   must be deployed first, and the responder must be reachable, so that Slack's URL-verification
   handshake succeeds when you save.
2. SSM params (SecureString): `slack.alerting.signing_secret` (app signing secret), `slack.alerting.operators` (comma-separated `U…` user IDs).
