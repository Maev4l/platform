# Interactive Slack Alerts — Design

**Date:** 2026-07-03
**Status:** Approved — ready for implementation plan

## Problem

The alerter is one-way today: SNS `alerting_events` → Go Lambda → Slack (outbound only).
We want alerts that carry action buttons (e.g. OK / Cancel). When an operator clicks a
button in Slack, an AWS action must fire. This requires a new **inbound** path from Slack
back into AWS, which does not exist yet.

## Goals

- Producers can attach buttons to an alert via the existing SNS message contract.
- A click triggers a **generic, configurable** outcome — the alerter does not know the
  action; it relays the decision so the originating producer acts on it.
- Only allow-listed Slack users can fire actions.
- Alerter stays **stateless** and decoupled (no per-producer resource coupling, no datastore).

## Non-goals

- Exactly-once under concurrent clicks by different operators (see Double-click, Level 2 —
  explicitly out of scope).
- Large callback payloads (> ~1.5 KB). Escape hatch documented, not built.
- Modals / multi-step Slack interactions. Buttons only.

## Decisions (locked)

| Topic | Decision |
|---|---|
| Action model | Generic/configurable — producer declares context; alerter relays the decision |
| Response delivery | New SNS topic `alerting_responses`; producers subscribe + filter on `source` |
| Authorization | Slack request signature **and** a Slack-user-ID allow-list |
| Button styling | Producer's responsibility (per-button `style` in the message) |
| Unauthorized click | **Ephemeral** rejection; original alert + buttons left intact |
| Anti-double-click | Level 1 only — remove buttons on success via `replace_original`; stateless |
| Inbound compute | Lambda **Function URL** (not API Gateway/LWA), fronted by CloudFront (below) |
| Responder endpoint | Stable custom domain `platform-slack-responder.isnan.eu` → CloudFront → Function URL. Function URL is `AWS_IAM`; only CloudFront (via OAC) may invoke it — raw `*.lambda-url` URL not directly reachable |
| Project layout | `packages/{notifier, responder, infrastructure}` (platform convention) |
| Channel abstraction | Removed — Slack is the only channel; no `Target` interface/registry |

## Project layout (refactor)

Restructure `alerter/` to the platform `packages/` convention. The move is mechanical for
the notifier (module name unchanged → no import edits); only Makefiles and Terraform
paths change.

```
alerter/
├── Makefile                     # root orchestrator (builds both packages, then infra)
├── README.md
└── packages/
    ├── notifier/                # ← today's function/ (SNS consumer, outbound)
    │   ├── Makefile
    │   ├── go.mod / go.sum       # module isnan.eu/notifier (renamed from isnan.eu/alerting post-implementation)
    │   └── cmd/…
    ├── responder/               # NEW inbound handler (button clicks)
    │   ├── Makefile
    │   ├── go.mod / go.sum       # module isnan.eu/responder — own deps, no goldmark/mdslack
    │   └── cmd/…
    └── infrastructure/          # ← today's infrastructure/ (Terraform; backend key unchanged)
        └── *.tf
```

Two **separate Go modules**: the responder needs signature-verify + SNS-publish; the
notifier needs goldmark/mdslack. Splitting keeps each Lambda binary lean with independent
deps.

## Remove the channel abstraction (notifier)

Slack is the only channel, so the multi-target indirection is dead weight. In the notifier:

- **Remove** the `targets.Target` interface, the `TARGETS` map, `GetName()`, and the
  runtime routing in `main.go`.
- `main.go` calls Slack sending directly (a package function) — no registry lookup.
- **Keep** the `target` field in the wire contract (`notifications.Message`) for producer
  backward-compat; the notifier simply sends to Slack (optionally logs a warn if
  `target != "slack"`).
- Flatten `cmd/targets/` → `cmd/slack.go` + retain `cmd/mdslack/`.

## Architecture

```
Producer → SNS alerting_events → notifier (SNS consumer) → Slack message + buttons
                                                                │ user clicks
                                                                ▼
Slack ─POST→ platform-slack-responder.isnan.eu ─► CloudFront ─(OAC/AWS_IAM)─► Function URL ─► responder
                                          ├─ verify signature (replay-safe, ≤5 min)
                                          ├─ check user allow-list
                                          ├─ publish → SNS alerting_responses ──► producer
                                          └─ update original message via response_url
```

Two Go functions under `alerter/packages/`:

- **`notifier/` (existing, moved + simplified)** — SNS consumer. Renders an actions block
  when the message carries an `interactive` block. Otherwise unchanged; channel abstraction
  removed (above).
- **`responder/` (new)** — HTTP handler behind a Lambda Function URL. Single
  responsibility: verify → authorize → publish → acknowledge. Uses
  `events.LambdaFunctionURLRequest`; no Gin/LWA (it is one Slack webhook, and signature
  verification needs the raw body, which Function URLs deliver).

## Message contract (`notifications.Message`)

Add one optional, pointer field. `omitempty` + pointer keeps existing producers' bytes
unchanged (same backward-compat approach as `format`).

```go
type Action struct {
    ID    string `json:"id"`              // action_id, echoed back in the response
    Label string `json:"label"`           // button text
    Style string `json:"style,omitempty"` // "", "primary", "danger" — set by the producer
}

type Interactive struct {
    CallbackID string   `json:"callbackId"`        // producer's correlation id (opaque to alerter)
    Payload    string   `json:"payload,omitempty"` // opaque producer context, echoed back verbatim
    Actions    []Action `json:"actions"`
}

// on Message:
Interactive *Interactive `json:"interactive,omitempty"`
```

`notifications` is a versioned Go module (currently `v1.1.0`). Adding these types →
tag **`v1.2.0`** and bump the require in both `notifier` and `responder` go.mod. Purely
additive, so `v1.1.0` producers keep compiling.

## Callback context — stateless

No datastore. When rendering buttons, each Slack button `value` carries a compact JSON of
everything the handler must echo back:

```json
{"s":"idp","c":"deploy-123","p":"<payload>","a":"approve"}
```

On click, Slack returns the clicked button's `value` → the handler reconstructs the response
without any lookup.

**Constraint:** Slack caps button `value` at 2000 chars, so `payload` must be small (an
id/token, not a blob). If a producer ever needs more, add a DynamoDB lookup keyed by
`callbackId`. **Out of scope now.**

## Response delivery — SNS `alerting_responses`

New topic the alerter owns. On a valid, authorized click the handler publishes:

```json
{
  "source": "idp",
  "callbackId": "deploy-123",
  "action": "approve",
  "payload": "<echoed verbatim>",
  "user": { "id": "U123", "name": "jsue" },
  "channel": "C0544QDSXKQ",
  "ts": "1699999999.000100"
}
```

Published with `source` as an **SNS message attribute** so each producer subscribes its
Lambda/SQS with a filter policy `{"source":["idp"]}`. The topic ARN is a Terraform output
for producers to reference.

**Topic ownership & subscriptions.** The alerter owns both `alerting-events` (inbound) and
`alerting-responses` (outbound). Producers own neither. Subscriptions are **producer-side**:
the alerter exports the responses topic ARN (Terraform output; producers may also resolve it
with a `data "aws_sns_topic"` lookup) and attaches a topic **access policy** granting producers
`sns:Subscribe`; each producer creates its own `aws_sns_topic_subscription` (→ its Lambda/SQS,
with the `source` filter policy) in its own Terraform. The alerter never learns about individual
producers, preserving decoupling.

## Authorization

Two independent gates:

1. **Slack request signature** — HMAC of the raw request body + timestamp using the app's
   signing secret. Rejects forged POSTs to the public Function URL. Reject if the timestamp
   is older than 5 minutes (replay protection). Invalid → HTTP 401, no publish.
2. **User allow-list** — comma-separated Slack user IDs from SSM. Checked against
   `payload.user.id`. Not allowed → **ephemeral** rejection (below), no publish, HTTP 200.

## response_url mechanism

`response_url` is generated by **Slack** and included in the inbound interaction payload — a
short-lived (~30 min), ≤5-use webhook bound to that message + click. The handler POSTs a JSON
body back to it. The handler owns `replace_original` / `response_type`.

**Successful click** — consume the buttons:

```jsonc
POST <response_url>
{ "replace_original": true,
  "blocks": [ /* "✅ Approved by @jsue · 14:32" — no actions block */ ] }
```

**Unauthorized click** — private rejection, alert untouched:

```jsonc
POST <response_url>
{ "response_type": "ephemeral",
  "replace_original": false,
  "text": "❌ You're not authorized to act on this alert." }
```

An expired `response_url` (message handled long ago) → POST fails → log, still return 200.

## Anti-double-click — Level 1 (stateless)

Slack does not disable buttons automatically. On a successful click the handler replaces the
original message (via `response_url`) with a version that has **no actions block** → nothing
left to click. Handles accidental/late re-clicks. Leaves a sub-second race if two operators
click near-simultaneously; accepted, given the small operator allow-list. Level 2 (DynamoDB
conditional write keyed by `callbackId`) is the documented escape hatch, not built.

## SSM parameters

Same path convention and decrypt-on-read as the existing `slack.alerting.token`.

| Param | Purpose |
|---|---|
| `slack.alerting.signing_secret` | Slack signing secret — verify inbound request signatures |
| `slack.alerting.operators` | Comma-separated Slack user IDs — the allow-list |

## Terraform (`alerter/packages/infrastructure/`)

- `aws_sns_topic.alerting_responses` (+ ARN output) with a topic **access policy**
  granting producers `sns:Subscribe` (producers self-subscribe from their own stacks;
  they discover the ARN via the output or a `data "aws_sns_topic"` lookup)
- `platform-notifier-responder` Lambda (arm64, zip, `provided.al2023`) + `aws_lambda_function_url`
  (AuthType **`AWS_IAM`**) — `reserved_concurrent_executions = 5` caps the public path
- **CloudFront + custom domain** (`cdn.tf`): `platform-slack-responder.isnan.eu` → CloudFront →
  the Function URL origin. Origin Access Control (`origin_type = "lambda"`, sigv4) signs origin
  requests so the `AWS_IAM` Function URL accepts only this distribution; an `aws_lambda_permission`
  grants `cloudfront.amazonaws.com` invoke scoped to the distribution ARN. Managed cache policy
  `CachingDisabled` + origin-request policy `AllViewerExceptHostHeader` (forward Slack signature
  headers + body, drop Host). Viewer cert = `*.isnan.eu` ACM (us-east-1, via aliased provider);
  Route53 A/AAAA alias → CloudFront. Output `responder_public_url` = the Slack Request URL.
  (OAC signs origin requests with UNSIGNED-PAYLOAD for POST bodies — fine here: IAM auth still
  authenticates, and body integrity is covered by TLS + the in-code Slack signature. Verify the
  Slack interactivity handshake through the domain at first deploy.)
- IAM for the responder role: `sns:Publish` to `alerting_responses`, SSM read for the two
  new params (no bot token — the responder posts via the pre-authorized `response_url`)
- Existing `platform-notifier` (notifier) zip/hash paths repointed to `../notifier/…`

## Testing

Unit tests:

- Signature verification: valid / bad signature / timestamp > 5 min (replay).
- Payload parsing (Slack `application/x-www-form-urlencoded`, `payload=<json>`).
- Allow-list gate: allowed → publish; not allowed → ephemeral, no publish.
- Button-block rendering, incl. per-button `style` (extend the notifier's existing block
  tests, `slack_blocks_test.go`).
- Response-publish body shape + `source` message attribute.
- Notifier still sends to Slack after the `Target`-abstraction removal (incl. unknown/absent
  `target` — no producer changes required).

## Error handling

| Case | Behavior |
|---|---|
| Invalid signature | HTTP 401, no publish |
| Timestamp > 5 min | HTTP 401 (replay), no publish |
| Unauthorized user | HTTP 200, ephemeral rejection, no publish |
| SNS publish failure | Log, return 200 (avoid Slack retry storms / double publish) |
| Expired `response_url` | Log, return 200 |

## One-time manual Slack setup (document in `alerter/README.md`)

1. Enable **Interactivity** in the Slack app; set Request URL = `https://platform-slack-responder.isnan.eu/`
   (the `responder_public_url` output). CloudFront + DNS must be deployed first so Slack's URL-verification handshake succeeds.
2. Store the signing secret in SSM `slack.alerting.signing_secret`.
3. Store operator Slack user IDs in SSM `slack.alerting.operators`.
4. Bot already has `chat:write` (used to post today).

## Documentation to update

- `alerter/README.md` — new `interactive` contract field, response-topic contract, Slack
  setup steps.
- `notifications` package doc comment — the new `Interactive`/`Action` types.
