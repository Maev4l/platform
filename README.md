# Platform

A monorepo of small, shareable and re-usable services and libraries. Everything
runs on AWS in `eu-central-1` and is provisioned with **Terraform**.

The pieces are loosely coupled through a single **`alerting-events` SNS topic**:
producers publish a shared message; the `alerter` consumes it and delivers to
Slack.

```
                          publish notifications.Message
  idp ──────────┐         (target:"slack", markdown/plain)
  cost-report ──┼──▶  SNS: alerting-events  ──▶  alerter  ──▶  Slack
  (your apps) ──┘
```

## Services & libraries

| Component            | Type                          | Purpose                                                        |
| -------------------- | ----------------------------- | -------------------------------------------------------------- |
| `notifications`      | Go library                    | Shared SNS message contract for the alerting pipeline.         |
| `users-management`   | Go library + default Lambda   | Reusable Cognito trigger handler.                              |
| `idp`                | Lambda + infra                | Cognito user pool with per-app, admin-approval sign-up flow.   |
| `alerter`            | Lambda + infra                | Routes `alerting-events` messages to Slack (Markdown-aware).   |
| `cost-report`        | Lambda + infra                | Weekly AWS Cost Explorer summary posted to Slack.              |
| `monitoring`         | Go binary + React SPA + infra | Local CloudFront access-log analytics dashboard over Athena.   |

---

### `notifications` — shared message contract

A tiny Go library (`github.com/Maev4l/platform/notifications`) defining the
single `Message` struct published to the `alerting-events` topic. One source of
truth so producers and the `alerter` consumer can never drift. Fields: `target`
(routing key, e.g. `slack`), `source`, `sourceDescription`, `content` (Markdown
by default), and `format` (`markdown` | `plain`).

### `users-management` — reusable Cognito handler

A Go library (`pkg/cognito`, `pkg/identifier`) plus a default Lambda entrypoint.
Provides a base Cognito trigger handler that other IdP Lambdas embed and
customize via hooks (e.g. `GetNotification`, `ShouldNotifyForApp`). `idp` is the
main consumer.

### `idp` — identity provider

The platform's Cognito user pool Lambda. Wires the `users-management` handler
into Cognito triggers (`pre_sign_up`, `post_confirmation`,
`post_authentication`, `pre_token_generation`) to implement a **per-app approval
workflow**: users self-register, and an admin approves them per application by
adding them to a Cognito group. App → client-id mappings are read from SSM
(`platform.idp.app-clients`); each sign-up and each unapproved access attempt
publishes a Slack notification containing the ready-to-run `aws cognito-idp
admin-add-user-to-group …` command. Includes Terraform for the pool, ACM,
Route53, and IAM.

### `alerter` — Slack delivery

The consumer end of the pipeline. A Lambda subscribed to `alerting-events` that
renders each `notifications.Message` and posts it to Slack. Supports standard
**Markdown** (bold, italic, code, links, lists, blockquotes, headings, and GFM
**tables** as native Slack table blocks) with graceful degradation — oversized
tables become code blocks and any render failure falls back to plain text, so an
alert is never dropped. Set `format:"plain"` for verbatim content. See
[`alerter/README.md`](alerter/README.md).

### `cost-report` — weekly AWS spend summary

A Go Lambda (`platform-cost-report`) that queries **Cost Explorer**, renders a
Markdown summary (credits applied/used, forecasted gross, top-10 services broken
down by usage type), and publishes it to `alerting-events` for Slack delivery.
Runs every Monday 06:00 UTC and on demand. See
[`cost-report/README.md`](cost-report/README.md).

### `monitoring` — CloudFront log analytics

A single local Go binary that authenticates via AWS IAM Identity Center (SSO
device flow), serves an embedded **React 18 + Vite + Tailwind + ECharts** SPA on
`localhost`, and queries **CloudFront access logs** (Parquet in S3) through
**Athena**. Adds GeoIP enrichment (MaxMind GeoLite2 City + ASN) for a world map,
country drill-down, and unique-callers-by-org view. Log sources are
auto-discovered from the Glue catalog. Terraform provisions the Glue tables
(partition projection), Athena workgroup, and results bucket. See
[`monitoring/CLAUDE.md`](monitoring/CLAUDE.md).

---

## Repository layout

```
platform/
├── notifications/     # shared Go library (SNS message contract)
├── users-management/  # reusable Cognito handler library + default Lambda
├── idp/               # Cognito IdP Lambda + infrastructure
├── alerter/           # SNS → Slack Lambda + infrastructure
├── cost-report/       # weekly AWS cost Lambda + infrastructure
├── monitoring/        # CloudFront log analytics (Go binary + web + infra)
└── docs/              # design specs, plans, UI mockups
```

Each service follows the same shape: an application/`function` folder, an
`infrastructure/` Terraform stack, and a `Makefile` for build/deploy.
