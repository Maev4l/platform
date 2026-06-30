# Cost Report → Slack — Design

## Summary

A new `cost-report/` service: a Go Lambda that queries AWS Cost Explorer,
renders a Markdown cost summary, and publishes it to the existing
`alerting-events` SNS topic. The existing `alerter` consumer turns that into a
Slack message. The report runs weekly (Monday 06:00 UTC) and on demand via
`aws lambda invoke`.

`cost-report` is a **producer** on the existing alerting pipeline — it contains
no Slack, webhook, or table-rendering code. All Slack delivery and Markdown →
Slack rendering (including monospace code blocks) is already handled by the
`alerter` Lambda.

## Goals

- Weekly automated AWS cost summary delivered to Slack.
- On-demand generation via `aws lambda invoke` (same Lambda, no extra infra).
- Reuse the existing `alerting-events` → `alerter` → Slack pipeline.
- Reuse the shared `notifications.Message` contract.
- Infrastructure built only from the common `terraform-modules`.

## Non-goals

- No new Slack app, webhook, or channel routing (uses the alerter's channel).
- No API Gateway / Function URL / Slack slash command.
- No persistence or historical storage of cost data.

## AWS account prerequisites (one-time, manual)

1. **Enable Cost Explorer** in the Billing & Cost Management console. Data takes
   ~24h to backfill after first enabling.
2. The **Cost Explorer API** bills **$0.01 per request** (~4 requests per run).

## Message format

The Lambda produces a single Markdown document. The current month label comes
from `time.Now().UTC()` formatted as `January 2006`. Example for June 2026:

```
# 💸 AWS Cost Report June 2026

- **Credits applied (MTD):** $4.58
- **Forecasted gross:** $22.74
- **Credits used YTD:** $245.53

### Top 10 Services (Gross MTD)

​```
Simple Storage Service        $2.06   45%
Key Management Service        $1.08   23%
EC2 - Other                   $0.59   13%
...
​```
```

Format rules:

- Header bullets are bold-labelled (`**Label:**`) so the alerter renders them
  bold.
- The Top-10 list is a **fenced code block** (not a GFM table): no header row,
  fixed-width columns, monospace. Service names are truncated to a fixed width;
  cost is right-aligned as `$X.XX`; percentage is rounded to an integer `%`.
  A code block reproduces the fixed-width, header-less, truncated look exactly.
- 10 rows fit comfortably within Slack's 3000-char section limit, so no chunking
  is required.

## Metric definitions (Cost Explorer)

All amounts use `UnblendedCost`. "MTD" = month-to-date (1st of current month →
today). "YTD" = year-to-date (Jan 1 → today). "Gross" = before credits.

| Line                   | Query                                                                                              |
| ---------------------- | -------------------------------------------------------------------------------------------------- |
| Credits applied (MTD)  | `GetCostAndUsage`, MTD, `UnblendedCost`, filter `RECORD_TYPE = Credit`. Shown as absolute value.   |
| Forecasted gross       | `GetCostForecast`, full current month, metric `UNBLENDED_COST`.                                     |
| Credits used YTD       | `GetCostAndUsage`, Jan 1 → today, `UnblendedCost`, filter `RECORD_TYPE = Credit`. Absolute value.  |
| Top 10 Services (gross)| `GetCostAndUsage`, MTD, `GroupBy = SERVICE`, `UnblendedCost`, filter `RECORD_TYPE = Usage`. Sort desc, take 10, each `%` of the gross MTD total. |

Cost Explorer is a global service reached via **us-east-1**; the CE client is
pinned to that region while the Lambda itself runs in eu-central-1.

## Components

### 1. Lambda handler (`function/cmd/main.go`)

- Go, `arm64`, zip-packaged (`provided.al2023`, `bootstrap`), logging via
  zerolog.
- Triggered identically by the scheduler and by `aws lambda invoke` — no event
  payload is read, so both paths produce the same report.
- Runs the four CE queries (CE client pinned to us-east-1), builds the Markdown,
  then publishes a `notifications.Message` to `alerting-events`:
  `{ target: "slack", source: "cost-report", sourceDescription: "", content: <markdown>, format: "markdown" }`.
  `sourceDescription` is empty so the alerter adds no context line above the
  heading.
- The SNS topic ARN is supplied via an environment variable.

### 2. Markdown builder (pure function, unit-tested)

- Separated from AWS calls so it is testable without the CE/SNS clients.
- Inputs: month label, the three header amounts, and the ordered top-10 service
  list (name + amount + percent). Output: the Markdown string above.
- Responsibilities: currency formatting (`$X.XX`), integer percentage rounding,
  service-name truncation to fixed width, column alignment.

### 3. Infrastructure (`infrastructure/`, Terraform, eu-central-1)

- `lambda-function` module (`github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.6.0`):
  zip filename `../function/dist/cost-report.zip`, `architecture = "arm64"`,
  `hash = filebase64sha256("../function/bin/bootstrap")` (binary hash, not zip).
- `lambda-trigger-scheduler` module (`?ref=v1.6.0`):
  `schedule_expression = "cron(0 6 ? * MON *)"`, `timezone = "UTC"`,
  `flexible_time_window = 0`.
- `data "aws_sns_topic" "alerting"` (name `alerting-events`) → topic ARN passed
  as the Lambda env var.
- IAM policy granting `ce:GetCostAndUsage`, `ce:GetCostForecast`, and
  `sns:Publish` (scoped to the topic ARN), attached via the lambda-function
  module's `additional_policy_arns` (same pattern as the alerter's SSM policy).
- S3 backend, `~> 6.0` AWS provider, `default_tags` with
  `application = "platform-cost-report"` — mirroring the alerter's `main.tf`.

### 4. Tooling

- `function/Makefile`: build the arm64 binary + zip (mirrors the alerter's
  Makefile).
- `package.json`: scripts for build, terraform apply, and a manual-invoke script
  wrapping `aws lambda invoke`.
- `README.md`: purpose, the four metric definitions, AWS prerequisites, and how
  to trigger manually.

## Error handling

- Any CE or SNS failure is logged (zerolog) and returned from the handler, so it
  surfaces in CloudWatch and triggers the scheduler's retry.
- On failure, additionally publish a short `format: "plain"` message to the same
  `alerting-events` topic, so a broken report is visible in Slack rather than
  failing silently.

## Testing

- Table-driven unit tests on the Markdown builder: fixed inputs → expected
  Markdown string. Cover currency formatting, integer percentages, name
  truncation, and the month/year label.
- The CE client sits behind a small interface so the handler logic can be
  exercised with a mock returning canned responses.

## Folder layout

```
cost-report/
├── function/
│   ├── cmd/main.go
│   ├── cmd/report_test.go
│   ├── go.mod                # requires github.com/Maev4l/platform/notifications v1.1.0
│   ├── go.sum
│   ├── Makefile
│   ├── bin/                  # git-ignored (bootstrap)
│   └── dist/                 # git-ignored (cost-report.zip)
├── infrastructure/
│   ├── main.tf               # provider, backend, lambda-function + scheduler modules
│   ├── iam.tf                # ce + sns:Publish policy
│   ├── variables.tf
│   └── .gitignore
├── README.md
└── package.json
```

## Dependencies

- `github.com/Maev4l/platform/notifications v1.1.0` (shared message contract).
- `github.com/aws/aws-sdk-go-v2` (config, costexplorer, sns).
- `github.com/aws/aws-lambda-go` (handler).
- `github.com/rs/zerolog` (logging).

## Open questions

None.
