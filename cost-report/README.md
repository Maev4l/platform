# Cost Report

Weekly AWS Cost Explorer summary delivered to Slack via the shared
`alerting-events` pipeline. Runs every Monday 06:00 UTC and on demand.

## How it works

A Go Lambda (`platform-cost-report`) queries Cost Explorer, renders a Markdown
summary, and publishes a `notifications.Message{target:"slack", format:"markdown"}`
to the `alerting-events` SNS topic. The `alerter` Lambda renders it to Slack.

## Metrics

All amounts use the `UnblendedCost` metric. MTD = month-to-date, YTD = year-to-date,
gross = before credits.

| Line                    | Source                                                                   |
| ----------------------- | ------------------------------------------------------------------------ |
| Credits applied (MTD)   | `GetCostAndUsage`, current month, `RECORD_TYPE=Credit` (absolute value)  |
| Forecasted gross        | gross MTD usage + `GetCostForecast` for the remainder of the month       |
| Credits used YTD        | `GetCostAndUsage`, Jan 1 → today, `RECORD_TYPE=Credit` (absolute value)  |
| Top 10 Services (gross) | `GetCostAndUsage`, current month, grouped by SERVICE then USAGE_TYPE, `RECORD_TYPE=Usage` |

Each service lists its **top 3 usage types** indented beneath it (e.g. `NatGateway-Hours`),
so you can see what drives the cost. Usage-type region prefixes (`EUC1-`) are stripped
for readability. Services and usage types whose cost rounds to `$0.00` are omitted from
the table, but still counted in the grand total used for percentages and the forecast base.

## AWS prerequisites (one-time)

1. Enable **Cost Explorer** in the Billing console (~24h to backfill data).
2. The Cost Explorer API bills **$0.01 per request** (~4 requests per run).

## Deploy

```bash
make backend-deploy   # package the Lambda zip, then terraform apply
make infra-apply      # apply terraform only (no rebuild)
```

## Manual trigger

```bash
make invoke
```
