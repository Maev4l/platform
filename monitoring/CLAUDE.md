# Platform Monitoring — CloudFront Log Analytics

A single local Go binary that authenticates with your AWS IAM Identity Center
identity, embeds + serves a React SPA on localhost, queries CloudFront access
logs (Parquet in S3) via Athena, and opens the dashboard in your browser.

## Layout
- `packages/app` — Go binary. SSO device-flow auth (`internal/ssoauth`), Athena
  client, GeoIP (local MaxMind), Gin API + embedded SPA. Logging via **zerolog**.
  CLI/config uses **cobra** (commands/flags) + **koanf** (merges env + CLI flags).
  Endpoints: `/api/sources,/access,/geo,/summary`.
- `packages/infrastructure` — Terraform: Glue partition-projection tables,
  Athena workgroup (`platform-monitoring`), results bucket.
- `packages/web` — React 18 + Vite + Tailwind v4 + ECharts. Lints with **oxlint**
  (`.oxlintrc.json`).

## Auth
No app login. The binary runs the SSO OIDC device flow at startup (browser
approve on a cold/expired token cache; silent otherwise), gets IdC temporary
credentials, and queries Athena with them. Serves only on 127.0.0.1.
Configure via env/flags: `MONITORING_SSO_START_URL`, `MONITORING_SSO_REGION`,
`AWS_ACCOUNT_ID`, `MONITORING_SSO_ROLE`. (The IAM permissions on your IdC
identity are managed separately.)

## Data model
Each log source = `{name, table}` in `var.log_sources` → one Glue table with
partition projection on `year/month/day`. Add a source via a map entry +
`terraform apply`.

## GeoIP
MaxMind GeoLite2 City `.mmdb` as a LOCAL file (`GEOIP_DB_PATH`, default
`./GeoLite2-City.mmdb`). Used only for country drill-down; the world view uses
`c-country`. Refresh = re-download the file.

## Build / run (from monitoring/)
- `make backend-build` — build SPA, embed it, build the binary
- `make frontend-serve` — Vite dev server (proxies /api → 127.0.0.1:8080)
- `make backend-run` — run the Go server locally (dev)
- `make infra-plan` / `make infra-apply` / `make infra-output`

## Constraints
90-day log retention bounds all queries. Day is the finest granularity.
Frontend is JS/JSX (no TS).

## UI Design Reference
See `docs/ui-design/monitoring.html` for the design mockup.
