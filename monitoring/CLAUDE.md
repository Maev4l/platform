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
Each log source is an entry in `var.log_sources` (key = name, value =
`{bucket, prefix}`) → one Glue table named `replace(name,'-','_')` with
partition projection on `year/month/day`. The binary's `LOG_SOURCES` env
(`[{name,table}]`) comes from the `log_sources_env` output. Add a source via a
map entry (see `packages/infrastructure/terraform.tfvars`) + `terraform apply`.

## Config (.env)
Runtime settings come from env vars (parsed by koanf). `make run` auto-loads a
gitignored `packages/app/.env` (template: `packages/app/.env.example`) and falls
back to `terraform output -raw log_sources_env` for `LOG_SOURCES`. Copy
`.env.example` → `.env` and fill it. Secrets (`.env`, `GeoIP.conf`, the `.mmdb`)
are gitignored.

## GeoIP
MaxMind GeoLite2 City `.mmdb` (`GEOIP_DB_PATH`, default `./GeoLite2-City.mmdb`).
**Auto-downloaded at startup** (default on) when missing or stale, using
`GEOIP_LICENSE_KEY` (the `download.maxmind.com` permalink authenticates by
`license_key` query param — no account id / basic auth); a `tar.gz.sha256`
sidecar avoids re-downloading when unchanged. Startup-only (no background
refresh). Used only for the country drill-down — the world view uses
`c-country`, so the app runs fine without it.

## Build / run (from monitoring/)
- `make run` — **one command to run the app**: builds the SPA, embeds it, builds
  the binary, and runs it (real UI, auto-port, opens the browser). Loads
  `packages/app/.env`.
- `make backend-build` — build SPA, embed it, build the binary (no run)
- Hot-reload dev (two terminals): `make backend-run` (API on :8080) +
  `make frontend-serve` (Vite on :5180, proxies /api → :8080); open :5180.
- `make infra-plan` / `make infra-apply` / `make infra-output`

## Constraints
90-day log retention bounds all queries. Day is the finest granularity.
Frontend is JS/JSX (no TS).

## UI Design Reference
See `docs/ui-design/monitoring.html` for the design mockup.
