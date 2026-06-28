# CloudFront Log Analytics — Design

Date: 2026-06-27
Location: `monitoring/` (platform repo)
Status: Approved (UI mockup approved; ready for planning)

## 1. Purpose

A single-user desktop-style app to query CloudFront access logs (Parquet in S3)
via Athena and visualize HTTP access: a world geo map of callers and request
histograms over time. It runs as **one local Go binary** that authenticates with
the operator's **AWS IAM Identity Center** identity, embeds and serves a React
SPA on localhost, and opens the browser automatically. Lives under `monitoring/`
in the shared platform repo.

## 2. Why local + IAM Identity Center (not a hosted web app)

This tool is for the operator only. Rather than stand up Cognito + CloudFront +
API Gateway + Lambda for one user, the app runs **locally** and authenticates
with the AWS identity the operator already has in **IAM Identity Center**:

- **No app-level identity provider.** Access is gated by the operator's AWS SSO
  session and IAM permissions — only someone holding live IdC credentials can
  run queries. Network-independent (works from any network), device-bound to
  wherever the SSO session lives.
- **Athena still runs in AWS.** "Local" refers only to the orchestrating binary
  and the UI; data never leaves AWS. The binary signs Athena/Glue/S3 API calls
  with SigV4 using the IdC-derived temporary credentials.
- **One command.** The binary performs the SSO **OIDC device authorization
  flow** itself (no AWS CLI dependency): on a warm token cache it starts
  silently; when the token is expired it opens the browser once to approve, then
  proceeds.

## 3. Context & constraints

- **Logs are produced by CloudFront standard logging v2:** delivered to S3 as
  `output_format = "parquet"`, `enable_hive_compatible_path = true`,
  `suffix_path = {yyyy}/{MM}/{dd}` → objects land at
  `s3://<bucket>/<prefix>/year=YYYY/month=MM/day=DD/`.
- **One bucket per app.** A bucket may hold more than one log source under
  different prefixes (e.g. `brigitte-leroux` → `raw/cms` and `raw/site`). The
  prefix is whatever the delivery destination suffix was set to — **not**
  necessarily the app name.
- **Confirmed Parquet columns** (`record_fields`):
  `date, time, c-ip, c-country, asn, cs-method, cs-protocol, cs(Host),
  cs-uri-stem, cs-uri-query, sc-status, x-edge-result-type, x-edge-location,
  cs(User-Agent)`. `c-country` and `asn` are present → country + network come
  free; MaxMind is needed only for city/lat-long drill-down.
- **90-day retention.** Log buckets have a 90-day S3 lifecycle expiry, so all
  queries are bounded to the last 90 days. Day is the finest granularity.
- **Single user.** No multi-tenant, no app login UI.
- **Live queries** against Athena per request, cached briefly in-process.
- **Platform conventions:** Go (1.26), Terraform (`~> 6.0`, eu-central-1),
  React 18 + Vite 8 + Tailwind v4, `yarn`, strict versions, `dayjs`,
  JavaScript/JSX only (no TypeScript).

## 4. Architecture

```
$ monitoring                       # one self-contained Go binary
  │
  ├─ ssoauth.Login()  ── native SSO OIDC device flow (ssooidc/sso SDK)
  │     warm cache → silent; expired → opens browser to approve once
  │     → aws.Config with IdC temporary credentials
  │
  ├─ HTTP server on 127.0.0.1:<auto>   # binds port 0 → OS picks a free port
  │     /          → embedded React SPA (//go:embed)
  │     /api/*     → handlers → Athena (SigV4 with IdC creds)
  │
  └─ browser.OpenURL("http://127.0.0.1:<actual-port>")

                      Athena (in AWS)
                        ├─ Glue Data Catalog (table defs, partition projection)
                        ├─ scans Parquet in per-app S3 buckets (date-pruned)
                        └─ writes to the monitoring results bucket

  GeoIP: MaxMind GeoLite2 City .mmdb read from a LOCAL file (no S3)
```

### Repo layout

```
monitoring/
├── packages/
│   ├── app/             # Go binary: SSO auth, embedded SPA server, Athena client
│   ├── web/             # React 18 + Vite 8 + Tailwind v4 + ECharts (own package.json)
│   └── infrastructure/  # Terraform (Glue, Athena workgroup, results bucket)
├── Makefile             # build the binary (embeds SPA) + deploy the data layer
└── CLAUDE.md
```

No root `package.json` under `monitoring/` (only `packages/web/`). The `Makefile`
uses hyphenated targets (Make forbids `:`): `backend-build`, `backend-run`,
`frontend-build`, `frontend-serve`, `infra-plan`, `infra-apply`, `infra-output`.

## 5. Backend (Go binary — `packages/app`)

Single binary, module `isnan.eu/monitoring`. Internal packages:

- `internal/ssoauth` — native SSO OIDC device authorization flow
  (`ssooidc:RegisterClient` → `StartDeviceAuthorization` → open browser → poll
  `CreateToken`), token cached under `os.UserCacheDir()/monitoring`; then
  `sso:GetRoleCredentials` → an `aws.CredentialsProvider` (wrapped in
  `aws.NewCredentialsCache`). SSO config (start URL, SSO region, account id,
  role name) from flags/env. **No AWS CLI dependency.**
- `internal/config` — env: `REGION`, `ATHENA_DATABASE`, `ATHENA_WORKGROUP`,
  `GEOIP_DB_PATH` (local `.mmdb`, default `./GeoLite2-City.mmdb` — process CWD),
  `GEOIP_LICENSE_KEY`, `GEOIP_AUTO_UPDATE` (default true), `LOG_SOURCES`
  (JSON `[{name,table}]`).
- `internal/geo` — MaxMind resolver **with auto-update** (default on): on
  startup downloads `GeoLite2-City` to `GEOIP_DB_PATH` if missing or stale
  (compares MaxMind's published `tar.gz.sha256` against a stored sidecar — no
  re-download when unchanged), then a 24h background ticker refreshes and
  **hot-swaps** the in-memory reader (RWMutex-guarded). No external `geoipupdate`
  binary. Auto-update needs only `GEOIP_LICENSE_KEY`; with no key (or on download
  failure) it falls back to any existing file, and with no DB at all the
  country drill-down simply returns no points (world view still works off
  `c-country`).
- `internal/query` — parameterized, partition-pruned SQL builders.
- `internal/athena` — start → poll → fetch wrapper (`Querier` interface).
- `internal/geo` — MaxMind GeoLite2 City resolver (`Resolver` interface).
- `internal/cache` — in-memory TTL cache.
- `internal/handlers` — Gin handlers + embedded-SPA serving.
- `internal/web` — `//go:embed` of the built SPA (`dist` copied in by the Makefile).

Endpoints (served on `127.0.0.1`, no auth — the process is gated by the SSO login):

| Endpoint | Purpose |
|---|---|
| `GET /api/sources` | List configured log sources for the selector. |
| `GET /api/access?source=&from=&to=&groupBy=day\|week\|month` | Time-bucketed request counts split by status class. |
| `GET /api/geo?source=&from=&to=` | World view: caller totals per country (from `c-country`). |
| `GET /api/geo?source=&from=&to=&country=XX` | Drill-down: per-IP points (MaxMind resolves `c-ip` → lat/long). |
| `GET /api/summary?source=&from=&to=` | Totals: requests, unique IPs, countries, error rate, top URIs. |

- **SQL:** always partition-pruned (`year/month/day` predicate from `from`/`to`),
  positional `?` parameters — no string interpolation of user input. Unknown
  source → 404; bad date/`groupBy` → 400; Athena failure → 502.
- **Geo:** world view uses `c-country` directly (no MaxMind); drill-down filters
  `c-country = 'XX'`, groups by `c-ip`, resolves each via the local MaxMind DB.

## 6. Frontend (React 18 + Vite 8 + Tailwind v4 + ECharts)

Styling stack: Tailwind **v4** via `@tailwindcss/vite` (CSS-first, `@import
"tailwindcss"` + `@theme` tokens — no `tailwind.config.js`/PostCSS), a `cn()`
helper (`clsx` + `tailwind-merge`), `class-variance-authority`, `lucide-react`,
and hand-rolled components in `src/components/ui/` (`Button`, `Card`, `Select`,
`ToggleGroup`) — no shadcn CLI, no Radix. **ECharts** powers the geo map +
histograms. **No auth library** (the app is served locally and gated by the SSO
login at process start); the API client calls same-origin `/api/*` with no token.

### Approved visual direction

Canonical mockup: **`docs/ui-design/monitoring.html`**. The React build reproduces it.

- **Aesthetic — "tactical telemetry console":** near-black obsidian base, faint
  tactical grid + grain, corner-tick panel framing.
- **Color:** phosphor-lime (`#c8f135`) single signal accent; HTTP status severity
  the only other color — blue `#5b9bff` (3xx), amber `#ffb020` (4xx), red
  `#ff5a5a` (5xx), lime (2xx).
- **Typography:** Archivo (display) + IBM Plex Mono (telemetry readouts) + IBM
  Plex Sans (body).
- **Layout:** header (source selector, date range, Day/Week/Month toggle) → KPI
  row (Total Requests, Unique Callers, Error Rate, Countries) → map panel (left) +
  right rail (Status Mix donut + Top URIs) → stacked-status histogram bottom.
- **Geo interaction:** lime `effectScatter` blips per country sized by caller
  total; click a country → map focuses on it (cyan outline), blips become per-IP
  points, breadcrumb `Global View ▸ Country`, Top-URIs list swaps to Top Callers.
  Back returns to the world view.

Dev runs Vite on fixed port **5180** (proxy `/api` → `127.0.0.1:8080`); the built
SPA is embedded into the binary for normal use. Not a PWA.

## 7. Infrastructure (Terraform — slim)

The cloud footprint is just the data layer (no compute, no CDN, no auth infra):

- **Glue Data Catalog:** database `monitoring` + one table per log source
  (`for_each` over `{name, bucket, prefix}`), Parquet SerDe, partition projection
  on `year/month/day`. No crawler, no ETL.
- **Athena workgroup** `platform-monitoring` (Glue DB likewise `platform-monitoring`) with a results bucket
  `<account-id>-monitoring-athena-results` (`force_destroy = true`) and a
  bytes-scanned cutoff per query.
- Adding a source = one entry in `var.log_sources` + `terraform apply`.

IAM for the operator's IdC identity (Athena/Glue/S3 lifecycle) is managed
**outside** this repo by the operator and is not part of this design.

## 8. Out of scope (v1)

- Hosted/public web access (Cognito, CloudFront, API Gateway, Lambda).
- Multi-tenant / per-source access control.
- Pre-aggregated rollup tables.
- Hour-level granularity (day is finest).
- Metrics beyond geo map + time histogram + summary cards.

## Unresolved questions

1. Exact Parquet physical column types (string vs typed) — verified against a
   sample file during implementation; affects `CAST` usage in the SQL builder.
2. MaxMind license: confirm a free GeoLite2 account/license key for the local
   `.mmdb` download.
