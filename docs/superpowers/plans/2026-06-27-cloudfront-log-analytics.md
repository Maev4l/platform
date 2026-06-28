# CloudFront Log Analytics — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single local Go binary that authenticates with the operator's AWS IAM Identity Center identity, embeds + serves a React SPA on localhost, queries CloudFront access logs (Parquet in S3) via Athena, and auto-opens the browser to a geo map + histogram dashboard.

**Architecture:** The binary performs the SSO OIDC device-authorization flow itself (no AWS CLI), obtains IdC temporary credentials, and uses them to run partition-pruned Athena queries. It serves the embedded React build and `/api/*` on `127.0.0.1`. Athena runs in AWS; the laptop only orchestrates and renders. GeoIP is a local MaxMind file.

**Tech Stack:** Go 1.26 + Gin + `embed` + `pkg/browser` + aws-sdk-go-v2 (athena, sso, ssooidc) + `oschwald/geoip2-golang`; Terraform (`~> 6.0`); React 18 + Vite 8 + Tailwind v4 + ECharts (JavaScript/JSX only).

## Global Constraints

- **Language:** Backend Go 1.26. Frontend **JavaScript/JSX only — NO TypeScript**. Fat-arrow functions. `dayjs` (never `moment`).
- **Frontend styling:** Tailwind **v4** via `@tailwindcss/vite` (CSS-first; `@import "tailwindcss"` + `@theme` in `index.css`; NO `tailwind.config.js`/`postcss.config.js`). `cn()` in `src/lib/utils.js` (`clsx`+`tailwind-merge`). `class-variance-authority` for variants. `lucide-react` icons. Hand-rolled components in `src/components/ui/` (capitalized files). `@` alias → `src/`.
- **Package manager:** `yarn` (never `npm`). Strict versions in `package.json` (no `^`/`~`).
- **AWS region:** `eu-central-1` for Athena/Glue/S3. The IdC SSO region may differ and is configured separately.
- **No app-level auth:** the binary serves only on `127.0.0.1`; access is gated by the SSO login at process start. No Cognito/JWT/login UI.
- **No AWS CLI dependency:** SSO login is implemented natively via `ssooidc`/`sso`.
- **Data window:** logs have a 90-day S3 expiry; all queries bounded to the last 90 days. Day is the finest granularity.
- **No root `package.json`** under `monitoring/` — only `packages/web/`. Makefile uses hyphenated targets (Make forbids `:`).
- **Spec:** `docs/superpowers/specs/2026-06-27-cloudfront-log-analytics-design.md`. **UI reference (canonical):** `docs/ui-design/index.html`.

---

## File Structure

```
monitoring/
├── Makefile                         # backend-build (embeds SPA), backend-run, frontend-*, infra-*
├── CLAUDE.md
├── packages/
│   ├── app/                         # Go binary
│   │   ├── go.mod / go.sum
│   │   ├── Makefile                 # build (copies web/dist + go build), run, test, lint
│   │   ├── bin/ (gitignored)        # monitoring binary
│   │   ├── cmd/main.go              # ssoauth → config → server → embed → open browser
│   │   └── internal/
│   │       ├── ssoauth/ssoauth.go   # native SSO OIDC device flow → aws.CredentialsProvider
│   │       ├── config/config.go     # env parsing, source registry
│   │       ├── athena/client.go     # start/poll/fetch wrapper (+ Querier iface)
│   │       ├── query/builder.go     # partition-pruned SQL builders
│   │       ├── geo/resolver.go      # MaxMind GeoLite2 lookups (+ Resolver iface)
│   │       ├── cache/cache.go       # in-memory TTL cache
│   │       ├── handlers/handlers.go # /api/sources,/access,/geo,/summary + SPA serving
│   │       └── web/embed.go         # //go:embed dist (SPA copied in by Makefile)
│   ├── infrastructure/              # Terraform root
│   │   ├── main.tf provider.tf variables.tf outputs.tf
│   │   ├── athena.tf glue.tf s3.tf
│   └── web/                         # React 18 + Vite 8 + Tailwind v4 + ECharts
│       ├── package.json vite.config.js eslint.config.js jsconfig.json index.html
│       └── src/
│           ├── main.jsx App.jsx index.css
│           ├── lib/ (api.js, utils.js, world.js)
│           ├── components/ui/ (Button.jsx, Card.jsx, Select.jsx, ToggleGroup.jsx)
│           └── components/ (Header, Kpis, GeoMap, Histogram, StatusDonut, TopList)
```

---

## Task 1: Scaffold Go binary — local server, embedded SPA, Makefiles

**Files:**
- Create: `monitoring/packages/app/go.mod`, `Makefile`, `.gitignore`, `cmd/main.go`
- Create: `monitoring/packages/app/internal/web/embed.go`, `internal/web/dist/index.html` (placeholder)
- Create: `monitoring/packages/app/internal/handlers/health_test.go`
- Create: `monitoring/Makefile`, `monitoring/.gitignore`

**Interfaces:**
- Produces: `main` serving the embedded SPA + `GET /api/health` → `200 {"status":"ok"}` on `127.0.0.1:8080`.

- [ ] **Step 1: Init the module + dependencies**

```bash
cd monitoring/packages/app
go mod init isnan.eu/monitoring
go get github.com/gin-gonic/gin@v1.10.0
go get github.com/rs/zerolog@v1.33.0
go get github.com/pkg/browser@v0.0.0-20240102092130-5ac0b6a4141c
go get github.com/aws/aws-sdk-go-v2@v1.32.6
go get github.com/aws/aws-sdk-go-v2/config@v1.28.6
go get github.com/aws/aws-sdk-go-v2/credentials@v1.17.47
go get github.com/aws/aws-sdk-go-v2/service/athena@v1.49.0
go get github.com/aws/aws-sdk-go-v2/service/sso@v1.24.7
go get github.com/aws/aws-sdk-go-v2/service/ssooidc@v1.28.6
go get github.com/oschwald/geoip2-golang@v1.11.0
```

- [ ] **Step 2: Placeholder SPA so `//go:embed` always builds**

Create `monitoring/packages/app/internal/web/dist/index.html`:

```html
<!doctype html><meta charset="utf-8"><title>monitoring</title>
<body>SPA not built yet — run <code>make frontend-build</code> then <code>make backend-build</code>.</body>
```

- [ ] **Step 3: Embed + static handler**

Create `monitoring/packages/app/internal/web/embed.go`:

```go
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var dist embed.FS

// FS returns the embedded SPA build rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}

// Handler serves the SPA, falling back to index.html for client-side routes.
func Handler() http.Handler {
	root := FS()
	fileServer := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fs.Stat(root, trimLeadingSlash(r.URL.Path)); err != nil {
			// not a real file → SPA entrypoint
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

func trimLeadingSlash(p string) string {
	if p == "/" || p == "" {
		return "index.html"
	}
	if p[0] == '/' {
		return p[1:]
	}
	return p
}
```

- [ ] **Step 4: Write the failing health test**

Create `monitoring/packages/app/internal/handlers/health_test.go`:

```go
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/health", Health)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/health", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != `{"status":"ok"}` {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 5: Run the test (fails: undefined Health)**

Run: `cd monitoring/packages/app && go test ./internal/handlers/`
Expected: FAIL — `undefined: Health`.

- [ ] **Step 6: Minimal handlers + main**

Create `monitoring/packages/app/internal/handlers/handlers.go`:

```go
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Health(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) }
```

Create `monitoring/packages/app/cmd/main.go`:

```go
package main

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"isnan.eu/monitoring/internal/handlers"
	"isnan.eu/monitoring/internal/web"
)

func main() {
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	r := gin.New()
	r.Use(gin.Recovery())
	r.GET("/api/health", handlers.Health)
	r.NoRoute(gin.WrapH(web.Handler())) // serve embedded SPA for everything else

	addr := "127.0.0.1:8080"
	log.Info().Msgf("serving on http://%s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal().Err(err).Msg("server exited")
	}
}
```

- [ ] **Step 7: Run the test (passes) + build**

Run: `cd monitoring/packages/app && go test ./internal/handlers/ && go build ./...`
Expected: PASS; build OK.

- [ ] **Step 8: app Makefile**

Create `monitoring/packages/app/Makefile`:

```makefile
BIN_DIR := bin

.PHONY: build run test lint clean

# Build the native binary (SPA must already be copied into internal/web/dist).
build:
	go build -ldflags="-s -w" -o $(BIN_DIR)/monitoring ./cmd

# Dev: serves on 127.0.0.1:8080 (matches Vite's /api proxy). Task 9 adds the
# --addr flag + auto-port to the binary and updates this target accordingly.
run:
	go run ./cmd

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BIN_DIR)
```

- [ ] **Step 9: app .gitignore**

Create `monitoring/packages/app/.gitignore`:

```
bin/
# Built SPA is copied in at build time; keep only the placeholder.
internal/web/dist/assets/
```

- [ ] **Step 10: top-level Makefile**

Create `monitoring/Makefile`:

```makefile
.PHONY: backend-build backend-run frontend-build frontend-serve \
        infra-plan infra-apply infra-output

INFRA := packages/infrastructure
APP    := packages/app
WEB    := packages/web

# Build the SPA, embed it into the Go module, build the binary.
backend-build: frontend-build
	rm -rf $(APP)/internal/web/dist
	mkdir -p $(APP)/internal/web/dist
	cp -r $(WEB)/dist/. $(APP)/internal/web/dist/
	$(MAKE) -C $(APP) build

# Run locally (dev): triggers SSO login + serves API; pair with frontend-serve.
backend-run:
	$(MAKE) -C $(APP) run

frontend-build:
	yarn --cwd $(WEB) build

frontend-serve:
	yarn --cwd $(WEB) dev

infra-plan:
	terraform -chdir=$(INFRA) plan

infra-apply:
	terraform -chdir=$(INFRA) apply -auto-approve

infra-output:
	terraform -chdir=$(INFRA) output -json
```

- [ ] **Step 11: monitoring/.gitignore**

```
packages/web/node_modules/
packages/web/dist/
packages/infrastructure/.terraform/
```

- [ ] **Step 12: Commit**

```bash
git add monitoring/Makefile monitoring/.gitignore monitoring/packages/app
git commit -m "feat(monitoring): scaffold Go binary (local server + embedded SPA)"
```

---

## Task 2: Config & source registry

**Files:**
- Create: `monitoring/packages/app/internal/config/config.go`
- Test: `monitoring/packages/app/internal/config/config_test.go`

**Interfaces:**
- Produces:
  - `type Source struct { Name, Table string }`
  - `type Config struct { Region, Database, Workgroup, GeoIPPath string; Sources map[string]Source }`
  - `func Load() (*Config, error)` — uses **koanf** (defaults overlaid by env vars): `REGION` (default `eu-central-1`), `ATHENA_DATABASE` (default `monitoring`), `ATHENA_WORKGROUP` (default `monitoring`), `GEOIP_DB_PATH` (default `./GeoLite2-City.mmdb`), `LOG_SOURCES` (JSON `[{"name","table"}]`).
  - `func (c *Config) Source(name string) (Source, bool)`

- [ ] **Step 1: Write the failing test**

```go
package config

import (
	"os"
	"testing"
)

func TestLoadDefaultsAndSources(t *testing.T) {
	os.Unsetenv("REGION")
	os.Setenv("LOG_SOURCES", `[{"name":"bl-site","table":"bl_site"}]`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Region != "eu-central-1" || c.Database != "monitoring" || c.Workgroup != "monitoring" {
		t.Fatalf("bad defaults: %+v", c)
	}
	if s, ok := c.Source("bl-site"); !ok || s.Table != "bl_site" {
		t.Fatalf("source lookup failed: %+v ok=%v", s, ok)
	}
}

func TestLoadBadJSON(t *testing.T) {
	os.Setenv("LOG_SOURCES", "nope")
	if _, err := Load(); err == nil {
		t.Fatal("expected error")
	}
}
```

- [ ] **Step 2: Run (fails)**

Run: `go test ./internal/config/`
Expected: FAIL — `undefined: Load`.

- [ ] **Step 3: Add koanf, then implement with it**

Add the config library (koanf v2 + the confmap and env providers):

```bash
go get github.com/knadh/koanf/v2@v2.1.2
go get github.com/knadh/koanf/providers/confmap@v1.0.0
go get github.com/knadh/koanf/providers/env@v1.1.0
```

(koanf split its providers into separate modules; the `v1.x` provider tags are the ones compatible with koanf `v2` — older `v0.1.0` tags cause an "ambiguous import" error.)

```go
package config

import (
	"encoding/json"
	"fmt"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

type Source struct {
	Name  string `json:"name"`
	Table string `json:"table"`
}

type Config struct {
	Region    string
	Database  string
	Workgroup string
	GeoIPPath string
	Sources   map[string]Source
}

// envMap translates process env var names to koanf keys. Only these are read;
// the env provider's callback returns "" for anything else, which koanf skips.
var envMap = map[string]string{
	"REGION":           "region",
	"ATHENA_DATABASE":  "database",
	"ATHENA_WORKGROUP": "workgroup",
	"GEOIP_DB_PATH":    "geoip_path",
	"LOG_SOURCES":      "log_sources",
}

// Load builds configuration with koanf: defaults overlaid by environment
// variables. LOG_SOURCES is a JSON array of {name,table}.
func Load() (*Config, error) {
	k := koanf.New(".")

	_ = k.Load(confmap.Provider(map[string]interface{}{
		"region":     "eu-central-1",
		"database":   "monitoring",
		"workgroup":  "monitoring",
		"geoip_path": "./GeoLite2-City.mmdb",
	}, "."), nil)

	_ = k.Load(env.Provider("", ".", func(s string) string { return envMap[s] }), nil)

	c := &Config{
		Region:    k.String("region"),
		Database:  k.String("database"),
		Workgroup: k.String("workgroup"),
		GeoIPPath: k.String("geoip_path"),
		Sources:   map[string]Source{},
	}

	if raw := k.String("log_sources"); raw != "" {
		var list []Source
		if err := json.Unmarshal([]byte(raw), &list); err != nil {
			return nil, fmt.Errorf("parse LOG_SOURCES: %w", err)
		}
		for _, s := range list {
			c.Sources[s.Name] = s
		}
	}
	return c, nil
}

func (c *Config) Source(name string) (Source, bool) {
	s, ok := c.Sources[name]
	return s, ok
}
```

**koanf version note:** if the installed koanf's `env.Provider` signature differs from `env.Provider(prefix, delim, callback)`, adjust the call so it compiles AND preserves the behavior (defaults overlaid only by the five mapped env vars; unmapped vars ignored; no spurious empty-string key). Report any such adjustment.

- [ ] **Step 4: Run (passes)**

Run: `go test ./internal/config/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add monitoring/packages/app/internal/config monitoring/packages/app/go.mod monitoring/packages/app/go.sum
git commit -m "feat(monitoring): koanf config loader + source registry"
```

---

## Task 3: Partition-pruned SQL builders

**Files:**
- Create: `monitoring/packages/app/internal/query/builder.go`
- Test: `monitoring/packages/app/internal/query/builder_test.go`

**Column names:** quoted physical Parquet names, centralised as constants so a single edit fixes any discrepancy found during the Task 12 verification query. Partition columns `year/month/day` are zero-padded strings; the predicate concatenates them so a lexicographic `BETWEEN` is correct. All user values are positional `?` parameters.

**Interfaces:**
- Produces:
  - `var ErrBadGroupBy = errors.New("invalid groupBy")`
  - `func Access(table, from, to, groupBy string) (string, []string, error)`
  - `func GeoCountries(table, from, to string) (string, []string)`
  - `func GeoIPs(table, from, to, country string) (string, []string)`
  - `func Summary(table, from, to string) (string, []string)`
  - `func TopURIs(table, from, to string, limit int) (string, []string)`

- [ ] **Step 1: Write the failing test**

```go
package query

import (
	"strings"
	"testing"
)

func TestAccessGroupByDay(t *testing.T) {
	sql, args, err := Access("bl_site", "2026-06-01", "2026-06-27", "day")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, `"bl_site"`) || !strings.Contains(sql, "BETWEEN ? AND ?") || !strings.Contains(sql, "date_trunc('day'") {
		t.Fatalf("bad sql: %s", sql)
	}
	if len(args) != 2 || args[0] != "2026-06-01" || args[1] != "2026-06-27" {
		t.Fatalf("bad args: %v", args)
	}
}

func TestAccessRejectsBadGroupBy(t *testing.T) {
	if _, _, err := Access("t", "a", "b", "hour"); err != ErrBadGroupBy {
		t.Fatalf("want ErrBadGroupBy, got %v", err)
	}
}

func TestGeoCountries(t *testing.T) {
	sql, args := GeoCountries("t", "2026-06-01", "2026-06-27")
	if !strings.Contains(sql, `"c-country"`) || !strings.Contains(strings.ToLower(sql), "group by") || len(args) != 2 {
		t.Fatalf("bad: %s %v", sql, args)
	}
}

func TestGeoIPsFiltersCountry(t *testing.T) {
	sql, args := GeoIPs("t", "2026-06-01", "2026-06-27", "FR")
	if !strings.Contains(sql, `"c-country" = ?`) || !strings.Contains(sql, `"c-ip"`) || len(args) != 3 || args[2] != "FR" {
		t.Fatalf("bad: %s %v", sql, args)
	}
}

func TestSummaryAndTopURIs(t *testing.T) {
	if sql, args := Summary("t", "2026-06-01", "2026-06-27"); !strings.Contains(sql, "count(") || len(args) != 2 {
		t.Fatalf("bad summary: %s %v", sql, args)
	}
	if sql, args := TopURIs("t", "2026-06-01", "2026-06-27", 8); !strings.Contains(sql, "LIMIT 8") || len(args) != 2 {
		t.Fatalf("bad topuris: %s %v", sql, args)
	}
}
```

- [ ] **Step 2: Run (fails)**

Run: `go test ./internal/query/`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement**

```go
package query

import (
	"errors"
	"fmt"
)

var ErrBadGroupBy = errors.New("invalid groupBy")

// Physical Parquet column names (quoted). Centralised: fix here if a name
// differs (Task 12 verification query confirms the real names).
const (
	colDate    = `"date"`
	colIP      = `"c-ip"`
	colCountry = `"c-country"`
	colStatus  = `"sc-status"`
	colURI     = `"cs-uri-stem"`
)

// partitionPredicate prunes scans to [from,to] over the zero-padded
// (year,month,day) string partitions. 2 positional args: from, to.
func partitionPredicate() string {
	return `("year" || '-' || "month" || '-' || "day") BETWEEN ? AND ?`
}

func Access(table, from, to, groupBy string) (string, []string, error) {
	switch groupBy {
	case "day", "week", "month":
	default:
		return "", nil, ErrBadGroupBy
	}
	sql := fmt.Sprintf(`
SELECT date_trunc('%s', date_parse(%s, '%%Y-%%m-%%d')) AS bucket,
       count_if(%s BETWEEN '200' AND '299') AS s2,
       count_if(%s BETWEEN '300' AND '399') AS s3,
       count_if(%s BETWEEN '400' AND '499') AS s4,
       count_if(%s BETWEEN '500' AND '599') AS s5
FROM %q
WHERE %s
GROUP BY 1
ORDER BY 1`, groupBy, colDate, colStatus, colStatus, colStatus, colStatus, table, partitionPredicate())
	return sql, []string{from, to}, nil
}

func GeoCountries(table, from, to string) (string, []string) {
	sql := fmt.Sprintf(`
SELECT %s AS country, count(*) AS callers, count(DISTINCT %s) AS ips
FROM %q
WHERE %s AND %s <> ''
GROUP BY 1
ORDER BY callers DESC`, colCountry, colIP, table, partitionPredicate(), colCountry)
	return sql, []string{from, to}
}

func GeoIPs(table, from, to, country string) (string, []string) {
	sql := fmt.Sprintf(`
SELECT %s AS ip, count(*) AS requests
FROM %q
WHERE %s AND %s = ?
GROUP BY 1
ORDER BY requests DESC
LIMIT 5000`, colIP, table, partitionPredicate(), colCountry)
	return sql, []string{from, to, country}
}

func Summary(table, from, to string) (string, []string) {
	sql := fmt.Sprintf(`
SELECT count(*) AS total,
       count(DISTINCT %s) AS unique_ips,
       count(DISTINCT %s) AS countries,
       count_if(%s BETWEEN '400' AND '599') AS errors
FROM %q
WHERE %s`, colIP, colCountry, colStatus, table, partitionPredicate())
	return sql, []string{from, to}
}

func TopURIs(table, from, to string, limit int) (string, []string) {
	sql := fmt.Sprintf(`
SELECT %s AS uri, count(*) AS hits
FROM %q
WHERE %s
GROUP BY 1
ORDER BY hits DESC
LIMIT %d`, colURI, table, partitionPredicate(), limit)
	return sql, []string{from, to}
}
```

- [ ] **Step 4: Run (passes)**

Run: `go test ./internal/query/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add monitoring/packages/app/internal/query
git commit -m "feat(monitoring): partition-pruned Athena SQL builders"
```

---

## Task 4: In-memory TTL cache

**Files:**
- Create: `monitoring/packages/app/internal/cache/cache.go`
- Test: `monitoring/packages/app/internal/cache/cache_test.go`

**Interfaces:** `func New(ttl time.Duration) *Cache`; `func (c *Cache) Get(key string) ([]byte, bool)`; `func (c *Cache) Set(key string, val []byte)` — concurrency-safe.

- [ ] **Step 1: Write the failing test**

```go
package cache

import (
	"testing"
	"time"
)

func TestSetGet(t *testing.T) {
	c := New(time.Minute)
	c.Set("k", []byte("v"))
	if got, ok := c.Get("k"); !ok || string(got) != "v" {
		t.Fatalf("want v, got %q ok=%v", got, ok)
	}
}

func TestExpiry(t *testing.T) {
	c := New(10 * time.Millisecond)
	c.Set("k", []byte("v"))
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected expiry")
	}
}
```

- [ ] **Step 2: Run (fails)** — `go test ./internal/cache/` → undefined `New`.

- [ ] **Step 3: Implement**

```go
package cache

import (
	"sync"
	"time"
)

type entry struct {
	val []byte
	exp time.Time
}

type Cache struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]entry
}

func New(ttl time.Duration) *Cache { return &Cache{ttl: ttl, m: map[string]entry{}} }

func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	e, ok := c.m[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.val, true
}

func (c *Cache) Set(key string, val []byte) {
	c.mu.Lock()
	c.m[key] = entry{val: val, exp: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}
```

- [ ] **Step 4: Run (passes)** — `go test ./internal/cache/`.

- [ ] **Step 5: Commit**

```bash
git add monitoring/packages/app/internal/cache
git commit -m "feat(monitoring): in-memory TTL cache"
```

---

## Task 5: GeoIP resolver (MaxMind GeoLite2 City)

**Files:**
- Create: `monitoring/packages/app/internal/geo/resolver.go`
- Test: `monitoring/packages/app/internal/geo/resolver_test.go`

**Interfaces:** `type Location struct { City, Country string; Lat, Lng float64 }`; `type Resolver interface { Lookup(ip string) (Location, bool) }`; `func Open(path string) (*MMDB, error)`; `func (m *MMDB) Lookup(ip string) (Location, bool)`; `func (m *MMDB) Close() error`.

- [ ] **Step 1: Write the failing test**

```go
package geo

import "testing"

type fakeResolver struct {
	loc Location
	ok  bool
}

func (f fakeResolver) Lookup(string) (Location, bool) { return f.loc, f.ok }

func TestResolverInterface(t *testing.T) {
	var r Resolver = fakeResolver{loc: Location{City: "Paris", Country: "FR", Lat: 48.85, Lng: 2.35}, ok: true}
	if loc, ok := r.Lookup("1.2.3.4"); !ok || loc.City != "Paris" {
		t.Fatalf("unexpected %+v ok=%v", loc, ok)
	}
}

func TestOpenMissingFile(t *testing.T) {
	if _, err := Open("/no/such/file.mmdb"); err == nil {
		t.Fatal("expected error")
	}
}
```

- [ ] **Step 2: Run (fails)** — `go test ./internal/geo/`.

- [ ] **Step 3: Implement**

```go
package geo

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

type Location struct {
	City    string  `json:"city"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lng     float64 `json:"lng"`
}

type Resolver interface {
	Lookup(ip string) (Location, bool)
}

type MMDB struct{ db *geoip2.Reader }

func Open(path string) (*MMDB, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &MMDB{db: db}, nil
}

func (m *MMDB) Lookup(ipStr string) (Location, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Location{}, false
	}
	rec, err := m.db.City(ip)
	if err != nil || rec == nil || (rec.Location.Latitude == 0 && rec.Location.Longitude == 0) {
		return Location{}, false
	}
	return Location{
		City:    rec.City.Names["en"],
		Country: rec.Country.IsoCode,
		Lat:     rec.Location.Latitude,
		Lng:     rec.Location.Longitude,
	}, true
}

func (m *MMDB) Close() error { return m.db.Close() }
```

- [ ] **Step 4: Run (passes)** — `go test ./internal/geo/`.

- [ ] **Step 5: Commit**

```bash
git add monitoring/packages/app/internal/geo
git commit -m "feat(monitoring): MaxMind GeoLite2 resolver"
```

---

## Task 6: Athena querier wrapper

**Files:**
- Create: `monitoring/packages/app/internal/athena/client.go`
- Test: `monitoring/packages/app/internal/athena/client_test.go`

**Interfaces:**
- `type Querier interface { Query(ctx, sql string, args []string) ([]map[string]string, error) }`
- `type AthenaAPI interface { StartQueryExecution; GetQueryExecution; GetQueryResults }` (SDK subset, for fakes)
- `func New(api AthenaAPI, database, workgroup string) *Client`
- Rows → `[]map[string]string` keyed by column; positional `args` passed via `ExecutionParameters`.

- [ ] **Step 1: Write the failing test with a fake AthenaAPI**

```go
package athena

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	atypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
)

type fakeAPI struct{}

func (fakeAPI) StartQueryExecution(ctx context.Context, in *athena.StartQueryExecutionInput, _ ...func(*athena.Options)) (*athena.StartQueryExecutionOutput, error) {
	return &athena.StartQueryExecutionOutput{QueryExecutionId: aws.String("q1")}, nil
}
func (fakeAPI) GetQueryExecution(ctx context.Context, in *athena.GetQueryExecutionInput, _ ...func(*athena.Options)) (*athena.GetQueryExecutionOutput, error) {
	return &athena.GetQueryExecutionOutput{QueryExecution: &atypes.QueryExecution{
		Status: &atypes.QueryExecutionStatus{State: atypes.QueryExecutionStateSucceeded},
	}}, nil
}
func (fakeAPI) GetQueryResults(ctx context.Context, in *athena.GetQueryResultsInput, _ ...func(*athena.Options)) (*athena.GetQueryResultsOutput, error) {
	row := func(vals ...string) atypes.Row {
		d := make([]atypes.Datum, len(vals))
		for i, v := range vals {
			vv := v
			d[i] = atypes.Datum{VarCharValue: &vv}
		}
		return atypes.Row{Data: d}
	}
	return &athena.GetQueryResultsOutput{ResultSet: &atypes.ResultSet{
		Rows: []atypes.Row{row("country", "callers"), row("FR", "9241")},
	}}, nil
}

func TestQueryMapsRows(t *testing.T) {
	c := New(fakeAPI{}, "monitoring", "monitoring")
	rows, err := c.Query(context.Background(), "SELECT 1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["country"] != "FR" || rows[0]["callers"] != "9241" {
		t.Fatalf("unexpected rows: %v", rows)
	}
}
```

- [ ] **Step 2: Run (fails)** — `go test ./internal/athena/` → undefined `New`.

- [ ] **Step 3: Implement**

```go
package athena

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	atypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
)

type AthenaAPI interface {
	StartQueryExecution(context.Context, *athena.StartQueryExecutionInput, ...func(*athena.Options)) (*athena.StartQueryExecutionOutput, error)
	GetQueryExecution(context.Context, *athena.GetQueryExecutionInput, ...func(*athena.Options)) (*athena.GetQueryExecutionOutput, error)
	GetQueryResults(context.Context, *athena.GetQueryResultsInput, ...func(*athena.Options)) (*athena.GetQueryResultsOutput, error)
}

type Querier interface {
	Query(ctx context.Context, sql string, args []string) ([]map[string]string, error)
}

type Client struct {
	api       AthenaAPI
	database  string
	workgroup string
}

func New(api AthenaAPI, database, workgroup string) *Client {
	return &Client{api: api, database: database, workgroup: workgroup}
}

func (c *Client) Query(ctx context.Context, sql string, args []string) ([]map[string]string, error) {
	params := append([]string(nil), args...)
	start, err := c.api.StartQueryExecution(ctx, &athena.StartQueryExecutionInput{
		QueryString:           aws.String(sql),
		WorkGroup:             aws.String(c.workgroup),
		QueryExecutionContext: &atypes.QueryExecutionContext{Database: aws.String(c.database)},
		ExecutionParameters:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("start query: %w", err)
	}
	id := start.QueryExecutionId

	backoff := 200 * time.Millisecond
	for {
		ex, err := c.api.GetQueryExecution(ctx, &athena.GetQueryExecutionInput{QueryExecutionId: id})
		if err != nil {
			return nil, fmt.Errorf("poll query: %w", err)
		}
		switch ex.QueryExecution.Status.State {
		case atypes.QueryExecutionStateSucceeded:
			return c.fetch(ctx, id)
		case atypes.QueryExecutionStateFailed, atypes.QueryExecutionStateCancelled:
			reason := ""
			if ex.QueryExecution.Status.StateChangeReason != nil {
				reason = *ex.QueryExecution.Status.StateChangeReason
			}
			return nil, fmt.Errorf("query %s: %s", ex.QueryExecution.Status.State, reason)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

func (c *Client) fetch(ctx context.Context, id *string) ([]map[string]string, error) {
	var header []string
	var out []map[string]string
	var token *string
	first := true
	for {
		res, err := c.api.GetQueryResults(ctx, &athena.GetQueryResultsInput{QueryExecutionId: id, NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("fetch results: %w", err)
		}
		rows := res.ResultSet.Rows
		startIdx := 0
		if first && len(rows) > 0 {
			for _, d := range rows[0].Data {
				header = append(header, deref(d.VarCharValue))
			}
			startIdx, first = 1, false
		}
		for _, r := range rows[startIdx:] {
			m := make(map[string]string, len(header))
			for i, d := range r.Data {
				if i < len(header) {
					m[header[i]] = deref(d.VarCharValue)
				}
			}
			out = append(out, m)
		}
		if res.NextToken == nil {
			break
		}
		token = res.NextToken
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
```

- [ ] **Step 4: Run (passes)** — `go test ./internal/athena/`.

- [ ] **Step 5: Commit**

```bash
git add monitoring/packages/app/internal/athena
git commit -m "feat(monitoring): Athena querier (start/poll/fetch)"
```

---

## Task 7: API handlers (sources/access/geo/summary) + SPA serving

**Files:**
- Modify: `monitoring/packages/app/internal/handlers/handlers.go`
- Test: `monitoring/packages/app/internal/handlers/handlers_test.go`

**Interfaces:**
- `type API struct { Cfg *config.Config; Q athena.Querier; Geo geo.Resolver; Cache *cache.Cache }`
- `func (a *API) Register(r *gin.Engine)` — wires `/api/health`, `/api/sources`, `/api/access`, `/api/geo`, `/api/summary`, and the embedded-SPA NoRoute.
- Response shapes: `/sources` → `[]string`; `/access` → `{buckets:[{t,s2,s3,s4,s5}]}`; `/geo` world → `{level:"world",countries:[{country,callers,ips}]}`; `/geo?country=` → `{level:"country",country,points:[{ip,city,lat,lng,requests}]}`; `/summary` → `{total,uniqueIps,countries,errors,errorRate,topUris:[{uri,hits}]}`.
- Validation: unknown source → 404; bad `from`/`to` (not `YYYY-MM-DD`) → 400; bad `groupBy` → 400; Athena error → 502.

- [ ] **Step 1: Write the failing tests (fake Querier + Resolver)**

```go
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"isnan.eu/monitoring/internal/cache"
	"isnan.eu/monitoring/internal/config"
	"isnan.eu/monitoring/internal/geo"
)

type fakeQ struct{ rows []map[string]string }

func (f fakeQ) Query(context.Context, string, []string) ([]map[string]string, error) {
	return f.rows, nil
}

type fakeGeo struct{}

func (fakeGeo) Lookup(string) (geo.Location, bool) {
	return geo.Location{City: "Paris", Country: "FR", Lat: 48.85, Lng: 2.35}, true
}

func newAPI(rows []map[string]string) *API {
	return &API{
		Cfg:   &config.Config{Sources: map[string]config.Source{"bl-site": {Name: "bl-site", Table: "bl_site"}}},
		Q:     fakeQ{rows: rows},
		Geo:   fakeGeo{},
		Cache: cache.New(time.Minute),
	}
}

func do(a *API, url string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	a.Register(r)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	r.ServeHTTP(w, req)
	return w
}

func TestSources(t *testing.T) {
	w := do(newAPI(nil), "/api/sources")
	var got []string
	json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != 200 || len(got) != 1 || got[0] != "bl-site" {
		t.Fatalf("bad sources: %d %v", w.Code, got)
	}
}

func TestUnknownSource404(t *testing.T) {
	if w := do(newAPI(nil), "/api/summary?source=nope&from=2026-06-01&to=2026-06-27"); w.Code != 404 {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestBadDate400(t *testing.T) {
	if w := do(newAPI(nil), "/api/summary?source=bl-site&from=06-2026&to=2026-06-27"); w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestGeoWorld(t *testing.T) {
	rows := []map[string]string{{"country": "FR", "callers": "9241", "ips": "1200"}}
	w := do(newAPI(rows), "/api/geo?source=bl-site&from=2026-06-01&to=2026-06-27")
	var got struct {
		Level     string `json:"level"`
		Countries []struct {
			Country string `json:"country"`
			Callers int    `json:"callers"`
		} `json:"countries"`
	}
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Level != "world" || got.Countries[0].Callers != 9241 {
		t.Fatalf("bad world: %+v", got)
	}
}

func TestGeoDrilldown(t *testing.T) {
	rows := []map[string]string{{"ip": "92.184.105.12", "requests": "842"}}
	w := do(newAPI(rows), "/api/geo?source=bl-site&from=2026-06-01&to=2026-06-27&country=FR")
	var got struct {
		Level  string `json:"level"`
		Points []struct {
			City string  `json:"city"`
			Lat  float64 `json:"lat"`
		} `json:"points"`
	}
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Level != "country" || got.Points[0].City != "Paris" || got.Points[0].Lat != 48.85 {
		t.Fatalf("bad drilldown: %+v", got)
	}
}
```

- [ ] **Step 2: Run (fails)** — `go test ./internal/handlers/` → undefined `API`.

- [ ] **Step 3: Implement handlers**

Replace `monitoring/packages/app/internal/handlers/handlers.go`:

```go
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"isnan.eu/monitoring/internal/athena"
	"isnan.eu/monitoring/internal/cache"
	"isnan.eu/monitoring/internal/config"
	"isnan.eu/monitoring/internal/geo"
	"isnan.eu/monitoring/internal/query"
	"isnan.eu/monitoring/internal/web"
)

type API struct {
	Cfg   *config.Config
	Q     athena.Querier
	Geo   geo.Resolver
	Cache *cache.Cache
}

func Health(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) }

func (a *API) Register(r *gin.Engine) {
	r.GET("/api/health", Health)
	r.GET("/api/sources", a.sources)
	r.GET("/api/access", a.access)
	r.GET("/api/geo", a.geo)
	r.GET("/api/summary", a.summary)
	r.NoRoute(gin.WrapH(web.Handler())) // embedded SPA
}

const dateLayout = "2006-01-02"

func (a *API) validate(c *gin.Context) (config.Source, string, string, bool) {
	src, ok := a.Cfg.Source(c.Query("source"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown source"})
		return config.Source{}, "", "", false
	}
	from, to := c.Query("from"), c.Query("to")
	if _, err := time.Parse(dateLayout, from); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "from must be YYYY-MM-DD"})
		return config.Source{}, "", "", false
	}
	if _, err := time.Parse(dateLayout, to); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "to must be YYYY-MM-DD"})
		return config.Source{}, "", "", false
	}
	return src, from, to, true
}

func (a *API) cached(c *gin.Context, key string, run func(ctx context.Context) (any, error)) {
	if b, ok := a.Cache.Get(key); ok {
		c.Data(http.StatusOK, "application/json; charset=utf-8", b)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	payload, err := run(ctx)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	b, _ := json.Marshal(payload)
	a.Cache.Set(key, b)
	c.Data(http.StatusOK, "application/json; charset=utf-8", b)
}

func (a *API) sources(c *gin.Context) {
	names := make([]string, 0, len(a.Cfg.Sources))
	for n := range a.Cfg.Sources {
		names = append(names, n)
	}
	c.JSON(http.StatusOK, names)
}

func (a *API) access(c *gin.Context) {
	src, from, to, ok := a.validate(c)
	if !ok {
		return
	}
	groupBy := c.DefaultQuery("groupBy", "day")
	sql, args, err := query.Access(src.Table, from, to, groupBy)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "groupBy must be day|week|month"})
		return
	}
	a.cached(c, "access|"+src.Name+"|"+from+"|"+to+"|"+groupBy, func(ctx context.Context) (any, error) {
		rows, err := a.Q.Query(ctx, sql, args)
		if err != nil {
			return nil, err
		}
		buckets := make([]gin.H, 0, len(rows))
		for _, r := range rows {
			buckets = append(buckets, gin.H{"t": r["bucket"], "s2": atoi(r["s2"]), "s3": atoi(r["s3"]), "s4": atoi(r["s4"]), "s5": atoi(r["s5"])})
		}
		return gin.H{"buckets": buckets}, nil
	})
}

func (a *API) geo(c *gin.Context) {
	src, from, to, ok := a.validate(c)
	if !ok {
		return
	}
	country := c.Query("country")
	if country == "" {
		sql, args := query.GeoCountries(src.Table, from, to)
		a.cached(c, "geoW|"+src.Name+"|"+from+"|"+to, func(ctx context.Context) (any, error) {
			rows, err := a.Q.Query(ctx, sql, args)
			if err != nil {
				return nil, err
			}
			out := make([]gin.H, 0, len(rows))
			for _, r := range rows {
				out = append(out, gin.H{"country": r["country"], "callers": atoi(r["callers"]), "ips": atoi(r["ips"])})
			}
			return gin.H{"level": "world", "countries": out}, nil
		})
		return
	}
	sql, args := query.GeoIPs(src.Table, from, to, country)
	a.cached(c, "geoC|"+src.Name+"|"+from+"|"+to+"|"+country, func(ctx context.Context) (any, error) {
		rows, err := a.Q.Query(ctx, sql, args)
		if err != nil {
			return nil, err
		}
		points := make([]gin.H, 0, len(rows))
		for _, r := range rows {
			loc, found := a.Geo.Lookup(r["ip"])
			if !found {
				continue
			}
			points = append(points, gin.H{"ip": r["ip"], "city": loc.City, "lat": loc.Lat, "lng": loc.Lng, "requests": atoi(r["requests"])})
		}
		return gin.H{"level": "country", "country": country, "points": points}, nil
	})
}

func (a *API) summary(c *gin.Context) {
	src, from, to, ok := a.validate(c)
	if !ok {
		return
	}
	sql, args := query.Summary(src.Table, from, to)
	topSQL, topArgs := query.TopURIs(src.Table, from, to, 8)
	a.cached(c, "sum|"+src.Name+"|"+from+"|"+to, func(ctx context.Context) (any, error) {
		rows, err := a.Q.Query(ctx, sql, args)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return gin.H{"total": 0, "uniqueIps": 0, "countries": 0, "errors": 0, "errorRate": 0.0, "topUris": []gin.H{}}, nil
		}
		r := rows[0]
		total, errs := atoi(r["total"]), atoi(r["errors"])
		rate := 0.0
		if total > 0 {
			rate = float64(errs) / float64(total) * 100
		}
		top, err := a.Q.Query(ctx, topSQL, topArgs)
		if err != nil {
			return nil, err
		}
		uris := make([]gin.H, 0, len(top))
		for _, u := range top {
			uris = append(uris, gin.H{"uri": u["uri"], "hits": atoi(u["hits"])})
		}
		return gin.H{"total": total, "uniqueIps": atoi(r["unique_ips"]), "countries": atoi(r["countries"]), "errors": errs, "errorRate": rate, "topUris": uris}, nil
	})
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
```

- [ ] **Step 4: Run (passes)** — `go test ./internal/handlers/`.

- [ ] **Step 5: Commit**

```bash
git add monitoring/packages/app/internal/handlers
git commit -m "feat(monitoring): API handlers + embedded SPA serving"
```

---

## Task 8: Native SSO OIDC device-flow auth (no AWS CLI)

**Files:**
- Create: `monitoring/packages/app/internal/ssoauth/ssoauth.go`
- Test: `monitoring/packages/app/internal/ssoauth/ssoauth_test.go`

**Interfaces:**
- `type Config struct { StartURL, SSORegion, AccountID, RoleName string }`
- `func Login(ctx context.Context, c Config) (aws.CredentialsProvider, error)` — uses a cached SSO token if valid; otherwise runs the device flow (register client → start device authorization → open browser → poll for token), caches the token under `os.UserCacheDir()/monitoring/sso.json`, then returns a credentials provider backed by `sso:GetRoleCredentials` (wrapped in `aws.NewCredentialsCache`).
- Internal helpers `loadToken`/`saveToken` (cache file with `accessToken` + `expiresAt`) — unit-tested.

- [ ] **Step 1: Write the failing test for the token cache round-trip**

```go
package ssoauth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTokenCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sso.json")
	want := cachedToken{AccessToken: "abc", ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
	if err := saveToken(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "abc" || !got.valid() {
		t.Fatalf("round-trip failed: %+v", got)
	}
}

func TestExpiredTokenInvalid(t *testing.T) {
	if (cachedToken{AccessToken: "x", ExpiresAt: time.Now().Add(-time.Minute)}).valid() {
		t.Fatal("expired token should be invalid")
	}
}
```

- [ ] **Step 2: Run (fails)** — `go test ./internal/ssoauth/` → undefined symbols.

- [ ] **Step 3: Implement**

```go
package ssoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	oidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/pkg/browser"
	"github.com/rs/zerolog/log"
)

type Config struct {
	StartURL  string
	SSORegion string
	AccountID string
	RoleName  string
}

type cachedToken struct {
	AccessToken string    `json:"accessToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func (t cachedToken) valid() bool { return t.AccessToken != "" && time.Now().Before(t.ExpiresAt) }

func cachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(dir, "monitoring")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(d, "sso.json"), nil
}

func loadToken(path string) (cachedToken, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return cachedToken{}, err
	}
	var t cachedToken
	return t, json.Unmarshal(b, &t)
}

func saveToken(path string, t cachedToken) error {
	b, _ := json.Marshal(t)
	return os.WriteFile(path, b, 0o600)
}

// Login returns AWS credentials derived from the operator's IdC identity,
// performing the SSO device-authorization flow on a cold/expired cache.
func Login(ctx context.Context, c Config) (aws.CredentialsProvider, error) {
	path, err := cachePath()
	if err != nil {
		return nil, err
	}
	tok, err := loadToken(path)
	if err != nil || !tok.valid() {
		tok, err = deviceFlow(ctx, c)
		if err != nil {
			return nil, err
		}
		if err := saveToken(path, tok); err != nil {
			log.Warn().Err(err).Msg("could not cache SSO token")
		}
	}

	ssoClient := sso.New(sso.Options{Region: c.SSORegion, Credentials: aws.AnonymousCredentials{}})
	provider := &roleProvider{client: ssoClient, accountID: c.AccountID, roleName: c.RoleName, token: tok.AccessToken}
	return aws.NewCredentialsCache(provider), nil
}

func deviceFlow(ctx context.Context, c Config) (cachedToken, error) {
	oidc := ssooidc.New(ssooidc.Options{Region: c.SSORegion, Credentials: aws.AnonymousCredentials{}})

	reg, err := oidc.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("monitoring"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return cachedToken{}, fmt.Errorf("register client: %w", err)
	}

	dev, err := oidc.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     aws.String(c.StartURL),
	})
	if err != nil {
		return cachedToken{}, fmt.Errorf("start device auth: %w", err)
	}

	log.Info().Msgf("Opening browser to approve sign-in. If it doesn't open, visit: %s", aws.ToString(dev.VerificationUriComplete))
	_ = browser.OpenURL(aws.ToString(dev.VerificationUriComplete))

	interval := time.Duration(dev.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		out, err := oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     reg.ClientId,
			ClientSecret: reg.ClientSecret,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
			DeviceCode:   dev.DeviceCode,
		})
		if err == nil {
			return cachedToken{
				AccessToken: aws.ToString(out.AccessToken),
				ExpiresAt:   time.Now().Add(time.Duration(out.ExpiresIn) * time.Second),
			}, nil
		}
		var pending *oidctypes.AuthorizationPendingException
		var slow *oidctypes.SlowDownException
		switch {
		case errors.As(err, &pending):
			// fall through to the ctx-aware wait below
		case errors.As(err, &slow):
			interval += 5 * time.Second
		default:
			return cachedToken{}, fmt.Errorf("create token: %w", err)
		}
		// ctx-aware wait so Ctrl-C interrupts immediately (not after the backoff).
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return cachedToken{}, ctx.Err()
		}
	}
}

// roleProvider exchanges the SSO access token for role credentials on demand.
type roleProvider struct {
	client    *sso.Client
	accountID string
	roleName  string
	token     string
}

func (p *roleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	out, err := p.client.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(p.token),
		AccountId:   aws.String(p.accountID),
		RoleName:    aws.String(p.roleName),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("get role credentials: %w", err)
	}
	rc := out.RoleCredentials
	return aws.Credentials{
		AccessKeyID:     aws.ToString(rc.AccessKeyId),
		SecretAccessKey: aws.ToString(rc.SecretAccessKey),
		SessionToken:    aws.ToString(rc.SessionToken),
		CanExpire:       true,
		Expires:         time.UnixMilli(rc.Expiration),
	}, nil
}
```

- [ ] **Step 4: Run (passes) + build** — `go test ./internal/ssoauth/ && go build ./...`.

- [ ] **Step 5: Commit**

```bash
git add monitoring/packages/app/internal/ssoauth
git commit -m "feat(monitoring): native SSO OIDC device-flow auth"
```

---

## Task 9: Wire main.go — SSO login → server → open browser

**Files:**
- Modify: `monitoring/packages/app/cmd/main.go`

**Interfaces:**
- Consumes: `ssoauth`, `config`, `athena`, `geo`, `cache`, `handlers`.
- Produces: a **cobra** root command (`monitoring`) whose flags + env are merged by **koanf** (an explicitly-set flag wins, else the env var, else the flag default). Flags/env: `--sso-start-url`/`MONITORING_SSO_START_URL`, `--sso-region`/`MONITORING_SSO_REGION`, `--account-id`/`AWS_ACCOUNT_ID`, `--sso-role`/`MONITORING_SSO_ROLE`, `--addr`/`ADDR` (default `127.0.0.1:0` = auto-select free port). `RunE` runs the full startup sequence.

- [ ] **Step 1: Add cobra + koanf posflag provider, then write main.go**

```bash
go get github.com/spf13/cobra@v1.8.1
go get github.com/knadh/koanf/providers/posflag@v1.0.0
```

(Use the `v1.x` posflag tag — like the other koanf v2 providers — to avoid the "ambiguous import" conflict. Bump to the nearest working tag if v1.0.0 is unavailable, and note it.)

```go
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/gin-gonic/gin"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/pkg/browser"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	athenacli "isnan.eu/monitoring/internal/athena"
	"isnan.eu/monitoring/internal/cache"
	"isnan.eu/monitoring/internal/config"
	"isnan.eu/monitoring/internal/geo"
	"isnan.eu/monitoring/internal/handlers"
	"isnan.eu/monitoring/internal/ssoauth"
)

func main() {
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	gin.SetMode(gin.ReleaseMode) // keep logs clean zerolog JSON (no Gin debug banner)
	if err := newRootCmd().Execute(); err != nil {
		log.Fatal().Err(err).Msg("monitoring")
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "monitoring",
		Short:         "CloudFront access-log analytics dashboard (local)",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          run,
	}
	f := cmd.Flags()
	f.String("sso-start-url", "", "IAM Identity Center start URL")
	f.String("sso-region", "", "IAM Identity Center region")
	f.String("account-id", "", "AWS account id")
	f.String("sso-role", "", "IdC permission-set / role name")
	// Port 0 → OS assigns a free port (no collisions). Dev passes 127.0.0.1:8080
	// so Vite's /api proxy can find it.
	f.String("addr", "127.0.0.1:0", "listen address (host:port; port 0 = auto-select)")
	return cmd
}

// cliEnvMap maps process env vars to the CLI flag keys koanf merges them into.
var cliEnvMap = map[string]string{
	"MONITORING_SSO_START_URL": "sso-start-url",
	"MONITORING_SSO_REGION":    "sso-region",
	"AWS_ACCOUNT_ID":           "account-id",
	"MONITORING_SSO_ROLE":      "sso-role",
	"ADDR":                     "addr",
}

func run(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	// koanf merges env vars with CLI flags. Passing the koanf instance to the
	// posflag provider makes an explicitly-set flag win, else the env var, else
	// the flag default.
	k := koanf.New(".")
	_ = k.Load(env.Provider("", ".", func(s string) string { return cliEnvMap[s] }), nil)
	_ = k.Load(posflag.Provider(cmd.Flags(), ".", k), nil)

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// 1. Authenticate with IAM Identity Center (device flow on cold cache).
	creds, err := ssoauth.Login(ctx, ssoauth.Config{
		StartURL:  k.String("sso-start-url"),
		SSORegion: k.String("sso-region"),
		AccountID: k.String("account-id"),
		RoleName:  k.String("sso-role"),
	})
	if err != nil {
		return fmt.Errorf("sso login: %w", err)
	}

	// 2. AWS config (Athena region) using the IdC credentials.
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(creds),
	)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}

	// 3. GeoIP from local file.
	resolver, err := geo.Open(cfg.GeoIPPath)
	if err != nil {
		return fmt.Errorf("geoip open %s: %w", cfg.GeoIPPath, err)
	}
	defer resolver.Close()

	q := athenacli.New(athena.NewFromConfig(awsCfg), cfg.Database, cfg.Workgroup)
	api := &handlers.API{Cfg: cfg, Q: q, Geo: resolver, Cache: cache.New(5 * time.Minute)}

	r := gin.New()
	r.Use(gin.Recovery())
	api.Register(r)

	// 4. Bind first to learn the actual (possibly auto-assigned) port, open the
	//    browser to it, then serve on that listener.
	addr := k.String("addr")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	url := "http://" + ln.Addr().String()
	go func() {
		time.Sleep(300 * time.Millisecond)
		log.Info().Msgf("opening %s", url)
		_ = browser.OpenURL(url)
	}()

	log.Info().Msgf("serving on %s", url)
	return r.RunListener(ln)
}
```

- [ ] **Step 2: Update the app Makefile `run` target for the new --addr flag**

Now that `main.go` parses `--addr` (default auto-port), pin dev to 8080 so Vite's proxy matches. In `monitoring/packages/app/Makefile`, change the `run` target to:

```makefile
# Dev: fixed port so Vite's /api proxy (127.0.0.1:8080) matches. The built
# binary (no --addr) auto-selects a free port instead.
run:
	go run ./cmd --addr 127.0.0.1:8080
```

- [ ] **Step 3: Tidy + build + full test run**

Run: `cd monitoring/packages/app && go mod tidy && go build ./... && go test ./...`
Expected: build OK; all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add monitoring/packages/app/cmd/main.go monitoring/packages/app/Makefile monitoring/packages/app/go.mod monitoring/packages/app/go.sum
git commit -m "feat(monitoring): wire SSO login → Athena → server → browser"
```

---

## Task 10: Terraform skeleton

**Files:**
- Create: `monitoring/packages/infrastructure/main.tf`, `provider.tf`, `variables.tf`, `outputs.tf`

**Interfaces:** `local.account_id`; `var.region`; `var.log_sources` (map of `{bucket,prefix}`).

- [ ] **Step 1: main.tf**

```hcl
terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  backend "s3" {
    bucket       = "global-tf-states"
    key          = "platform/monitoring.tfstate"
    region       = "eu-central-1"
    use_lockfile = true
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}
```

- [ ] **Step 2: provider.tf**

```hcl
provider "aws" {
  region = var.region
  default_tags {
    tags = {
      application = "platform-monitoring"
      owner       = "terraform"
    }
  }
}
```

- [ ] **Step 3: variables.tf**

`log_sources` defaults to empty; add an entry per source (key = name shown in the UI, `bucket` = the CloudFront log bucket, `prefix` = the delivery suffix under `raw/`). Example in the comment.

```hcl
variable "region" {
  type    = string
  default = "eu-central-1"
}

# Map of source name -> { bucket, prefix }. Example:
#   bl-cms  = { bucket = "<bucket>", prefix = "raw/cms" }
#   bl-site = { bucket = "<bucket>", prefix = "raw/site" }
variable "log_sources" {
  type = map(object({
    bucket = string
    prefix = string
  }))
  default = {}
}
```

- [ ] **Step 4: outputs.tf**

```hcl
output "athena_workgroup" {
  value = aws_athena_workgroup.monitoring.name
}

output "athena_database" {
  value = aws_glue_catalog_database.monitoring.name
}

# Convenience: the LOG_SOURCES JSON the binary expects (name -> sanitized table).
output "log_sources_env" {
  value = jsonencode([for name, _ in var.log_sources : { name = name, table = replace(name, "-", "_") }])
}
```

- [ ] **Step 5: Commit**

```bash
git add monitoring/packages/infrastructure
git commit -m "feat(monitoring): terraform skeleton"
```

---

## Task 11: Athena workgroup + results bucket

**Files:**
- Create: `monitoring/packages/infrastructure/s3.tf`, `athena.tf`

- [ ] **Step 1: s3.tf**

```hcl
resource "aws_s3_bucket" "athena_results" {
  bucket        = "${local.account_id}-monitoring-athena-results"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    id     = "expire-results"
    status = "Enabled"
    filter {}
    expiration { days = 7 }
  }
}
```

- [ ] **Step 2: athena.tf**

```hcl
resource "aws_athena_workgroup" "monitoring" {
  name          = "monitoring"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false
    bytes_scanned_cutoff_per_query     = 5 * 1024 * 1024 * 1024 # 5 GB cost guardrail

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
    }
  }
}
```

- [ ] **Step 3: Validate**

Run: `terraform -chdir=monitoring/packages/infrastructure init && terraform -chdir=monitoring/packages/infrastructure validate`
Expected: valid.

- [ ] **Step 4: Commit**

```bash
git add monitoring/packages/infrastructure/s3.tf monitoring/packages/infrastructure/athena.tf
git commit -m "feat(monitoring): athena workgroup + results bucket"
```

---

## Task 12: Glue database + per-source tables (partition projection)

**Files:**
- Create: `monitoring/packages/infrastructure/glue.tf`

**Column-name caveat:** confirm the exact Parquet column names (esp. `cs(Host)`/`cs(User-Agent)`) with a one-row query (Step 3). If they differ, fix `glue.tf` columns and `query/builder.go` constants together.

- [ ] **Step 1: glue.tf**

```hcl
resource "aws_glue_catalog_database" "monitoring" {
  name = "monitoring"
}

resource "aws_glue_catalog_table" "source" {
  for_each      = var.log_sources
  name          = replace(each.key, "-", "_")
  database_name = aws_glue_catalog_database.monitoring.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification              = "parquet"
    "projection.enabled"        = "true"
    "projection.year.type"      = "integer"
    "projection.year.range"     = "2024,2030"
    "projection.year.digits"    = "4"
    "projection.month.type"     = "integer"
    "projection.month.range"    = "1,12"
    "projection.month.digits"   = "2"
    "projection.day.type"       = "integer"
    "projection.day.range"      = "1,31"
    "projection.day.digits"     = "2"
    "storage.location.template" = "s3://${each.value.bucket}/${each.value.prefix}/year=$${year}/month=$${month}/day=$${day}"
  }

  storage_descriptor {
    location      = "s3://${each.value.bucket}/${each.value.prefix}/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    columns { name = "date"               type = "string" }
    columns { name = "time"               type = "string" }
    columns { name = "c-ip"               type = "string" }
    columns { name = "c-country"          type = "string" }
    columns { name = "asn"                type = "string" }
    columns { name = "cs-method"          type = "string" }
    columns { name = "cs-protocol"        type = "string" }
    columns { name = "cs-host"            type = "string" }
    columns { name = "cs-uri-stem"        type = "string" }
    columns { name = "cs-uri-query"       type = "string" }
    columns { name = "sc-status"          type = "string" }
    columns { name = "x-edge-result-type" type = "string" }
    columns { name = "x-edge-location"    type = "string" }
    columns { name = "cs-user-agent"      type = "string" }
  }

  partition_keys { name = "year"  type = "string" }
  partition_keys { name = "month" type = "string" }
  partition_keys { name = "day"   type = "string" }
}
```

- [ ] **Step 2: Add a real source + apply**

Set `var.log_sources` (in a `terraform.tfvars` or the default map) to a source whose bucket you control, then:

```bash
terraform -chdir=monitoring/packages/infrastructure validate
terraform -chdir=monitoring/packages/infrastructure apply -auto-approve
```
Expected: database, workgroup, results bucket, and one table per source created.

- [ ] **Step 3: Confirm partition projection + column names**

```bash
aws athena start-query-execution --work-group monitoring \
  --query-execution-context Database=monitoring \
  --query-string 'SELECT * FROM <table> WHERE year='\''2026'\'' AND month='\''06'\'' AND day='\''27'\'' LIMIT 1'
# aws athena get-query-results --query-execution-id <id>
```
Inspect the returned column names; if any differ from `glue.tf`, fix `glue.tf` + `query/builder.go` constants, re-apply, re-run.

- [ ] **Step 4: Commit**

```bash
git add monitoring/packages/infrastructure/glue.tf
git commit -m "feat(monitoring): glue db + per-source tables (partition projection)"
```

---

## Task 13: Scaffold the React app (Vite + Tailwind v4)

**Files:**
- Create: `monitoring/packages/web/` (Vite scaffold), `package.json`, `vite.config.js`, `eslint.config.js`, `jsconfig.json`, `index.html`, `src/main.jsx`, `src/App.jsx`, `src/index.css`, `src/lib/utils.js`, `src/components/ui/{Button,Card,Select,ToggleGroup}.jsx`.

- [ ] **Step 1: Scaffold + deps (Tailwind v4, no PostCSS)**

```bash
cd monitoring/packages
yarn create vite web --template react
cd web
yarn add react@18.3.1 react-dom@18.3.1 echarts@5.5.1 dayjs@1.11.13 \
  class-variance-authority@0.7.1 clsx@2.1.1 tailwind-merge@2.6.0 lucide-react@0.469.0
yarn add -D @tailwindcss/vite@4.1.18 tailwindcss@4.1.18
```

- [ ] **Step 2: vite.config.js — Tailwind v4 plugin, @ alias, fixed port, /api proxy for dev**

```js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  server: {
    port: 5180,
    strictPort: true,
    proxy: { '/api': 'http://127.0.0.1:8080' }, // dev: hit the local Go server
  },
});
```

- [ ] **Step 3: src/index.css — Tailwind v4 @theme tokens + fonts**

```css
@import "tailwindcss";
@import url('https://fonts.googleapis.com/css2?family=Archivo:wght@400;600;700;800;900&family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

@theme {
  --color-background: #08090b;
  --color-foreground: #e7ebef;
  --color-card: #0f1217;
  --color-border: #1c2129;
  --color-muted: #12151b;
  --color-muted-foreground: #8b94a0;
  --color-signal: #c8f135;
  --color-cyan: #39d9c8;
  --color-amber: #ffb020;
  --color-danger: #ff5a5a;
  --font-display: 'Archivo', system-ui, sans-serif;
  --font-mono: '"IBM Plex Mono"', ui-monospace, monospace;
  --font-sans: '"IBM Plex Sans"', system-ui, sans-serif;
}

body {
  background-color: var(--color-background);
  color: var(--color-foreground);
  font-family: var(--font-sans);
  background-image:
    linear-gradient(rgba(255,255,255,.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.018) 1px, transparent 1px);
  background-size: 42px 42px;
}
```

- [ ] **Step 4: src/lib/utils.js — cn() helper**

```js
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export const cn = (...inputs) => twMerge(clsx(inputs));
```

- [ ] **Step 5: Hand-roll the UI primitives**

`src/components/ui/Button.jsx`:

```jsx
import { cva } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const button = cva(
  'inline-flex items-center justify-center gap-2 rounded-[4px] font-mono transition-colors disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'bg-signal text-[#0b0d07] hover:bg-signal/90',
        outline: 'border border-border bg-card text-foreground hover:border-signal/60',
      },
      size: { default: 'h-9 px-4 text-sm', sm: 'h-7 px-2.5 text-[10px] uppercase tracking-[0.12em]' },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  }
);

export const Button = ({ className, variant, size, ...props }) => (
  <button className={cn(button({ variant, size }), className)} {...props} />
);
```

`src/components/ui/Card.jsx`:

```jsx
import { cn } from '@/lib/utils';

export const Card = ({ className, ...props }) => (
  <div className={cn('relative rounded-[4px] border border-border bg-gradient-to-b from-card to-[#0c0e12]', className)} {...props} />
);
```

`src/components/ui/Select.jsx`:

```jsx
import { ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';

export const Select = ({ value, onChange, options, className }) => (
  <div className={cn('relative inline-flex items-center', className)}>
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 appearance-none rounded-[4px] border border-border bg-card pl-3 pr-8 font-mono text-sm text-foreground outline-none hover:border-signal/60"
    >
      {options.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
    <ChevronDown className="pointer-events-none absolute right-2 h-3.5 w-3.5 text-muted-foreground" />
  </div>
);
```

`src/components/ui/ToggleGroup.jsx`:

```jsx
import { cn } from '@/lib/utils';

export const ToggleGroup = ({ value, onChange, items }) => (
  <div className="flex h-9 overflow-hidden rounded-[4px] border border-border bg-card">
    {items.map((it, i) => (
      <button
        key={it.value}
        onClick={() => onChange(it.value)}
        className={cn(
          'border-border px-3.5 font-mono text-[11px] uppercase tracking-[0.08em] transition-colors',
          i > 0 && 'border-l',
          value === it.value ? 'bg-signal font-semibold text-[#0b0d07]' : 'text-muted-foreground hover:text-foreground'
        )}
      >
        {it.label}
      </button>
    ))}
  </div>
);
```

- [ ] **Step 6: jsconfig.json**

```json
{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./src/*"] } } }
```

- [ ] **Step 7: eslint.config.js**

```js
import js from '@eslint/js';
import react from 'eslint-plugin-react';

export default [
  js.configs.recommended,
  {
    files: ['src/**/*.{js,jsx}'],
    languageOptions: { ecmaVersion: 2022, sourceType: 'module' },
    plugins: { react },
    rules: {},
  },
];
```

- [ ] **Step 8: Verify dev server boots** — `yarn --cwd monitoring/packages/web dev` → serves on `http://localhost:5180`.

- [ ] **Step 9: Commit**

```bash
git add monitoring/packages/web
git commit -m "feat(monitoring): scaffold React app (Vite + Tailwind v4)"
```

---

## Task 14: API client + app shell (Header + KPIs)

**Files:**
- Create: `monitoring/packages/web/src/lib/api.js`, `src/App.jsx`, `src/components/Header.jsx`, `src/components/Kpis.jsx`
- Modify: `monitoring/packages/web/src/main.jsx`

**Interfaces:** `api(path, params)` → JSON (same-origin `/api/*`, no auth header). App holds `{source, from, to, groupBy, country}`, fetches `summary` for KPIs, passes state to children.

- [ ] **Step 1: api.js (no auth — local server)**

```js
export const api = async (path, params = {}) => {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(`${path}${qs ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
};
```

- [ ] **Step 2: main.jsx**

```jsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
```

- [ ] **Step 3: Header.jsx**

```jsx
import { Select } from '@/components/ui/Select';
import { ToggleGroup } from '@/components/ui/ToggleGroup';

export const Header = ({ sources, state, setState }) => (
  <header className="flex h-[58px] items-center gap-6 border-b border-border px-5">
    <div className="flex items-center gap-2">
      <span className="text-signal text-lg drop-shadow-[0_0_6px_rgba(200,241,53,.6)]">◢</span>
      <div>
        <div className="font-display text-base font-extrabold">EDGE<span className="text-signal">//</span>WATCH</div>
        <div className="font-mono text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground">cloudfront access telemetry</div>
      </div>
    </div>
    <div className="ml-auto flex items-center gap-3">
      <Select
        value={state.source}
        onChange={(v) => setState((s) => ({ ...s, source: v, country: '' }))}
        options={sources}
        className="w-[230px]"
      />
      <ToggleGroup
        value={state.groupBy}
        onChange={(v) => setState((s) => ({ ...s, groupBy: v }))}
        items={[{ value: 'day', label: 'Day' }, { value: 'week', label: 'Week' }, { value: 'month', label: 'Month' }]}
      />
    </div>
  </header>
);
```

- [ ] **Step 4: Kpis.jsx**

```jsx
import { Card } from '@/components/ui/Card';

const Kpi = ({ label, value, unit, accent }) => (
  <Card className="relative overflow-hidden p-4">
    <span className={`absolute left-0 top-0 h-full w-[3px] ${accent ? 'bg-signal shadow-[0_0_10px_rgba(200,241,53,.5)]' : 'bg-border'}`} />
    <div className="font-mono text-[9.5px] uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
    <div className={`mt-2 font-mono text-3xl font-semibold tabular-nums ${accent ? 'text-signal' : ''}`}>
      {value}{unit && <span className="ml-1 text-sm text-muted-foreground">{unit}</span>}
    </div>
  </Card>
);

export const Kpis = ({ summary }) => (
  <div className="grid grid-cols-4 gap-3.5">
    <Kpi label="Total Requests" value={(summary?.total ?? 0).toLocaleString()} accent />
    <Kpi label="Unique Callers" value={(summary?.uniqueIps ?? 0).toLocaleString()} unit="ip" />
    <Kpi label="Error Rate · 4xx+5xx" value={(summary?.errorRate ?? 0).toFixed(2)} unit="%" />
    <Kpi label="Countries" value={summary?.countries ?? 0} />
  </div>
);
```

- [ ] **Step 5: App.jsx**

```jsx
import { useEffect, useState } from 'react';
import dayjs from 'dayjs';
import { api } from '@/lib/api';
import { Header } from '@/components/Header';
import { Kpis } from '@/components/Kpis';
import { GeoMap } from '@/components/GeoMap';
import { Histogram } from '@/components/Histogram';
import { StatusDonut } from '@/components/StatusDonut';
import { TopList } from '@/components/TopList';

const today = dayjs().format('YYYY-MM-DD');
const twoWeeksAgo = dayjs().subtract(14, 'day').format('YYYY-MM-DD');

export default function App() {
  const [sources, setSources] = useState([]);
  const [state, setState] = useState({ source: '', from: twoWeeksAgo, to: today, groupBy: 'day', country: '' });
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    api('/api/sources').then((s) => {
      setSources(s);
      setState((st) => ({ ...st, source: st.source || s[0] || '' }));
    });
  }, []);

  useEffect(() => {
    if (!state.source) return;
    api('/api/summary', { source: state.source, from: state.from, to: state.to }).then(setSummary);
  }, [state.source, state.from, state.to]);

  return (
    <div className="flex h-screen flex-col">
      <Header sources={sources} state={state} setState={setState} />
      <main className="grid flex-1 grid-cols-[1fr_340px] grid-rows-[auto_1fr_auto] gap-3.5 p-4 min-h-0">
        <div className="col-span-2"><Kpis summary={summary} /></div>
        <GeoMap state={state} setState={setState} />
        <aside className="flex flex-col gap-3.5 min-h-0">
          <StatusDonut summary={summary} />
          <TopList state={state} summary={summary} />
        </aside>
        <div className="col-span-2"><Histogram state={state} /></div>
      </main>
    </div>
  );
}
```

- [ ] **Step 6: Commit**

```bash
git add monitoring/packages/web/src
git commit -m "feat(monitoring): api client + app shell (header, KPIs)"
```

---

## Task 15: ECharts world map + country drill-down

**Files:**
- Create: `monitoring/packages/web/src/lib/world.js`, `src/components/GeoMap.jsx`

**Reference:** port the ECharts options from `docs/ui-design/index.html` (`worldOption`, `franceOption`, drill click handler).

- [ ] **Step 1: world.js**

```js
import * as echarts from 'echarts';

let registered = false;
export const ensureWorld = async () => {
  if (registered) return;
  const res = await fetch('https://cdn.jsdelivr.net/gh/johan/world.geo.json@master/countries.geo.json');
  echarts.registerMap('world', await res.json());
  registered = true;
};

// ISO-A2 → [lng,lat] centroid + display name (extend as needed).
export const CENTROIDS = {
  US: { name: 'United States', coord: [-98, 39] },
  FR: { name: 'France', coord: [2.4, 46.6] },
  DE: { name: 'Germany', coord: [10.4, 51.1] },
  GB: { name: 'United Kingdom', coord: [-1.5, 52.6] },
  ES: { name: 'Spain', coord: [-3.7, 40.2] },
  BR: { name: 'Brazil', coord: [-51, -10] },
  IN: { name: 'India', coord: [79, 22] },
  JP: { name: 'Japan', coord: [138, 36.5] },
  CA: { name: 'Canada', coord: [-106, 56] },
  AU: { name: 'Australia', coord: [134, -25] },
  SG: { name: 'Singapore', coord: [103.8, 1.35] },
  ZA: { name: 'South Africa', coord: [24.5, -29] },
};
```

- [ ] **Step 2: GeoMap.jsx**

```jsx
import { useEffect, useRef, useState } from 'react';
import * as echarts from 'echarts';
import { api } from '@/lib/api';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { ensureWorld, CENTROIDS } from '@/lib/world';

const SIGNAL = '#c8f135';
const CYAN = '#39d9c8';
const tip = {
  backgroundColor: '#0c0e12', borderColor: '#1c2129', borderWidth: 1,
  textStyle: { color: '#e7ebef', fontFamily: '"IBM Plex Mono", monospace', fontSize: 11 },
};

const worldOption = (data) => ({
  tooltip: { ...tip, formatter: (p) => (p.value ? `${p.name}<br/><b style="color:${SIGNAL}">${p.value[2].toLocaleString()}</b> callers` : p.name) },
  geo: { map: 'world', roam: true, zoom: 1.2, center: [12, 28], itemStyle: { areaColor: '#13161c', borderColor: '#262c36', borderWidth: 0.6 }, emphasis: { itemStyle: { areaColor: '#1a1f27' }, label: { show: false } }, scaleLimit: { min: 1, max: 8 } },
  series: [{ type: 'effectScatter', coordinateSystem: 'geo', data, zlevel: 2, symbolSize: (v) => Math.max(9, Math.sqrt(v[2]) / 2.4), showEffectOn: 'render', rippleEffect: { brushType: 'stroke', scale: 2.6, period: 4 }, itemStyle: { color: SIGNAL, shadowBlur: 14, shadowColor: 'rgba(200,241,53,.75)' }, emphasis: { scale: 1.5 } }],
});

const countryOption = (data, center) => ({
  tooltip: { ...tip, formatter: (p) => (p.value ? `${p.name}<br/><b style="color:${CYAN}">${p.value[2].toLocaleString()}</b> requests` : p.name) },
  geo: { map: 'world', roam: true, zoom: 11, center, itemStyle: { areaColor: '#13161c', borderColor: '#2a313c', borderWidth: 0.8 }, emphasis: { itemStyle: { areaColor: '#1a1f27' }, label: { show: false } }, scaleLimit: { min: 4, max: 40 } },
  series: [{ type: 'effectScatter', coordinateSystem: 'geo', data, zlevel: 2, symbolSize: (v) => Math.max(5, Math.sqrt(v[2])), showEffectOn: 'render', rippleEffect: { brushType: 'stroke', scale: 2.2, period: 3.5 }, itemStyle: { color: CYAN, shadowBlur: 10, shadowColor: 'rgba(57,217,200,.7)' } }],
});

export const GeoMap = ({ state, setState }) => {
  const ref = useRef(null);
  const chart = useRef(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    (async () => {
      await ensureWorld();
      if (!alive) return;
      chart.current = echarts.init(ref.current);
      chart.current.on('click', (p) => {
        if (p.seriesType === 'effectScatter' && p.data?.code) {
          setState((s) => ({ ...s, country: p.data.code }));
        }
      });
      setLoading(false);
    })();
    const onResize = () => chart.current?.resize();
    window.addEventListener('resize', onResize);
    return () => { alive = false; window.removeEventListener('resize', onResize); };
  }, [setState]);

  useEffect(() => {
    if (loading || !state.source) return;
    const c = chart.current;
    if (!state.country) {
      api('/api/geo', { source: state.source, from: state.from, to: state.to }).then((d) => {
        const data = d.countries.filter((x) => CENTROIDS[x.country]).map((x) => ({ name: CENTROIDS[x.country].name, code: x.country, value: [...CENTROIDS[x.country].coord, x.callers] }));
        c.setOption(worldOption(data), true);
      });
    } else {
      api('/api/geo', { source: state.source, from: state.from, to: state.to, country: state.country }).then((d) => {
        const data = d.points.map((p) => ({ name: `${p.city} · ${p.ip}`, value: [p.lng, p.lat, p.requests] }));
        c.setOption(countryOption(data, CENTROIDS[state.country]?.coord || [0, 20]), true);
      });
    }
  }, [loading, state.source, state.from, state.to, state.country]);

  return (
    <Card className="relative flex flex-col min-h-0">
      <div className="flex items-center gap-3 border-b border-border px-3.5 py-2.5 font-mono text-[11px]">
        {state.country && <Button variant="outline" size="sm" onClick={() => setState((s) => ({ ...s, country: '' }))}>◀ Back</Button>}
        <span className={state.country ? 'text-muted-foreground' : 'text-signal uppercase tracking-[0.1em]'}>Global View</span>
        {state.country && <><span className="text-muted-foreground">▸</span><span className="text-signal uppercase tracking-[0.1em]">{state.country}</span></>}
      </div>
      <div ref={ref} className="flex-1 min-h-0" />
    </Card>
  );
};
```

- [ ] **Step 3: Commit**

```bash
git add monitoring/packages/web/src/lib/world.js monitoring/packages/web/src/components/GeoMap.jsx
git commit -m "feat(monitoring): ECharts world map + country drill-down"
```

---

## Task 16: Histogram + status donut + top list

**Files:**
- Create: `monitoring/packages/web/src/components/Histogram.jsx`, `StatusDonut.jsx`, `TopList.jsx`

- [ ] **Step 1: Histogram.jsx**

```jsx
import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
import { api } from '@/lib/api';
import { Card } from '@/components/ui/Card';

const COLORS = { s2: '#c8f135', s3: '#5b9bff', s4: '#ffb020', s5: '#ff5a5a' };

export const Histogram = ({ state }) => {
  const ref = useRef(null);
  const chart = useRef(null);

  useEffect(() => { chart.current = echarts.init(ref.current); const r = () => chart.current?.resize(); window.addEventListener('resize', r); return () => window.removeEventListener('resize', r); }, []);

  useEffect(() => {
    if (!state.source) return;
    api('/api/access', { source: state.source, from: state.from, to: state.to, groupBy: state.groupBy }).then((d) => {
      const x = d.buckets.map((b) => b.t);
      const series = ['s2', 's3', 's4', 's5'].map((k) => ({ name: k, type: 'bar', stack: 't', barWidth: '58%', data: d.buckets.map((b) => b[k]), itemStyle: { color: COLORS[k] } }));
      chart.current.setOption({
        tooltip: { trigger: 'axis', backgroundColor: '#0c0e12', borderColor: '#1c2129', textStyle: { color: '#e7ebef', fontFamily: '"IBM Plex Mono", monospace', fontSize: 11 } },
        grid: { left: 54, right: 18, top: 14, bottom: 24 },
        xAxis: { type: 'category', data: x, axisLine: { lineStyle: { color: '#1c2129' } }, axisTick: { show: false }, axisLabel: { color: '#5c6470', fontFamily: '"IBM Plex Mono", monospace', fontSize: 10 } },
        yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(255,255,255,.04)' } }, axisLabel: { color: '#5c6470', fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, formatter: (v) => (v >= 1000 ? v / 1000 + 'k' : v) } },
        series,
      }, true);
    });
  }, [state.source, state.from, state.to, state.groupBy]);

  return (
    <Card className="h-[188px] flex flex-col">
      <div className="border-b border-border px-3.5 py-2.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">Requests Over Time</div>
      <div ref={ref} className="flex-1 min-h-0" />
    </Card>
  );
};
```

- [ ] **Step 2: StatusDonut.jsx**

```jsx
import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
import { Card } from '@/components/ui/Card';

export const StatusDonut = ({ summary }) => {
  const ref = useRef(null);
  const chart = useRef(null);
  useEffect(() => { chart.current = echarts.init(ref.current); }, []);
  useEffect(() => {
    if (!summary) return;
    const errors = summary.errors ?? 0;
    const ok = (summary.total ?? 0) - errors;
    chart.current.setOption({
      series: [{ type: 'pie', radius: ['62%', '92%'], label: { show: false }, labelLine: { show: false }, itemStyle: { borderColor: '#0f1217', borderWidth: 2 },
        data: [{ value: ok, name: '2xx/3xx', itemStyle: { color: '#c8f135' } }, { value: errors, name: '4xx/5xx', itemStyle: { color: '#ff5a5a' } }] }],
    });
  }, [summary]);
  return (
    <Card className="flex flex-col">
      <div className="border-b border-border px-3.5 py-2.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">Status Mix</div>
      <div ref={ref} className="h-[150px]" />
    </Card>
  );
};
```

- [ ] **Step 3: TopList.jsx**

```jsx
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Card } from '@/components/ui/Card';

export const TopList = ({ state, summary }) => {
  const [items, setItems] = useState([]);
  const [title, setTitle] = useState('Top URIs');

  useEffect(() => {
    if (state.country) {
      setTitle(`Top Callers · ${state.country}`);
      api('/api/geo', { source: state.source, from: state.from, to: state.to, country: state.country })
        .then((d) => setItems(d.points.slice(0, 12).map((p) => ({ label: p.ip, sub: p.city, n: p.requests }))));
    } else {
      setTitle('Top URIs');
      setItems((summary?.topUris ?? []).map((u) => ({ label: u.uri, sub: '', n: u.hits })));
    }
  }, [state.country, state.source, state.from, state.to, summary]);

  const max = Math.max(1, ...items.map((i) => i.n));
  return (
    <Card className="flex-1 flex flex-col min-h-0">
      <div className="border-b border-border px-3.5 py-2.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">{title}</div>
      <div className="flex-1 overflow-auto py-1.5">
        {items.map((i, idx) => (
          <div key={idx} className="px-3.5 py-2">
            <div className="flex justify-between font-mono text-[11.5px]"><span className="truncate">{i.label}</span><span className="tabular-nums text-muted-foreground">{i.n.toLocaleString()}</span></div>
            <div className="mt-1 h-[3px] rounded bg-border overflow-hidden"><i className="block h-full rounded" style={{ width: `${(i.n / max * 100).toFixed(1)}%`, background: 'linear-gradient(90deg,#8ba31f,#c8f135)' }} /></div>
            {i.sub && <div className="font-mono text-[9.5px] text-muted-foreground">{i.sub}</div>}
          </div>
        ))}
      </div>
    </Card>
  );
};
```

- [ ] **Step 4: Build the full frontend** — `yarn --cwd monitoring/packages/web build` → succeeds.

- [ ] **Step 5: Commit**

```bash
git add monitoring/packages/web/src/components
git commit -m "feat(monitoring): histogram, status donut, top list"
```

---

## Task 17: Build the binary end-to-end + run it

**Files:** none (build + manual verification).

**Prerequisite:** download `GeoLite2-City.mmdb` (free MaxMind account) into the run directory (or set `GEOIP_DB_PATH`).

- [ ] **Step 1: Build the embedded binary**

Run: `make -C monitoring backend-build`
Expected: `yarn build` → SPA copied into `packages/app/internal/web/dist` → `packages/app/bin/monitoring` produced.

- [ ] **Step 2: Run it (full path)**

Set the SSO + sources env and run:

```bash
export MONITORING_SSO_START_URL="https://<your-portal>.awsapps.com/start"
export MONITORING_SSO_REGION="<idc-region>"
export AWS_ACCOUNT_ID="<account-id>"
export MONITORING_SSO_ROLE="<permission-set-name>"
export LOG_SOURCES="$(terraform -chdir=monitoring/packages/infrastructure output -raw log_sources_env)"
export GEOIP_DB_PATH="$PWD/GeoLite2-City.mmdb"
monitoring/packages/app/bin/monitoring
```

Expected: browser opens for SSO approval (first run), then the dashboard opens at `http://127.0.0.1:<auto-port>` (the binary logs the exact URL; the port is OS-assigned).

- [ ] **Step 3: Verify end-to-end**

In the browser: source selector populates → KPI cards fill → world map shows country blips → click a country → per-IP drill-down → Back returns → histogram renders → Day/Week/Month toggles change it.

---

## Task 18: Documentation (CLAUDE.md)

**Files:**
- Create: `monitoring/CLAUDE.md`

- [ ] **Step 1: Write monitoring/CLAUDE.md**

```markdown
# Platform Monitoring — CloudFront Log Analytics

A single local Go binary that authenticates with your AWS IAM Identity Center
identity, embeds + serves a React SPA on localhost, queries CloudFront access
logs (Parquet in S3) via Athena, and opens the dashboard in your browser.

## Layout
- `packages/app` — Go binary. SSO device-flow auth (`internal/ssoauth`), Athena
  client, GeoIP (local MaxMind), Gin API + embedded SPA. Endpoints:
  `/api/sources,/access,/geo,/summary`.
- `packages/infrastructure` — Terraform: Glue partition-projection tables,
  Athena workgroup, results bucket.
- `packages/web` — React 18 + Vite + Tailwind v4 + ECharts.

## Auth
No app login. The binary runs the SSO OIDC device flow at startup (browser
approve on a cold/expired token cache; silent otherwise), gets IdC temporary
credentials, and queries Athena with them. Serves only on 127.0.0.1.
Configure via env/flags: `MONITORING_SSO_START_URL`, `MONITORING_SSO_REGION`,
`AWS_ACCOUNT_ID`, `MONITORING_SSO_ROLE`. (The IAM permissions on your IdC
identity are managed separately.)

## Data model
Each log source = `{name, bucket, prefix}` in `var.log_sources` → one Glue table
(`replace(name,'-','_')`) with partition projection on `year/month/day`. Add a
source via a map entry + `terraform apply`.

## GeoIP
MaxMind GeoLite2 City `.mmdb` as a LOCAL file (`GEOIP_DB_PATH`, default
`./GeoLite2-City.mmdb`). Used only for country drill-down; the world view uses
`c-country`. Refresh = re-download the file.

## Build / run (from monitoring/)
- `make backend-build`  — build SPA, embed it, build the binary
- `make frontend-serve` — Vite dev server (proxies /api → 127.0.0.1:8080)
- `make backend-run`    — run the Go server locally (dev)
- `make infra-plan` / `make infra-apply` / `make infra-output`

## Constraints
90-day log retention bounds all queries. Day is the finest granularity.
Frontend is JS/JSX (no TS).
```

- [ ] **Step 2: Commit**

```bash
git add monitoring/CLAUDE.md
git commit -m "docs(monitoring): app CLAUDE.md"
```

---

## Self-Review

**1. Spec coverage:**
- Local single binary + embedded SPA + auto-open browser → Tasks 1, 9. ✓
- Native SSO device flow (no CLI) → Task 8; wired in Task 9. ✓
- IAM Identity Center credentials → Athena → Tasks 8, 9, 6. ✓
- Partition-pruned parameterized SQL → Task 3. ✓
- Endpoints `/sources,/access,/geo (world+drill),/summary` → Task 7. ✓
- MaxMind local file, drill-down only → Tasks 5, 7, 9. ✓
- Caching → Tasks 4, 7. ✓
- Data layer (Glue partition projection + Athena workgroup + results bucket) → Tasks 10–12. ✓
- Per-source `{name,bucket,prefix}` + add-a-source → Tasks 10, 12, 18. ✓
- Frontend React+Vite+Tailwind v4+ECharts, telemetry-console theme, world→drill, histogram, donut, top list, KPI → Tasks 13–16. ✓
- Makefile hyphenated targets, no root package.json → Task 1. ✓
- Cost controls (bytes cutoff, results lifecycle, cache) → Tasks 11, 4. ✓
- Error handling (400/404/502, unknown source, IP miss) → Task 7. ✓
- 90-day window / day granularity → UI defaults + spec note. ✓

**2. Placeholder scan:** Concrete code throughout. Operator-supplied runtime values (`<your-portal>`, `<idc-region>`, `<account-id>`, `<permission-set-name>`, log-source bucket names) are environment facts, not code placeholders. `var.log_sources` defaults to empty with a documented example; Task 12 instructs adding a real source before apply/verify.

**3. Type consistency:** Module path `isnan.eu/monitoring` used consistently across imports. `athena.Querier.Query(ctx, sql, args)` (Task 6) consumed exactly in handlers (Task 7). `geo.Resolver.Lookup` (Task 5) used in Task 7. `query.*` signatures (Task 3) match handler calls. `ssoauth.Login` returns `aws.CredentialsProvider` consumed by `awsconfig.WithCredentialsProvider` (Task 9). Frontend `state` shape `{source,from,to,groupBy,country}` consistent across App/Header/GeoMap/Histogram/TopList; API response keys (`buckets/countries/points/topUris`) match handlers (Task 7) ↔ components (Tasks 15–16).

**Note:** `flag.String(name, os.Getenv(...), ...)` in Task 9 gives each flag an env-var default, so the binary accepts either flags or env vars with no extra code.
