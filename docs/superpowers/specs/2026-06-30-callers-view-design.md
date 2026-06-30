# Callers View + React Router Rework — Design

**Date:** 2026-06-30
**App:** `monitoring/` (CloudFront Log Analytics)

## Goal

Make the "Unique Callers" KPI clickable, opening a view that lists every unique
client IP grouped by country (alphabetical, `Unknown` last). Each row shows
IP · city · request count, sorted by requests descending within its country.
Introduce `react-router` and rework the existing frontend onto it, keeping the
current EDGE//WATCH theme and layout unchanged.

## Scope

- **Backend:** one new endpoint `GET /api/callers`. No change to existing
  queries/handlers/auth.
- **Frontend:** add `react-router-dom`, restructure into a layout + routes,
  move shared filter state into URL search params, add the Callers view, make
  the KPI a navigation link. No visual restyling — same theme, tokens, and UI
  primitives.
- **Out of scope:** new query columns, per-IP detail drill-down, any change to
  Athena query logic, infrastructure, or the geo map behavior.

## Theme constraint (binding)

Reuse the existing design system verbatim — no new visual language:
- Tokens/colors: `signal` (#c8f135 lime), `cyan` (#39d9c8), `border`, `card`,
  `muted-foreground`, dark surfaces. Type: `font-mono` / `font-display`.
- Primitives: `Card`, `Button`, `Select`, `ToggleGroup` from
  `components/ui/`. Country sections in the Callers view are `Card`-styled
  blocks; rows follow the `TopList.jsx` row idiom (mono, tabular-nums,
  truncate).
- Existing components are not restyled — only their control wiring changes
  (state → URL params).

---

## Backend

### New endpoint: `GET /api/callers`

Params: `source`, `from`, `to` — validated by the existing `API.validate`
(unknown source → 404; bad date → 400). Cached via the existing `API.cached`
with key `callers|<source>|<from>|<to>`.

**Resolution** mirrors the `/api/geo` world hybrid:
1. Run `query.GeoAllIPs(table, from, to)` → rows of `{ip, requests}` (already
   exists; `LIMIT 50000`).
2. For each IP, MaxMind `Geo.Lookup(ip)`:
   - country = `loc.Country` if non-empty, else `"Unknown"`.
   - city = `loc.City` (may be empty string).
3. Group by country.

> Note on the `c_country` path: city always comes from MaxMind regardless, and
> for the active sources `c_country` is unpopulated (see `CLAUDE.md` GeoIP
> section), so grouping uses the MaxMind-resolved country. This keeps the
> endpoint single-path and consistent with the map's drill-down
> (`resolvePoints`). `Unknown` collects every IP MaxMind can't place — so the
> sum of group counts equals the `unique_ips` value from `/api/summary`,
> **except** when distinct IPs exceed `GeoAllIPs`' `LIMIT 50000`, where the
> list is truncated. That bound is far above expected cardinality for these
> sources; if a range ever hits it the Callers total simply caps at 50000 (no
> silent corruption — the geo map already shares the same bound).

**Ordering (server-side):**
- Groups sorted alphabetically by country name; `"Unknown"` forced last.
- IPs within a group sorted by `requests` descending, then `ip` ascending as a
  stable tiebreak.

**Response shape:**
```json
{
  "groups": [
    {
      "country": "FRANCE",
      "count": 3,
      "ips": [
        { "ip": "88.120.4.21", "city": "Paris", "requests": 1204 },
        { "ip": "2.15.88.3",   "city": "Lyon",  "requests": 412 }
      ]
    },
    { "country": "Unknown", "count": 4, "ips": [ ... ] }
  ]
}
```
`count` == `len(ips)` per group. Empty result → `{"groups": []}`.

### Handler/registration changes

- `handlers.go`: register `r.GET("/api/callers", a.callers)`.
- Add `callers(c *gin.Context)` handler following the `geo` handler's shape
  (validate → cached → build payload). Grouping/sorting in a small helper for
  testability, e.g. `groupCallersByCountry(rows []map[string]string) []gin.H`
  using `a.Geo.Lookup`.

### Tests (Go)

Add to `handlers_test.go` (table style, fake `Querier` + fake `Geo` resolver
already used there):
- groups are alphabetical with `Unknown` last;
- within a group IPs are requests-desc (tiebreak ip-asc);
- an IP that resolves to empty country lands in `Unknown`;
- `count` equals `len(ips)`; sum of counts equals number of distinct IPs in;
- empty rows → `{"groups": []}`.

---

## Frontend

### Routing

- Add dependency `react-router-dom` (v7, strict version) to
  `packages/web/package.json`.
- `BrowserRouter` with clean URLs. Justified: the Go embed handler already
  falls back to `index.html` for unknown paths (`internal/web/embed.go`), and
  Vite dev serves the SPA entry for unknown routes — so refresh/deep-link work
  in both dev and prod without `#`.

**Route tree:**
```
<BrowserRouter>
  <Routes>
    <Route element={<Layout/>}>        // Header + <Outlet/>, owns sources + filters
      <Route index element={<Dashboard/>}/>      // "/"
      <Route path="callers" element={<Callers/>}/>  // "/callers"
    </Route>
  </Routes>
</BrowserRouter>
```

### Shared filter state → URL search params

Filters move from `App` `useState` into the URL query string:
`?source=<name>&from=<YYYY-MM-DD>&to=<YYYY-MM-DD>&groupBy=<day|week|month>`.

New hook `lib/useFilters.js` wrapping `useSearchParams`:
- Returns `{ source, from, to, groupBy, range, setSource, setRange, setGroupBy }`.
- `range` is derived from `from/to` for the Select label (reverse of the
  `RANGES` map in `Header.jsx`); `setRange(label)` recomputes `from/to` from
  `dayjs` exactly as `Header.jsx` does today.
- Defaults when params absent: `source` = first available source, `range` =
  `Last 14 days` (`from` = today−14, `to` = today), `groupBy` = `day`. The hook
  writes defaults into the URL on first load (via `setSearchParams(..., {replace:true})`)
  so the URL is always canonical.
- Changing `source` clears the Dashboard's local `country` drill-down (handled
  in `Dashboard`, since `country` is no longer global state).

### Components

| File | Change |
|---|---|
| `App.jsx` | Becomes the router root: `<BrowserRouter><Routes>…`. No state. |
| `components/Layout.jsx` *(new)* | Fetches `/api/sources` (the effect now in `App`), renders `Header` + `<Outlet/>`. Provides filters via `useFilters` and passes `sources` to `Header`. |
| `pages/Dashboard.jsx` *(new)* | The current `<main>` grid extracted from `App` (Kpis, GeoMap, Histogram, StatusDonut, TopList). Owns `country` drill-down via local `useState`. Reads filters via `useFilters`; fetches `/api/summary` and the country-count `/api/geo` (effects moved from `App`). |
| `pages/Callers.jsx` *(new)* | New view (below). |
| `components/Header.jsx` | Controls call `useFilters` setters (`setSource`/`setRange`/`setGroupBy`) instead of a `setState` prop. Still receives `sources` prop. Markup/theme unchanged. |
| `components/Kpis.jsx` | "Unique Callers" card wrapped in a react-router `<Link to={{pathname:'/callers', search}}>` preserving current search params. Add `cursor-pointer` + hover affordance on that card only; other cards unchanged. |
| `components/GeoMap.jsx` | Props change from `state/setState` to `{source, from, to, country, setCountry}` (country now lives in Dashboard). Logic unchanged. |
| `components/Histogram.jsx`, `StatusDonut.jsx`, `TopList.jsx` | Take plain props (`source/from/to/groupBy`, `country`, `summary`) from Dashboard instead of a `state` object. No behavior change. |

> Components keep taking plain props (fed by `Dashboard` from the hook) to
> minimize churn — only `App`, `Header`, and `Kpis` actually touch the router.

### Callers view (`pages/Callers.jsx`)

- Reads filters via `useFilters`; fetches `api('/api/callers', {source, from, to})`
  on filter change.
- Layout: a header strip matching the GeoMap card header idiom — a `◀ Back`
  `Button` (`<Link to={{pathname:'/', search}}>` or `navigate(-1)`), title
  "Unique Callers", and a total-IPs count (sum of group counts).
- Body: scrollable list of country sections. Each section is a `Card`:
  - Section header: country name (mono, uppercase, `tracking`), right-aligned
    `(<count> IPs)` in `muted-foreground`. Collapsible (default expanded;
    chevron from `lucide-react`, local `useState` set of collapsed countries).
  - Rows: `IP` (mono) · `city` (`muted-foreground`, omitted if empty) ·
    `requests` (tabular-nums, right-aligned) — same row idiom as `TopList.jsx`.
- Empty state: "No callers in range" in `muted-foreground`, themed like other
  empty states.

### Frontend quality

- `oxlint` clean (existing convention — no JS test harness in repo).
- No new fonts/colors; bundle impact limited to `react-router-dom` (acceptable;
  vendor chunking via existing `advancedChunks` will place it in a vendor
  group).

---

## Docs

- `monitoring/CLAUDE.md`:
  - Endpoints line: `/api/sources,/access,/geo,/summary` → add `/callers`.
  - `packages/web` line: note the SPA now uses `react-router` (BrowserRouter)
    with routes `/` (dashboard) and `/callers`, and that shared filters live in
    URL search params.

## Testing summary

| Layer | Test |
|---|---|
| Go | `handlers_test.go`: grouping order, Unknown-last, intra-group sort, count integrity, empty case |
| Go | `go vet ./...`, `go test ./...`, `go build` clean |
| Web | `oxlint` clean; manual smoke: KPI link → Callers → Back, refresh on `/callers` preserves filters |

## Open questions

None.
