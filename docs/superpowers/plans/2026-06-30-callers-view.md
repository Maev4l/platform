# Callers View + React Router Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the "Unique Callers" KPI open a view listing every unique client IP grouped by country (alphabetical, `Unknown` last; IP · city · requests), and rework the React frontend onto `react-router` with URL-backed shared filters.

**Architecture:** New Go endpoint `GET /api/callers` reuses the existing `GeoAllIPs` query + MaxMind resolver to group IPs by country server-side. Frontend gains `react-router-dom` (`BrowserRouter`); shared filters (source/from/to/groupBy) move into URL search params via a `useFilters` hook; the dashboard grid and the new Callers view become routes under a shared `Layout`.

**Tech Stack:** Go 1.26 + Gin (`packages/app`); React 18 + Vite 8 (Rolldown) + Tailwind v4 + ECharts + react-router-dom v7, lint via oxlint (`packages/web`).

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-30-callers-view-design.md` is the contract.
- **Theme is binding — no new visual language.** Reuse existing tokens/colors (`signal` #c8f135, `cyan` #39d9c8, `border`, `card`, `muted-foreground`), `font-mono`/`font-display`, and the `Card`/`Button`/`Select`/`ToggleGroup` primitives. Existing components are not restyled — only their control/prop wiring changes.
- **No TypeScript** — JS/JSX only. Use fat-arrow functions. Use `dayjs` (never moment).
- **Strict dependency versions** in `package.json` (no `^`/`~`).
- **Frontend verification is `yarn --cwd packages/web build` + `yarn --cwd packages/web lint` (oxlint) + the stated manual smoke** — the repo has no JS test harness; do not add one.
- **Backend:** Go tests via `go test ./...` from `packages/app`; lint/vet via `go vet ./...`.
- **Endpoint contract:** `GET /api/callers?source=&from=&to=` → `{"groups":[{"country","count","ips":[{"ip","city","requests"}]}]}`; groups alphabetical with `"Unknown"` last; IPs requests-desc then ip-asc; `count == len(ips)`; empty → `{"groups":[]}`.
- All paths below are relative to `/Users/jrsue/dev/repos/platform/monitoring`.
- **Commit messages** end with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Stay on `main` (per user's standing instruction for this app).

---

## File Structure

**Backend (`packages/app`):**
- `internal/handlers/handlers.go` — add `callers` handler + `groupCallersByCountry` helper + route registration.
- `internal/handlers/handlers_test.go` — add grouping/order/empty tests + a map-backed fake resolver.

**Frontend (`packages/web`):**
- `package.json` — add `react-router-dom` (strict pin).
- `vite.config.js` — add react-router to the `react` vendor chunk group.
- `src/lib/useFilters.js` *(new)* — URL-search-param-backed shared filters hook + `RANGES`.
- `src/App.jsx` — becomes the router root.
- `src/components/Layout.jsx` *(new)* — sources fetch + `Header` + `<Outlet/>`.
- `src/pages/Dashboard.jsx` *(new)* — current main grid, owns `country` drill-down.
- `src/pages/Callers.jsx` *(new)* — country-grouped unique-IP list.
- `src/components/Header.jsx` — controls drive `useFilters` setters.
- `src/components/Kpis.jsx` — "Unique Callers" becomes a `<Link>`.
- `src/components/GeoMap.jsx`, `Histogram.jsx`, `TopList.jsx` — discrete props instead of a `state` object. (`StatusDonut.jsx` already takes `{summary}` — unchanged.)

**Docs:**
- `CLAUDE.md` — endpoints list + web routing note.

---

### Task 1: Backend `GET /api/callers` endpoint

**Files:**
- Modify: `internal/handlers/handlers.go` (register route; add `callers` + `groupCallersByCountry`)
- Test: `internal/handlers/handlers_test.go` (add fake resolver + two tests)

**Interfaces:**
- Consumes (existing): `query.GeoAllIPs(table, from, to) (string, []string)`; `API.validate`, `API.cached`, `API.Geo.Lookup(ip) (geo.Location, bool)`, `atoi`.
- Produces: `func (a *API) callers(c *gin.Context)`; `func (a *API) groupCallersByCountry(rows []map[string]string) []gin.H`; route `GET /api/callers`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/handlers/handlers_test.go` (a map-backed resolver so some IPs resolve and one does not):

```go
// mapGeo resolves only the IPs present in the map; absent IPs → not found,
// exercising the "Unknown" grouping path.
type mapGeo map[string]geo.Location

func (m mapGeo) Lookup(ip string) (geo.Location, bool) {
	loc, ok := m[ip]
	return loc, ok
}

func newAPIGeo(rows []map[string]string, g geo.Resolver) *API {
	return &API{
		Cfg:   &config.Config{Sources: map[string]config.Source{"bl-site": {Name: "bl-site", Table: "bl_site"}}},
		Q:     fakeQ{rows: rows},
		Geo:   g,
		Cache: cache.New(time.Minute),
	}
}

func TestCallersGrouping(t *testing.T) {
	rows := []map[string]string{
		{"ip": "1.1.1.1", "requests": "10"},
		{"ip": "2.2.2.2", "requests": "50"},
		{"ip": "3.3.3.3", "requests": "20"},
		{"ip": "9.9.9.9", "requests": "5"}, // unresolved → Unknown
	}
	g := mapGeo{
		"1.1.1.1": {City: "Lyon", Country: "FR", Lat: 45.7, Lng: 4.8},
		"2.2.2.2": {City: "Paris", Country: "FR", Lat: 48.8, Lng: 2.3},
		"3.3.3.3": {City: "Berlin", Country: "DE", Lat: 52.5, Lng: 13.4},
	}
	w := do(newAPIGeo(rows, g), "/api/callers?source=bl-site&from=2026-06-01&to=2026-06-27")
	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var got struct {
		Groups []struct {
			Country string `json:"country"`
			Count   int    `json:"count"`
			IPs     []struct {
				IP       string `json:"ip"`
				City     string `json:"city"`
				Requests int    `json:"requests"`
			} `json:"ips"`
		} `json:"groups"`
	}
	json.Unmarshal(w.Body.Bytes(), &got)

	// Alphabetical (DE, FR) then Unknown last.
	if len(got.Groups) != 3 || got.Groups[0].Country != "DE" ||
		got.Groups[1].Country != "FR" || got.Groups[2].Country != "Unknown" {
		t.Fatalf("bad group order: %+v", got.Groups)
	}
	// FR group: requests-desc → Paris(50) before Lyon(10), city carried through.
	fr := got.Groups[1]
	if fr.Count != 2 || len(fr.IPs) != 2 ||
		fr.IPs[0].IP != "2.2.2.2" || fr.IPs[0].Requests != 50 || fr.IPs[0].City != "Paris" ||
		fr.IPs[1].IP != "1.1.1.1" {
		t.Fatalf("bad FR group: %+v", fr)
	}
	// Unknown group: the unresolved IP, empty city.
	unk := got.Groups[2]
	if unk.Count != 1 || unk.IPs[0].IP != "9.9.9.9" || unk.IPs[0].City != "" {
		t.Fatalf("bad Unknown group: %+v", unk)
	}
	// Count integrity: count == len(ips) per group; sum == distinct IPs.
	sum := 0
	for _, grp := range got.Groups {
		if grp.Count != len(grp.IPs) {
			t.Fatalf("count != len(ips) for %s", grp.Country)
		}
		sum += grp.Count
	}
	if sum != len(rows) {
		t.Fatalf("sum of counts %d != distinct IPs %d", sum, len(rows))
	}
}

func TestCallersEmpty(t *testing.T) {
	w := do(newAPIGeo(nil, mapGeo{}), "/api/callers?source=bl-site&from=2026-06-01&to=2026-06-27")
	var got struct {
		Groups []any `json:"groups"`
	}
	json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != 200 || len(got.Groups) != 0 {
		t.Fatalf("want 200 + empty groups, got %d %+v", w.Code, got.Groups)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/app && go test ./internal/handlers/ -run TestCallers -v`
Expected: FAIL to compile — `a.callers` / route undefined (`404` or build error referencing missing handler).

- [ ] **Step 3: Register the route**

In `internal/handlers/handlers.go`, inside `Register`, add the line after the `/api/summary` registration:

```go
	r.GET("/api/summary", a.summary)
	r.GET("/api/callers", a.callers)
```

- [ ] **Step 4: Add the handler and grouping helper**

In `internal/handlers/handlers.go`, add after the `summary` handler (and before `func atoi`):

```go
// unknownCountry buckets IPs MaxMind can't place, so the Callers total
// reconciles with the unique-IPs KPI. Forced last in the grouped output.
const unknownCountry = "Unknown"

// callers returns every unique client IP grouped by country for the source and
// date range, reached from the "Unique Callers" KPI. IPs are resolved to
// country+city via MaxMind — the same basis as the geo drill-down.
func (a *API) callers(c *gin.Context) {
	src, from, to, ok := a.validate(c)
	if !ok {
		return
	}
	sql, args := query.GeoAllIPs(src.Table, from, to)
	a.cached(c, "callers|"+src.Name+"|"+from+"|"+to, func(ctx context.Context) (any, error) {
		rows, err := a.Q.Query(ctx, sql, args)
		if err != nil {
			return nil, err
		}
		return gin.H{"groups": a.groupCallersByCountry(rows)}, nil
	})
}

// groupCallersByCountry turns {ip,requests} rows into country groups. Country
// falls back to "Unknown" when MaxMind can't place an IP. Groups are sorted
// alphabetically with "Unknown" forced last; IPs within a group are sorted by
// requests descending, with ip ascending as a stable tiebreak.
func (a *API) groupCallersByCountry(rows []map[string]string) []gin.H {
	type caller struct {
		ip       string
		city     string
		requests int
	}
	groups := map[string][]caller{}
	for _, r := range rows {
		country, city := unknownCountry, ""
		if loc, found := a.Geo.Lookup(r["ip"]); found && loc.Country != "" {
			country, city = loc.Country, loc.City
		}
		groups[country] = append(groups[country], caller{ip: r["ip"], city: city, requests: atoi(r["requests"])})
	}

	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == unknownCountry || names[j] == unknownCountry {
			return names[j] == unknownCountry // push Unknown to the end
		}
		return names[i] < names[j]
	})

	out := make([]gin.H, 0, len(names))
	for _, name := range names {
		cs := groups[name]
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].requests != cs[j].requests {
				return cs[i].requests > cs[j].requests
			}
			return cs[i].ip < cs[j].ip
		})
		ips := make([]gin.H, 0, len(cs))
		for _, x := range cs {
			ips = append(ips, gin.H{"ip": x.ip, "city": x.city, "requests": x.requests})
		}
		out = append(out, gin.H{"country": name, "count": len(cs), "ips": ips})
	}
	return out
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd packages/app && go test ./internal/handlers/ -run TestCallers -v`
Expected: PASS (both `TestCallersGrouping` and `TestCallersEmpty`).

- [ ] **Step 6: Vet + full backend test sweep**

Run: `cd packages/app && go vet ./... && go test ./...`
Expected: no vet output; all packages `ok`.

- [ ] **Step 7: Commit**

```bash
git add packages/app/internal/handlers/handlers.go packages/app/internal/handlers/handlers_test.go
git commit -m "feat(monitoring): add /api/callers endpoint grouping unique IPs by country

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Frontend foundation — react-router + `useFilters` hook

**Files:**
- Modify: `packages/web/package.json` (add `react-router-dom`)
- Modify: `packages/web/vite.config.js:23` (add react-router to the `react` chunk group)
- Create: `packages/web/src/lib/useFilters.js`

**Interfaces:**
- Produces: `useFilters(sources)` returning `{ source, from, to, groupBy, range, setSource, setRange, setGroupBy }`; named export `RANGES` (object of label → days). Backed by `react-router-dom`'s `useSearchParams`.

- [ ] **Step 1: Add the dependency**

Run: `yarn --cwd packages/web add react-router-dom@7`
Then open `packages/web/package.json` and ensure the added line is an **exact** version (no `^`). It should sit alphabetically in `dependencies`, e.g.:

```json
    "react-router-dom": "7.9.1",
```

(Use whatever 7.x version yarn resolved; just strip any leading `^`.)

- [ ] **Step 2: Verify it installed and builds**

Run: `yarn --cwd packages/web build`
Expected: build succeeds (no missing-module error for react-router-dom).

- [ ] **Step 3: Add react-router to the vendor chunk group**

In `packages/web/vite.config.js`, extend the existing `react` group test (around line 23) so the router ships in the React vendor chunk instead of the app chunk:

```js
          groups: [
            { name: 'echarts', test: /node_modules\/(echarts|zrender)\// },
            { name: 'react', test: /node_modules\/(react|react-dom|react-router|react-router-dom|scheduler)\// },
          ],
```

- [ ] **Step 4: Create the `useFilters` hook**

Create `packages/web/src/lib/useFilters.js`:

```js
import { useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import dayjs from 'dayjs';

// Preset date ranges → number of days back from today (90 = log retention max).
export const RANGES = { 'Last 7 days': 7, 'Last 14 days': 14, 'Last 30 days': 30, 'Last 90 days': 90 };

const today = () => dayjs().format('YYYY-MM-DD');
const daysAgo = (n) => dayjs().subtract(n, 'day').format('YYYY-MM-DD');

// Reverse the from/to span back to a preset label for the Select; falls back to
// the 14-day default label when the span doesn't match a preset.
const rangeLabel = (from, to) => {
  if (to === today()) {
    const days = dayjs(to).diff(dayjs(from), 'day');
    const match = Object.keys(RANGES).find((k) => RANGES[k] === days);
    if (match) return match;
  }
  return 'Last 14 days';
};

// Shared dashboard filters, backed by URL search params so refresh / browser
// Back / deep-link preserve them and the /callers route inherits the same
// selection. `sources` is used only for the first-source default and to gate
// canonicalization until the source list has loaded.
export const useFilters = (sources) => {
  const [params, setParams] = useSearchParams();

  const source = params.get('source') || sources?.[0] || '';
  const from = params.get('from') || daysAgo(14);
  const to = params.get('to') || today();
  const groupBy = params.get('groupBy') || 'day';

  // Write the effective defaults into the URL once the source list is known, so
  // the URL is always canonical (a bare refresh on /callers keeps the filters).
  // Guarded on `missing`, so it no-ops after the first write — no render loop.
  useEffect(() => {
    if (!sources || sources.length === 0) return;
    const missing = !params.get('source') || !params.get('from') || !params.get('to') || !params.get('groupBy');
    if (!missing) return;
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      if (!p.get('source')) p.set('source', sources[0]);
      if (!p.get('from')) p.set('from', daysAgo(14));
      if (!p.get('to')) p.set('to', today());
      if (!p.get('groupBy')) p.set('groupBy', 'day');
      return p;
    }, { replace: true });
  }, [sources, params, setParams]);

  const patch = useCallback((next) => {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      Object.entries(next).forEach(([k, v]) => p.set(k, v));
      return p;
    }, { replace: true });
  }, [setParams]);

  const setSource = useCallback((v) => patch({ source: v }), [patch]);
  const setGroupBy = useCallback((v) => patch({ groupBy: v }), [patch]);
  const setRange = useCallback((label) => {
    const days = RANGES[label] ?? 14;
    patch({ from: daysAgo(days), to: today() });
  }, [patch]);

  return { source, from, to, groupBy, range: rangeLabel(from, to), setSource, setRange, setGroupBy };
};
```

- [ ] **Step 5: Lint**

Run: `yarn --cwd packages/web lint`
Expected: oxlint reports no errors.

- [ ] **Step 6: Commit**

```bash
git add packages/web/package.json packages/web/yarn.lock packages/web/vite.config.js packages/web/src/lib/useFilters.js
git commit -m "feat(monitoring): add react-router-dom and URL-backed useFilters hook

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Router restructure — Layout + Dashboard, rewire existing components

Moves the current single-screen dashboard onto the router with no visual or behavioral change: same grid, same theme, same data. Filters come from `useFilters`; the country drill-down becomes Dashboard-local state.

**Files:**
- Modify: `packages/web/src/App.jsx` (becomes router root)
- Create: `packages/web/src/components/Layout.jsx`
- Create: `packages/web/src/pages/Dashboard.jsx`
- Modify: `packages/web/src/components/Header.jsx` (controls → `useFilters` setters)
- Modify: `packages/web/src/components/GeoMap.jsx` (props `{source,from,to,country,setCountry}`)
- Modify: `packages/web/src/components/Histogram.jsx` (props `{source,from,to,groupBy}`)
- Modify: `packages/web/src/components/TopList.jsx` (props `{source,from,to,country,summary}`)

**Interfaces:**
- Consumes: `useFilters` (Task 2); existing `api`, `useApiLoading`, `Select`, `ToggleGroup`, `Card`, `Button`, `Kpis`, `StatusDonut`.
- Produces: `Layout` (named export) rendering `<Outlet context={sources}/>`; `Dashboard` (default export); reworked prop shapes for `Header({sources})`, `GeoMap({source,from,to,country,setCountry})`, `Histogram({source,from,to,groupBy})`, `TopList({source,from,to,country,summary})`.

- [ ] **Step 1: Replace `App.jsx` with the router root**

Overwrite `packages/web/src/App.jsx`:

```jsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import Dashboard from '@/pages/Dashboard';
import Callers from '@/pages/Callers';

// BrowserRouter (clean URLs): the Go embed handler falls back to index.html for
// unknown paths (internal/web/embed.go) and Vite dev serves the SPA entry, so
// refresh / deep-link work in both dev and prod without a hash.
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="callers" element={<Callers />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
```

> Note: `Callers` (`@/pages/Callers`) is created in Task 4. To keep this task's build green, create a one-line placeholder now and replace it in Task 4:
> Create `packages/web/src/pages/Callers.jsx` with:
> ```jsx
> export default function Callers() { return null; }
> ```

- [ ] **Step 2: Create `Layout.jsx`**

Create `packages/web/src/components/Layout.jsx`:

```jsx
import { useEffect, useState } from 'react';
import { Outlet } from 'react-router-dom';
import { api } from '@/lib/api';
import { Header } from '@/components/Header';

// App shell: fetches the source list once and renders the shared Header plus
// the active route. `sources` is passed to routed pages via Outlet context so
// they (and Header) can resolve the first-source default for useFilters.
export const Layout = () => {
  const [sources, setSources] = useState([]);

  useEffect(() => {
    api('/api/sources')
      // Guard against a non-array response (unexpected API shape on error).
      .then((s) => setSources(Array.isArray(s) ? s : []))
      .catch((err) => console.error('sources fetch failed', err));
  }, []);

  return (
    <div className="flex h-screen flex-col">
      <Header sources={sources} />
      <Outlet context={sources} />
    </div>
  );
};
```

- [ ] **Step 3: Create `Dashboard.jsx`**

Create `packages/web/src/pages/Dashboard.jsx` (the grid lifted from the old `App.jsx`, with `country` now local state):

```jsx
import { useEffect, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { api } from '@/lib/api';
import { useFilters } from '@/lib/useFilters';
import { Kpis } from '@/components/Kpis';
import { GeoMap } from '@/components/GeoMap';
import { Histogram } from '@/components/Histogram';
import { StatusDonut } from '@/components/StatusDonut';
import { TopList } from '@/components/TopList';

export default function Dashboard() {
  const sources = useOutletContext();
  const { source, from, to, groupBy } = useFilters(sources);
  const [country, setCountry] = useState(''); // map drill-down (view-only, dashboard-local)
  const [summary, setSummary] = useState(null);
  const [countryCount, setCountryCount] = useState(0);

  // Reset the drill-down when the source changes (old Header did this inline).
  useEffect(() => { setCountry(''); }, [source]);

  useEffect(() => {
    if (!source) return;
    api('/api/summary', { source, from, to })
      .then(setSummary)
      .catch((err) => console.error('summary fetch failed', err));
  }, [source, from, to]);

  // "Countries" KPI = count of countries in the IP-resolved world geo (matches
  // the map's dots); the summary query no longer counts c_country.
  useEffect(() => {
    if (!source) return;
    api('/api/geo', { source, from, to })
      .then((d) => setCountryCount(d?.countries?.length ?? 0))
      .catch((err) => console.error('country count fetch failed', err));
  }, [source, from, to]);

  return (
    <main className="grid flex-1 grid-cols-[1fr_340px] grid-rows-[auto_1fr_auto] gap-3.5 p-4 min-h-0">
      <div className="col-span-2"><Kpis summary={summary} countries={countryCount} /></div>
      <GeoMap source={source} from={from} to={to} country={country} setCountry={setCountry} />
      <aside className="flex flex-col gap-3.5 min-h-0">
        <StatusDonut summary={summary} />
        <TopList source={source} from={from} to={to} country={country} summary={summary} />
      </aside>
      <div className="col-span-2"><Histogram source={source} from={from} to={to} groupBy={groupBy} /></div>
    </main>
  );
}
```

- [ ] **Step 4: Rewire `Header.jsx` to `useFilters`**

Overwrite `packages/web/src/components/Header.jsx`:

```jsx
import { Loader2 } from 'lucide-react';
import { Select } from '@/components/ui/Select';
import { ToggleGroup } from '@/components/ui/ToggleGroup';
import { useApiLoading } from '@/lib/api';
import { useFilters, RANGES } from '@/lib/useFilters';

export const Header = ({ sources }) => {
  const loading = useApiLoading();
  const { source, range, groupBy, setSource, setRange, setGroupBy } = useFilters(sources);
  return (
    <header className="flex h-[58px] items-center gap-6 border-b border-border px-5">
      <div className="flex items-center gap-2">
        <span className="text-signal text-lg drop-shadow-[0_0_6px_rgba(200,241,53,.6)]">◢</span>
        <div>
          <div className="font-display text-base font-extrabold">EDGE<span className="text-signal">//</span>WATCH</div>
          <div className="font-mono text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground">cloudfront access telemetry</div>
        </div>
      </div>
      <div className="ml-auto flex items-center gap-3">
        <Select value={source} onChange={setSource} options={sources} className="w-[230px]" />
        <Select value={range} onChange={setRange} options={Object.keys(RANGES)} className="w-[150px]" />
        <ToggleGroup
          value={groupBy}
          onChange={setGroupBy}
          items={[{ value: 'day', label: 'Day' }, { value: 'week', label: 'Week' }, { value: 'month', label: 'Month' }]}
        />
        {/* In-flight indicator: spinner while any /api request runs, else a live dot. */}
        <span className="flex w-[88px] items-center justify-end gap-2 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
          {loading ? (
            <><Loader2 className="h-3.5 w-3.5 animate-spin text-signal" />querying</>
          ) : (
            <><span className="h-[7px] w-[7px] rounded-full bg-signal" />live</>
          )}
        </span>
      </div>
    </header>
  );
};
```

- [ ] **Step 5: Rewire `GeoMap.jsx` to discrete props**

In `packages/web/src/components/GeoMap.jsx`, change only the component signature, the click/Back handlers, and the effect deps (chart/option logic unchanged). Replace the component body's wiring:

Signature:
```jsx
export const GeoMap = ({ source, from, to, country, setCountry }) => {
```

Click handler (inside the init effect) — replace the `setState(...)` call:
```jsx
      chart.current.on('click', (p) => {
        if (p.seriesType === 'effectScatter' && p.data?.code) {
          setCountry(p.data.code);
        }
      });
```
…and change that effect's dependency array from `[setState]` to `[setCountry]`.

Data effect — replace `state.*` reads and deps:
```jsx
  useEffect(() => {
    if (loading || !source) return;
    const c = chart.current;
    if (!country) {
      api('/api/geo', { source, from, to })
        .then((d) => {
          if (!c || c.isDisposed()) return;
          const data = (d?.countries ?? []).filter((x) => CENTROIDS[x.country]).map((x) => ({ name: CENTROIDS[x.country].name, code: x.country, value: [...CENTROIDS[x.country].coord, x.callers] }));
          c.setOption(worldOption(data), true);
        })
        .catch((err) => console.error('geo world fetch failed', err));
    } else {
      api('/api/geo', { source, from, to, country })
        .then((d) => {
          if (!c || c.isDisposed()) return;
          const data = (d?.points ?? []).map((p) => ({ name: `${p.city} · ${p.ip}`, value: [p.lng, p.lat, p.requests] }));
          c.setOption(countryOption(data, CENTROIDS[country]?.coord || [0, 20]), true);
        })
        .catch((err) => console.error('geo drill fetch failed', err));
    }
  }, [loading, source, from, to, country]);
```

Header strip — replace `state.country` reads and the Back handler:
```jsx
      <div className="flex items-center gap-3 border-b border-border px-3.5 py-2.5 font-mono text-[11px]">
        {country && <Button variant="outline" size="sm" onClick={() => setCountry('')}>◀ Back</Button>}
        <span className={country ? 'text-muted-foreground' : 'text-signal uppercase tracking-[0.1em]'}>Global View</span>
        {country && <><span className="text-muted-foreground">▸</span><span className="text-signal uppercase tracking-[0.1em]">{country}</span></>}
      </div>
```

- [ ] **Step 6: Rewire `Histogram.jsx` to discrete props**

In `packages/web/src/components/Histogram.jsx`, change the signature and the data effect (chart setup + option unchanged):

```jsx
export const Histogram = ({ source, from, to, groupBy }) => {
```
```jsx
  useEffect(() => {
    if (!source) return;
    api('/api/access', { source, from, to, groupBy })
      .then((d) => {
        if (!d?.buckets) return;
        if (!chart.current || chart.current.isDisposed()) return;
        const x = d.buckets.map((b) => fmtBucket(b.t));
        const series = ['s2', 's3', 's4', 's5'].map((k) => ({ name: k, type: 'bar', stack: 't', barWidth: '58%', data: d.buckets.map((b) => b[k]), itemStyle: { color: COLORS[k] } }));
        chart.current.setOption({
          tooltip: { trigger: 'axis', backgroundColor: '#0c0e12', borderColor: '#1c2129', textStyle: { color: '#e7ebef', fontFamily: '"IBM Plex Mono", monospace', fontSize: 11 } },
          grid: { left: 54, right: 18, top: 14, bottom: 24 },
          xAxis: { type: 'category', data: x, axisLine: { lineStyle: { color: '#1c2129' } }, axisTick: { show: false }, axisLabel: { color: '#5c6470', fontFamily: '"IBM Plex Mono", monospace', fontSize: 10 } },
          yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(255,255,255,.04)' } }, axisLabel: { color: '#5c6470', fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, formatter: (v) => (v >= 1000 ? v / 1000 + 'k' : v) } },
          series,
        }, true);
      })
      .catch((err) => console.error('access fetch failed', err));
  }, [source, from, to, groupBy]);
```

- [ ] **Step 7: Rewire `TopList.jsx` to discrete props**

Overwrite `packages/web/src/components/TopList.jsx`:

```jsx
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Card } from '@/components/ui/Card';

export const TopList = ({ source, from, to, country, summary }) => {
  const [items, setItems] = useState([]);
  const [title, setTitle] = useState('Top URIs');

  useEffect(() => {
    if (country) {
      setTitle(`Top Callers · ${country}`);
      api('/api/geo', { source, from, to, country })
        // Guard against missing points array (e.g. empty/malformed API response)
        .then((d) => setItems((d?.points ?? []).slice(0, 12).map((p) => ({ label: p.ip, sub: p.city, n: p.requests }))))
        .catch((err) => console.error('geo drill fetch failed', err));
    } else {
      setTitle('Top URIs');
      setItems((summary?.topUris ?? []).map((u) => ({ label: u.uri, sub: '', n: u.hits })));
    }
  }, [country, source, from, to, summary]);

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

- [ ] **Step 8: Build + lint**

Run: `yarn --cwd packages/web build && yarn --cwd packages/web lint`
Expected: build succeeds; oxlint reports no errors.

- [ ] **Step 9: Manual smoke**

Run `make run` (from `monitoring/`). Confirm: dashboard renders identically to before at `/`; changing source/range/groupBy updates the URL query string and the charts; clicking a country dot drills in and `◀ Back` returns; a browser refresh preserves the selected source/range (URL params). 

- [ ] **Step 10: Commit**

```bash
git add packages/web/src/App.jsx packages/web/src/components/Layout.jsx packages/web/src/pages/Dashboard.jsx packages/web/src/pages/Callers.jsx packages/web/src/components/Header.jsx packages/web/src/components/GeoMap.jsx packages/web/src/components/Histogram.jsx packages/web/src/components/TopList.jsx
git commit -m "refactor(monitoring): move dashboard onto react-router with URL-backed filters

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Callers view + clickable KPI

**Files:**
- Modify: `packages/web/src/pages/Callers.jsx` (replace the placeholder from Task 3)
- Modify: `packages/web/src/components/Kpis.jsx` ("Unique Callers" → `<Link>`)

**Interfaces:**
- Consumes: `/api/callers` (Task 1); `useFilters` (Task 2); `useOutletContext`, `Link`, `useLocation` from react-router-dom; `Card`, `Button`; `ChevronDown`/`ChevronRight` from lucide-react.
- Produces: `Callers` (default export) rendering the country-grouped list; `Kpis` with the second card linking to `/callers` preserving the current search string.

- [ ] **Step 1: Implement the Callers page**

Overwrite `packages/web/src/pages/Callers.jsx`:

```jsx
import { useEffect, useState } from 'react';
import { Link, useLocation, useOutletContext } from 'react-router-dom';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { api } from '@/lib/api';
import { useFilters } from '@/lib/useFilters';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';

// Unique client IPs grouped by country (alphabetical, "Unknown" last), reached
// from the "Unique Callers" KPI. Honors the same source/date filters as the
// dashboard (URL search params), so the Back link round-trips cleanly.
export default function Callers() {
  const sources = useOutletContext();
  const { source, from, to } = useFilters(sources);
  const { search } = useLocation();
  const [groups, setGroups] = useState([]);
  const [collapsed, setCollapsed] = useState(() => new Set());

  useEffect(() => {
    if (!source) return;
    api('/api/callers', { source, from, to })
      // Guard against a missing/malformed groups array.
      .then((d) => setGroups(Array.isArray(d?.groups) ? d.groups : []))
      .catch((err) => console.error('callers fetch failed', err));
  }, [source, from, to]);

  const total = groups.reduce((n, g) => n + (g.count ?? 0), 0);
  const toggle = (country) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(country)) next.delete(country);
      else next.add(country);
      return next;
    });

  return (
    <main className="flex flex-1 flex-col gap-3.5 p-4 min-h-0">
      <div className="flex items-center gap-3 font-mono text-[11px]">
        <Link to={{ pathname: '/', search }}><Button variant="outline" size="sm">◀ Back</Button></Link>
        <span className="text-signal uppercase tracking-[0.1em]">Unique Callers</span>
        <span className="text-muted-foreground">
          {total.toLocaleString()} ip across {groups.length} {groups.length === 1 ? 'country' : 'countries'}
        </span>
      </div>

      <div className="flex flex-1 flex-col gap-3.5 overflow-auto min-h-0">
        {groups.length === 0 && (
          <div className="font-mono text-[11px] text-muted-foreground">No callers in range</div>
        )}
        {groups.map((g) => {
          const isCollapsed = collapsed.has(g.country);
          return (
            <Card key={g.country}>
              <button
                type="button"
                onClick={() => toggle(g.country)}
                className="flex w-full items-center justify-between border-b border-border px-3.5 py-2.5 font-mono text-[10.5px] uppercase tracking-[0.2em]"
              >
                <span className="flex items-center gap-2 text-foreground">
                  {isCollapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                  {g.country}
                </span>
                <span className="text-muted-foreground">{g.count} {g.count === 1 ? 'ip' : 'ips'}</span>
              </button>
              {!isCollapsed && (
                <div className="py-1.5">
                  {g.ips.map((ip) => (
                    <div key={ip.ip} className="flex items-baseline justify-between gap-3 px-3.5 py-1.5 font-mono text-[11.5px]">
                      <span className="truncate text-foreground">{ip.ip}</span>
                      {ip.city && <span className="flex-1 truncate text-[10px] text-muted-foreground">{ip.city}</span>}
                      <span className="tabular-nums text-muted-foreground">{ip.requests.toLocaleString()} req</span>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </main>
  );
}
```

- [ ] **Step 2: Make the "Unique Callers" KPI a link**

Overwrite `packages/web/src/components/Kpis.jsx`:

```jsx
import { Link, useLocation } from 'react-router-dom';
import { Card } from '@/components/ui/Card';

const Kpi = ({ label, value, unit, accent }) => (
  <Card className="relative h-full overflow-hidden p-4">
    <span className={`absolute left-0 top-0 h-full w-[3px] ${accent ? 'bg-signal shadow-[0_0_10px_rgba(200,241,53,.5)]' : 'bg-border'}`} />
    <div className="font-mono text-[9.5px] uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
    <div className={`mt-2 font-mono text-3xl font-semibold tabular-nums ${accent ? 'text-signal' : ''}`}>
      {value}{unit && <span className="ml-1 text-sm text-muted-foreground">{unit}</span>}
    </div>
  </Card>
);

export const Kpis = ({ summary, countries }) => {
  const { search } = useLocation();
  return (
    <div className="grid grid-cols-4 gap-3.5">
      <Kpi label="Total Requests" value={(summary?.total ?? 0).toLocaleString()} accent />
      {/* Clickable → Callers view; preserve the current filters via the search string. */}
      <Link
        to={{ pathname: '/callers', search }}
        aria-label="View unique callers by country"
        className="block transition-transform hover:-translate-y-0.5 [&>div]:hover:border-signal/60"
      >
        <Kpi label="Unique Callers ▸" value={(summary?.uniqueIps ?? 0).toLocaleString()} unit="ip" />
      </Link>
      <Kpi label="Error Rate · 4xx+5xx" value={(summary?.errorRate ?? 0).toFixed(2)} unit="%" />
      {/* Derived from the IP-resolved world geo (matches the map), not c-country. */}
      <Kpi label="Countries" value={countries ?? 0} />
    </div>
  );
};
```

- [ ] **Step 3: Build + lint**

Run: `yarn --cwd packages/web build && yarn --cwd packages/web lint`
Expected: build succeeds; oxlint reports no errors.

- [ ] **Step 4: Manual smoke**

Run `make run`. Confirm: the "Unique Callers ▸" KPI is hover-highlighted and clickable; clicking navigates to `/callers` with the same `?source=&from=&to=&groupBy=` query; the list shows countries alphabetically with `Unknown` last, each row IP · city · requests, sorted by requests desc; section headers collapse/expand; the total reads "N ip across M countries"; `◀ Back` returns to the dashboard with filters intact; refreshing on `/callers` preserves filters and re-renders the list.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/pages/Callers.jsx packages/web/src/components/Kpis.jsx
git commit -m "feat(monitoring): add country-grouped Callers view from the Unique Callers KPI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Docs

**Files:**
- Modify: `monitoring/CLAUDE.md`

- [ ] **Step 1: Update the endpoints line**

In `CLAUDE.md`, change the endpoints line (currently `Endpoints: \`/api/sources,/access,/geo,/summary\`.`) to:

```
  Endpoints: `/api/sources,/access,/geo,/summary,/callers`.
```

- [ ] **Step 2: Update the `packages/web` description**

Change the `packages/web` bullet to note the router and routes:

```
- `packages/web` — React 18 + Vite + Tailwind v4 + ECharts + **react-router**
  (BrowserRouter; routes `/` dashboard, `/callers` unique callers by country).
  Shared filters (source/date/groupBy) live in URL search params. Lints with
  **oxlint** (`.oxlintrc.json`).
```

- [ ] **Step 3: Verify**

Run: `grep -n "callers" CLAUDE.md`
Expected: matches on both the endpoints line and the `packages/web` line.

- [ ] **Step 4: Commit**

```bash
git add monitoring/CLAUDE.md
git commit -m "docs(monitoring): document /api/callers and react-router routing

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- New `GET /api/callers`, server-side grouping, `Unknown` last, requests-desc, count integrity, empty case → Task 1. ✅
- `c_country`/MaxMind basis (single-path via `GeoAllIPs` + `Geo.Lookup`) → Task 1 handler. ✅
- react-router-dom v7 + BrowserRouter; rationale (embed.go fallback) → Tasks 2–3. ✅
- Filters → URL search params via `useFilters`; defaults canonicalized; source change clears drill-down → Tasks 2 (hook), 3 (Dashboard effect). ✅
- Route tree Layout → Dashboard `/`, Callers `/callers` → Tasks 3–4. ✅
- Component rework table (App/Layout/Dashboard/Header/Kpis/GeoMap/Histogram/TopList; StatusDonut unchanged) → Tasks 3–4. ✅
- Callers view layout (Back, title, total, collapsible Card sections, IP·city·requests rows, empty state) → Task 4. ✅
- KPI `<Link>` preserving search → Task 4. ✅
- Theme reuse / no restyle → enforced via Global Constraints + verbatim markup. ✅
- Vendor chunking of react-router → Task 2 Step 3. ✅
- Docs (endpoints + routing note) → Task 5. ✅
- 50000-IP truncation caveat: inherited from existing `GeoAllIPs`; no code needed (documented in spec). ✅

**2. Placeholder scan:** No TBD/TODO/"handle errors". The only intentional stub is the `Callers.jsx` one-liner in Task 3 Step 1, explicitly replaced in Task 4 Step 1 (needed so Task 3 builds independently). ✅

**3. Type/name consistency:** `useFilters` shape `{source,from,to,groupBy,range,setSource,setRange,setGroupBy}` + `RANGES` consistent across Tasks 2–4. Prop shapes match between Dashboard (Task 3 Step 3) and the rewired GeoMap/Histogram/TopList (Steps 5–7). `groupCallersByCountry` / `callers` / route string consistent between handler (Task 1) and frontend call (Task 4). `unknownCountry = "Unknown"` matches the frontend's reliance on `"Unknown"` sorting last (server-enforced; frontend just renders order). ✅
