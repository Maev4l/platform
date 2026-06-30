# GeoLite2-ASN + AS Org in Callers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auto-download MaxMind GeoLite2-ASN the same way as GeoLite2-City and show each caller's AS organization inline (`IP · city · org · requests`) in the unique-IP-by-country list.

**Architecture:** Parameterize the existing GeoIP updater by edition; gate the ASN download behind the same license-key/auto-update flags; add a second nil-safe ASN reader to the `geo.MMDB` resolver and expose `ASNOrg` on `geo.Location` (resolved independently of country); thread `asnOrg` through `/api/callers`; render it inline in `Callers.jsx`.

**Tech Stack:** Go 1.26 + Gin, `oschwald/geoip2-golang` (already a dep; `Reader.ASN` returns `AutonomousSystemOrganization`); React 18 + Vite + Tailwind + oxlint.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-30-asn-org-callers-design.md` is the contract.
- Mirror the existing City wiring exactly: **same** `GEOIP_LICENSE_KEY` and `GEOIP_AUTO_UPDATE` gate both DBs — no new flag. Downloads are best-effort (warn, never fatal); a missing ASN DB just means AS org is blank.
- AS **org name only** (not the ASN number); no hostname/reverse-DNS.
- The geo world map and country drill-down (`/api/geo`, `resolvePoints`) must be unchanged — AS org is added only to `/api/callers` and the Callers view.
- `geo.Location.Country` stays the ISO code (the world map/CENTROIDS depend on it); `ASNOrg` is a new field.
- `Lookup`'s returned bool keeps its current meaning ("country resolved"); `ASNOrg` is populated independently of it.
- No TypeScript; fat-arrow; strict dep versions; dayjs not moment. **Theme is binding** — render org with existing tokens, no restyle.
- Go: `go vet ./...` + `go test ./...` green. Web: `yarn --cwd packages/web build` + `yarn --cwd packages/web lint` clean. Runtime smoke (`make run`) needs live AWS SSO + both `.mmdb` files → operator step.
- Paths below are relative to `/Users/jrsue/dev/repos/platform/monitoring`.
- Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Stay on `main`.

## File Structure

- `internal/geo/updater.go` / `updater_test.go` — edition parameter.
- `internal/config/config.go` / `config_test.go` — `GeoIPASNPath`.
- `internal/geo/resolver.go` / `resolver_test.go` — `ASNOrg`, second reader, `LoadASN`, `Lookup` restructure.
- `internal/handlers/handlers.go` / `handlers_test.go` — `asnOrg` in the callers payload.
- `cmd/main.go` — download + open the ASN DB.
- `packages/web/src/pages/Callers.jsx` — inline org.
- `.gitignore`, `packages/app/.gitignore`, `packages/app/.env.example`, `CLAUDE.md` — plumbing/docs.

---

### Task 1: Parameterize the GeoIP updater by edition

**Files:**
- Modify: `packages/app/internal/geo/updater.go`
- Test: `packages/app/internal/geo/updater_test.go`

**Interfaces:**
- Produces: `Update(ctx context.Context, licenseKey, editionID, dbPath string) (bool, error)`; `httpGet(ctx, licenseKey, editionID, suffix string) ([]byte, error)`; `remoteSHA(ctx, licenseKey, editionID string) (string, error)`. The package const `editionID` is removed.

- [ ] **Step 1: Update the failing test to the new signature and assert the edition propagates**

In `updater_test.go`, replace both `Update(context.Background(), "k", dbPath)` calls with the edition arg, and add a test that the request carries the passed `edition_id`. Replace the two call sites inside `TestUpdateDownloadsThenDetectsUpToDate`:

```go
	changed, err := Update(context.Background(), "k", "GeoLite2-City", dbPath)
```
(both occurrences — first update and the second no-op update.)

Then add this new test at the end of the file:

```go
func TestUpdateUsesEditionInURL(t *testing.T) {
	payload := []byte("fake-mmdb-bytes")
	archive := makeArchive(t, payload)
	sum := sha256.Sum256(archive)
	shaHex := hex.EncodeToString(sum[:])

	var gotEdition string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEdition = r.URL.Query().Get("edition_id") // record the edition the client requested
		switch r.URL.Query().Get("suffix") {
		case "tar.gz.sha256":
			w.Write([]byte(shaHex + "  GeoLite2-ASN_20260101.tar.gz\n"))
		case "tar.gz":
			w.Write(archive)
		default:
			http.Error(w, "bad suffix", 400)
		}
	}))
	defer srv.Close()

	old := baseURL
	baseURL = srv.URL
	defer func() { baseURL = old }()

	dbPath := filepath.Join(t.TempDir(), "GeoLite2-ASN.mmdb")
	if _, err := Update(context.Background(), "k", "GeoLite2-ASN", dbPath); err != nil {
		t.Fatalf("update: %v", err)
	}
	if gotEdition != "GeoLite2-ASN" {
		t.Fatalf("edition_id in request = %q, want GeoLite2-ASN", gotEdition)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/app && go test ./internal/geo/ -run TestUpdate -v`
Expected: compile failure — `Update` is called with 4 args but still defined with 3 (and the new test references the not-yet-updated signature).

- [ ] **Step 3: Parameterize the updater**

In `updater.go`: delete the line `const editionID = "GeoLite2-City"`. Change the three functions to take `editionID`:

```go
func httpGet(ctx context.Context, licenseKey, editionID, suffix string) ([]byte, error) {
	u := fmt.Sprintf("%s?edition_id=%s&license_key=%s&suffix=%s", baseURL, editionID, licenseKey, suffix)
```
(rest of `httpGet` unchanged.)

```go
func remoteSHA(ctx context.Context, licenseKey, editionID string) (string, error) {
	b, err := httpGet(ctx, licenseKey, editionID, "tar.gz.sha256")
```
(rest unchanged.)

```go
func Update(ctx context.Context, licenseKey, editionID, dbPath string) (bool, error) {
	remote, err := remoteSHA(ctx, licenseKey, editionID)
```
…and the one other `httpGet` call inside `Update`:
```go
	gz, err := httpGet(ctx, licenseKey, editionID, "tar.gz")
```
Update the doc comment on `Update` to say it downloads "the given MaxMind edition" rather than "GeoLite2-City".

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd packages/app && go test ./internal/geo/ -run TestUpdate -v`
Expected: PASS (`TestUpdateDownloadsThenDetectsUpToDate`, `TestUpdateUsesEditionInURL`).

- [ ] **Step 5: Commit**

```bash
git add packages/app/internal/geo/updater.go packages/app/internal/geo/updater_test.go
git commit -m "refactor(monitoring): parameterize GeoIP updater by edition

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Add `GeoIPASNPath` to config

**Files:**
- Modify: `packages/app/internal/config/config.go`
- Test: `packages/app/internal/config/config_test.go`

**Interfaces:**
- Produces: `Config.GeoIPASNPath string`; env `GEOIP_ASN_DB_PATH`; default `./GeoLite2-ASN.mmdb`.

- [ ] **Step 1: Write the failing test**

Add to `config_test.go`:

```go
func TestGeoIPASNPathDefaultAndOverride(t *testing.T) {
	os.Unsetenv("LOG_SOURCES")
	os.Unsetenv("GEOIP_ASN_DB_PATH")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.GeoIPASNPath != "./GeoLite2-ASN.mmdb" {
		t.Fatalf("default GeoIPASNPath = %q, want ./GeoLite2-ASN.mmdb", c.GeoIPASNPath)
	}
	os.Setenv("GEOIP_ASN_DB_PATH", "/tmp/asn.mmdb")
	t.Cleanup(func() { os.Unsetenv("GEOIP_ASN_DB_PATH") })
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.GeoIPASNPath != "/tmp/asn.mmdb" {
		t.Fatalf("override GeoIPASNPath = %q, want /tmp/asn.mmdb", c.GeoIPASNPath)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/app && go test ./internal/config/ -run TestGeoIPASNPath -v`
Expected: compile failure — `c.GeoIPASNPath` undefined.

- [ ] **Step 3: Implement**

In `config.go`:
- Add to the `Config` struct, after `GeoIPPath`:
```go
	GeoIPASNPath    string
```
- Add to `envMap`:
```go
	"GEOIP_ASN_DB_PATH": "geoip_asn_path",
```
- Add to the confmap defaults (after `"geoip_path": "./GeoLite2-City.mmdb",`):
```go
		"geoip_asn_path": "./GeoLite2-ASN.mmdb",
```
- Populate in the `Config` literal (after `GeoIPPath: k.String("geoip_path"),`):
```go
		GeoIPASNPath:    k.String("geoip_asn_path"),
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd packages/app && go test ./internal/config/ -v`
Expected: PASS (all config tests).

- [ ] **Step 5: Commit**

```bash
git add packages/app/internal/config/config.go packages/app/internal/config/config_test.go
git commit -m "feat(monitoring): add GEOIP_ASN_DB_PATH config (default ./GeoLite2-ASN.mmdb)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Resolver — second reader, `ASNOrg`, country-independent lookup

**Files:**
- Modify: `packages/app/internal/geo/resolver.go`
- Test: `packages/app/internal/geo/resolver_test.go`

**Interfaces:**
- Consumes: `github.com/oschwald/geoip2-golang` `Reader.ASN(ip) (*geoip2.ASN, error)` with field `AutonomousSystemOrganization string`.
- Produces: `geo.Location` field `ASNOrg string` (`json:"asnOrg"`); `func (m *MMDB) LoadASN(path string) error`; `Lookup` returns `ASNOrg` independently of the country bool; `Close()` closes both readers.

**Note on test scope:** the real two-reader `Lookup` needs MaxMind `.mmdb` fixtures we don't vendor, so resolver tests cover `LoadASN` (missing file → error) and nil-safe `Close`. The behavioral contract (org present even when country is absent) is verified at the handler layer in Task 4 via the resolver fake.

- [ ] **Step 1: Write the failing tests**

Add to `resolver_test.go`:

```go
func TestLoadASNMissingFile(t *testing.T) {
	m := New()
	if err := m.LoadASN("/no/such/asn.mmdb"); err == nil {
		t.Fatal("expected error loading missing ASN db")
	}
	// Close must stay nil-safe with no readers loaded.
	if err := m.Close(); err != nil {
		t.Fatalf("Close after failed LoadASN: %v", err)
	}
}

func TestLocationCarriesASNOrg(t *testing.T) {
	// Compile-level + value check that the field exists and round-trips.
	loc := Location{ASNOrg: "Orange S.A."}
	if loc.ASNOrg != "Orange S.A." {
		t.Fatal("ASNOrg not set")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/app && go test ./internal/geo/ -run 'TestLoadASN|TestLocationCarriesASNOrg' -v`
Expected: compile failure — `LoadASN` and `Location.ASNOrg` undefined.

- [ ] **Step 3: Implement the resolver changes**

Rewrite `resolver.go` to this (it is small; replace the whole file):

```go
package geo

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

type Location struct {
	City        string  `json:"city"`
	Country     string  `json:"country"`     // ISO 3166-1 alpha-2 (e.g. "FR") — keyed by the world map / CENTROIDS
	CountryName string  `json:"countryName"` // full English name (e.g. "France") — used by the callers list
	ASNOrg      string  `json:"asnOrg"`      // MaxMind autonomous-system organization (e.g. "Orange S.A.")
	Lat         float64 `json:"lat"`
	Lng         float64 `json:"lng"`
}

type Resolver interface {
	Lookup(ip string) (Location, bool)
}

// MMDB resolves an IP via two optional MaxMind readers: City (geo) and ASN
// (organization). Either may be nil — a nil reader simply contributes no data,
// so the app starts and degrades gracefully when a .mmdb is absent.
type MMDB struct {
	city *geoip2.Reader
	asn  *geoip2.Reader
}

// New returns a resolver with no databases loaded. Lookup returns false for
// every IP until a City DB is opened via Open (and optionally an ASN DB via
// LoadASN).
func New() *MMDB { return &MMDB{} }

func Open(path string) (*MMDB, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &MMDB{city: db}, nil
}

// LoadASN attaches a GeoLite2-ASN reader to this resolver. On error the resolver
// keeps asn == nil (AS org is then simply absent from results).
func (m *MMDB) LoadASN(path string) error {
	db, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	m.asn = db
	return nil
}

// Lookup resolves country/city (City DB) and AS organization (ASN DB)
// independently. The returned bool means "country resolved" (the world map
// relies on this); ASNOrg is populated whenever the ASN DB has data, even when
// the country is unknown — so an unplaceable IP still carries its org.
func (m *MMDB) Lookup(ipStr string) (Location, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Location{}, false
	}
	var loc Location
	countryOK := false
	if m.city != nil {
		// Require a resolved country (the world map groups by it). Coordinates
		// may be missing/zero for some IPs — fine for the world view; the
		// drill-down skips zero-coord points itself.
		if rec, err := m.city.City(ip); err == nil && rec != nil && rec.Country.IsoCode != "" {
			loc.City = rec.City.Names["en"]
			loc.Country = rec.Country.IsoCode
			loc.CountryName = rec.Country.Names["en"]
			loc.Lat = rec.Location.Latitude
			loc.Lng = rec.Location.Longitude
			countryOK = true
		}
	}
	if m.asn != nil {
		if rec, err := m.asn.ASN(ip); err == nil && rec != nil {
			loc.ASNOrg = rec.AutonomousSystemOrganization
		}
	}
	return loc, countryOK
}

// Close closes both readers; each is nil-safe (a resolver from New() or one
// without an ASN DB closes cleanly).
func (m *MMDB) Close() error {
	if m.city != nil {
		if err := m.city.Close(); err != nil {
			return err
		}
	}
	if m.asn != nil {
		return m.asn.Close()
	}
	return nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd packages/app && go test ./internal/geo/ -v`
Expected: PASS (existing `TestResolverInterface`, `TestOpenMissingFile`, `TestNewResolverLookupReturnsFalse`, `TestUpdate*`, plus the two new tests).

- [ ] **Step 5: Commit**

```bash
git add packages/app/internal/geo/resolver.go packages/app/internal/geo/resolver_test.go
git commit -m "feat(monitoring): resolve AS org via a second nil-safe ASN reader

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Thread `asnOrg` through `/api/callers`

**Files:**
- Modify: `packages/app/internal/handlers/handlers.go`
- Test: `packages/app/internal/handlers/handlers_test.go`

**Interfaces:**
- Consumes: `geo.Location.ASNOrg` (Task 3).
- Produces: each IP object in `/api/callers` gains `"asnOrg"`.

- [ ] **Step 1: Update the test fake and add the failing test**

In `handlers_test.go`, change `mapGeo.Lookup` so its `found` bool mirrors the real resolver (found == country resolved), enabling an "org but no country" case:

```go
func (m mapGeo) Lookup(ip string) (geo.Location, bool) {
	loc, ok := m[ip]
	if !ok {
		return geo.Location{}, false
	}
	// Mirror MMDB: "found" means the country resolved. An entry with ASNOrg but
	// no Country returns (loc, false) — org present, country unknown.
	return loc, loc.Country != ""
}
```

(The existing `TestCallersGrouping` map entries all set `Country`, so they still report `found==true` and that test is unaffected.)

Then add this test:

```go
func TestCallersIncludesASNOrg(t *testing.T) {
	rows := []map[string]string{
		{"ip": "1.1.1.1", "requests": "30"}, // FR + org
		{"ip": "8.8.8.8", "requests": "10"}, // org but no country → Unknown, org still shown
	}
	g := mapGeo{
		"1.1.1.1": {City: "Paris", Country: "FR", CountryName: "France", ASNOrg: "Orange S.A."},
		"8.8.8.8": {ASNOrg: "Google LLC"}, // no Country → found=false → Unknown group
	}
	w := do(newAPIGeo(rows, g), "/api/callers?source=bl-site&from=2026-06-01&to=2026-06-27")
	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var got struct {
		Groups []struct {
			Country string `json:"country"`
			IPs     []struct {
				IP     string `json:"ip"`
				ASNOrg string `json:"asnOrg"`
			} `json:"ips"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.Bytes())
	}
	// France (resolved) first, Unknown last.
	if len(got.Groups) != 2 || got.Groups[0].Country != "France" || got.Groups[1].Country != "Unknown" {
		t.Fatalf("bad groups: %+v", got.Groups)
	}
	if got.Groups[0].IPs[0].ASNOrg != "Orange S.A." {
		t.Fatalf("France IP org = %q, want Orange S.A.", got.Groups[0].IPs[0].ASNOrg)
	}
	// Org is shown even though the IP has no country (Unknown bucket).
	if got.Groups[1].IPs[0].IP != "8.8.8.8" || got.Groups[1].IPs[0].ASNOrg != "Google LLC" {
		t.Fatalf("Unknown IP org = %+v, want 8.8.8.8/Google LLC", got.Groups[1].IPs[0])
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/app && go test ./internal/handlers/ -run TestCallersIncludesASNOrg -v`
Expected: FAIL — `asnOrg` absent from the payload (empty string), so the org assertions fail.

- [ ] **Step 3: Implement — read org regardless of country and emit it**

In `handlers.go` `groupCallersByCountry`, add `org` to the `caller` struct and the grouping loop, and emit it. Replace the struct and loop:

```go
	type caller struct {
		ip       string
		city     string
		org      string
		requests int
	}
	groups := map[string][]caller{}
	for _, r := range rows {
		loc, found := a.Geo.Lookup(r["ip"])
		country, city := unknownCountry, ""
		if found && loc.Country != "" {
			// Display the full name; fall back to the ISO code if MaxMind has
			// no English name for this country (rare).
			country, city = loc.CountryName, loc.City
			if country == "" {
				country = loc.Country
			}
		}
		// AS org is country-independent: populated even when found==false, so an
		// IP that can't be geolocated still shows its organization.
		groups[country] = append(groups[country], caller{ip: r["ip"], city: city, org: loc.ASNOrg, requests: atoi(r["requests"])})
	}
```

And in the emit loop, add `asnOrg`:

```go
		for _, x := range cs {
			ips = append(ips, gin.H{"ip": x.ip, "city": x.city, "asnOrg": x.org, "requests": x.requests})
		}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd packages/app && go test ./internal/handlers/ -run TestCallers -v`
Expected: PASS (`TestCallersGrouping`, `TestCallersEmpty`, `TestCallersIncludesASNOrg`).

- [ ] **Step 5: Full backend sweep + commit**

Run: `cd packages/app && go vet ./... && go test ./...`
Expected: vet clean; all packages `ok`.

```bash
git add packages/app/internal/handlers/handlers.go packages/app/internal/handlers/handlers_test.go
git commit -m "feat(monitoring): include AS org per IP in /api/callers

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Startup wiring — download + open the ASN DB

**Files:**
- Modify: `packages/app/cmd/main.go`

**Interfaces:**
- Consumes: `config.Config.GeoIPASNPath` (Task 2); `geo.Update(ctx, licenseKey, editionID, dbPath)` (Task 1); `(*geo.MMDB).LoadASN(path)` (Task 3).

No unit test (main.go has none; it is wiring). Verification is `go build` + the full suite still green; runtime behavior is an operator smoke step (needs live SSO + license key).

- [ ] **Step 1: Pass the edition to the existing City update and add the ASN update**

In `cmd/main.go`, the current GeoIP block calls `geo.Update(ctx, cfg.GeoIPLicenseKey, cfg.GeoIPPath)`. Change it to pass the City edition and add the ASN download right after. Locate:

```go
	} else if _, err := geo.Update(ctx, cfg.GeoIPLicenseKey, cfg.GeoIPPath); err != nil {
		log.Warn().Err(err).Msg("geoip download failed; will use an existing DB if present")
	}
```

Replace with:

```go
	} else {
		if _, err := geo.Update(ctx, cfg.GeoIPLicenseKey, "GeoLite2-City", cfg.GeoIPPath); err != nil {
			log.Warn().Err(err).Msg("geoip city download failed; will use an existing DB if present")
		}
		// AS-org DB: same license key + gate as City; best-effort (org is optional).
		if _, err := geo.Update(ctx, cfg.GeoIPLicenseKey, "GeoLite2-ASN", cfg.GeoIPASNPath); err != nil {
			log.Warn().Err(err).Msg("geoip ASN download failed; AS org will be blank")
		}
	}
```

- [ ] **Step 2: Attach the ASN reader after opening the City resolver**

Find the block that opens the City resolver (`resolver := geo.New()` … `if r, err := geo.Open(cfg.GeoIPPath); err != nil { … } else { resolver = r; … }`). Immediately after that block (before `defer resolver.Close()`), add:

```go
	// Attach the ASN reader so the callers list can show each IP's AS org.
	// Independent of the City DB — tolerated if absent (org just stays blank).
	if err := resolver.LoadASN(cfg.GeoIPASNPath); err != nil {
		log.Warn().Err(err).Str("path", cfg.GeoIPASNPath).Msg("geoip ASN DB NOT loaded → AS org will be blank; set GEOIP_LICENSE_KEY or place a .mmdb at GEOIP_ASN_DB_PATH")
	} else {
		log.Info().Str("path", cfg.GeoIPASNPath).Msg("geoip ASN database loaded")
	}
```

(Ensure this runs whether or not the City DB loaded — `resolver` is always a valid `*geo.MMDB` from `geo.New()` or `geo.Open`.)

- [ ] **Step 3: Build + full suite**

Run: `cd packages/app && go build ./... && go vet ./... && go test ./...`
Expected: builds; vet clean; all `ok`.

- [ ] **Step 4: Commit**

```bash
git add packages/app/cmd/main.go
git commit -m "feat(monitoring): auto-download and open the GeoLite2-ASN database at startup

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Frontend — show AS org inline in the Callers row

**Files:**
- Modify: `packages/web/src/pages/Callers.jsx`

**Interfaces:**
- Consumes: `ip.asnOrg` from `/api/callers` (Task 4).

- [ ] **Step 1: Render city + org in the middle column**

In `Callers.jsx`, the IP row currently renders the city in a conditional middle span. Replace that row's middle span so city and org appear together (each omitted when empty), inline between the IP and the request count. Find the row block:

```jsx
                    <div key={ip.ip} className="flex items-baseline justify-between gap-3 px-3.5 py-1.5 font-mono text-[11.5px]">
                      <span className="truncate text-foreground">{ip.ip}</span>
                      {ip.city && <span className="flex-1 truncate text-[10px] text-muted-foreground">{ip.city}</span>}
                      <span className="tabular-nums text-muted-foreground">{ip.requests.toLocaleString()} req</span>
                    </div>
```

Replace with:

```jsx
                    <div key={ip.ip} className="flex items-baseline justify-between gap-3 px-3.5 py-1.5 font-mono text-[11.5px]">
                      <span className="truncate text-foreground">{ip.ip}</span>
                      {/* city · AS org — each shown only when present, on the same line as the IP */}
                      <span className="flex-1 truncate text-[10px] text-muted-foreground">
                        {[ip.city, ip.asnOrg].filter(Boolean).join(' · ')}
                      </span>
                      <span className="tabular-nums text-muted-foreground">{ip.requests.toLocaleString()} req</span>
                    </div>
```

- [ ] **Step 2: Build + lint**

Run: `yarn --cwd packages/web build && yarn --cwd packages/web lint`
Expected: build succeeds; oxlint reports no errors.

- [ ] **Step 3: Commit**

```bash
git add packages/web/src/pages/Callers.jsx
git commit -m "feat(monitoring): show AS org inline beside city in the Callers list

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Plumbing + docs

**Files:**
- Modify: `.gitignore`, `packages/app/.gitignore`, `packages/app/.env.example`, `CLAUDE.md`

- [ ] **Step 1: Ignore the ASN DB artifacts in both .gitignore files**

In `monitoring/.gitignore`, after the three `GeoLite2-City.mmdb*` lines, add:

```
GeoLite2-ASN.mmdb
GeoLite2-ASN.mmdb.sha256
GeoLite2-ASN.mmdb.tmp
```

Do the same in `monitoring/packages/app/.gitignore` (after its `GeoLite2-City.mmdb*` lines).

- [ ] **Step 2: Note the new var in `.env.example`**

In `packages/app/.env.example`, near the existing `GEOIP_DB_PATH` line, add a commented line:

```
# Optional. Path to the GeoLite2-ASN DB (AS org for the callers list).
# Auto-downloaded with the same GEOIP_LICENSE_KEY. Default: ./GeoLite2-ASN.mmdb
# GEOIP_ASN_DB_PATH=./GeoLite2-ASN.mmdb
```

(Match the surrounding comment/format style of the file; use Read first to see the exact City entry and mirror it.)

- [ ] **Step 3: Update the CLAUDE.md GeoIP section**

In `monitoring/CLAUDE.md`, update the GeoIP section to note that **both** GeoLite2-City and GeoLite2-ASN are auto-downloaded with the same `GEOIP_LICENSE_KEY`/`GEOIP_AUTO_UPDATE`, and that the callers list shows the MaxMind-resolved AS organization per IP (`GEOIP_ASN_DB_PATH`, default `./GeoLite2-ASN.mmdb`). Use Read to find the current GeoIP paragraph and extend it; keep the existing wording about City intact.

- [ ] **Step 4: Verify**

Run: `cd /Users/jrsue/dev/repos/platform/monitoring && grep -rn "GeoLite2-ASN" .gitignore packages/app/.gitignore packages/app/.env.example CLAUDE.md`
Expected: matches in all four files.

- [ ] **Step 5: Commit**

```bash
git add monitoring/.gitignore monitoring/packages/app/.gitignore monitoring/packages/app/.env.example monitoring/CLAUDE.md
git commit -m "docs(monitoring): document GeoLite2-ASN auto-download and AS org in callers

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- Updater edition param → Task 1. ✅
- Config `GeoIPASNPath` + env + default → Task 2. ✅
- `Location.ASNOrg`, second nil-safe reader, `LoadASN`, country-independent `Lookup`, `Close` both → Task 3. ✅
- `/api/callers` `asnOrg` (incl. org-on-Unknown) → Task 4. ✅
- main.go download (same gate) + LoadASN, both editions named → Task 5. ✅
- Frontend inline `IP · city · org · requests` → Task 6. ✅
- .gitignore ×2, .env.example, CLAUDE.md → Task 7. ✅
- World map / drill-down unchanged: `Lookup` bool semantics preserved; only callers payload + Callers.jsx touched. ✅

**2. Placeholder scan:** No TBD/TODO. `.env.example`/`CLAUDE.md` steps say "Read first and mirror" because exact surrounding text isn't quoted here — the change content itself is fully specified. ✅

**3. Type/name consistency:** `Update(ctx, licenseKey, editionID, dbPath)` consistent across Tasks 1 and 5. `GeoIPASNPath` consistent (Tasks 2, 5). `Location.ASNOrg` / `json:"asnOrg"` consistent across Tasks 3, 4, 6. `LoadASN` consistent (Tasks 3, 5). Handler reads `loc.ASNOrg` unconditionally; resolver populates it independently of the bool — consistent with the Task 4 test fake (`found == Country != ""`). ✅
