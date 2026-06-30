# GeoLite2-ASN + AS Org in Callers View — Design

**Date:** 2026-06-30
**App:** `monitoring/` (CloudFront Log Analytics)
**Builds on:** the Callers view (`2026-06-30-callers-view-design.md`) and the GeoIP City auto-update already in the app.

## Goal

Wire the MaxMind **GeoLite2-ASN** database into the app the same way GeoLite2-City
is already wired (auto-download + local lookup), and show each caller's
**Autonomous System organization** (e.g. "Orange S.A.") inline in the
unique-IP-by-country list: `IP · city · org · requests`.

## Scope

- **In:** parameterize the GeoIP updater by edition; download GeoLite2-ASN under
  the same license-key/auto-update gate as City; add a second nil-safe ASN
  reader to the resolver; expose `ASNOrg` on `geo.Location`; add `asnOrg` to the
  `/api/callers` payload; render org inline in `Callers.jsx`; plumbing (.gitignore,
  .env.example, CLAUDE.md); tests.
- **Out:** hostname / reverse-DNS (explicitly dropped). The ASN **number** is not
  shown (org name only). The geo world map and country drill-down
  (`/api/geo`, `resolvePoints`) are unchanged — org is added only to the
  callers list. No new auto-update flag.

## Theme constraint (binding)

No new visual language. The org renders with existing tokens (muted text in the
same row as city, following the existing `Callers.jsx` row idiom). City and org
are each omitted when empty.

---

## Backend

### 1. Updater — parameterize the edition (`internal/geo/updater.go`)

Today `editionID` is a package const (`"GeoLite2-City"`) baked into `httpGet`'s
URL. Change the download functions to take an `editionID` parameter so the same
flow serves both editions:

- `httpGet(ctx, licenseKey, editionID, suffix string)` — interpolate `editionID`.
- `remoteSHA(ctx, licenseKey, editionID string)`.
- `Update(ctx, licenseKey, editionID, dbPath string) (bool, error)`.

The sha-sidecar logic, `tar.gz` checksum verification, `extractMMDB`, and atomic
`.tmp`→rename are unchanged (already edition-agnostic). Remove the package
const; callers pass `"GeoLite2-City"` / `"GeoLite2-ASN"` explicitly.

> All existing `Update(...)` / `httpGet(...)` call sites (main.go and
> `updater_test.go`) must be updated to the new signatures.

### 2. Config (`internal/config/config.go`)

- Add field `GeoIPASNPath string`.
- Add env mapping `"GEOIP_ASN_DB_PATH": "geoip_asn_path"`.
- Add default `"geoip_asn_path": "./GeoLite2-ASN.mmdb"`.
- Populate `c.GeoIPASNPath = k.String("geoip_asn_path")`.

`GEOIP_LICENSE_KEY` and `GEOIP_AUTO_UPDATE` are reused unchanged — they gate both
databases together.

### 3. Resolver (`internal/geo/resolver.go`)

- `Location` gains `ASNOrg string` (`json:"asnOrg"`). Keep `Country` (ISO) and
  `CountryName` as-is.
- `MMDB` holds two readers. Rename the existing field to `city` and add
  `asn *geoip2.Reader`; both may be nil.
- Add `func (m *MMDB) LoadASN(path string) error` — opens the ASN `.mmdb` via
  `geoip2.Open` and attaches it (`m.asn = reader`). Errors propagate so the
  caller can log; on error the resolver keeps `asn == nil` (org simply absent).
- `Close()` closes both readers (each nil-safe).
- **Restructure `Lookup`** so ASN org is independent of country resolution:
  - Parse the IP once; return `(Location{}, false)` if unparseable.
  - If `m.city != nil`: look up city; populate `City`/`Country`/`CountryName`/
    `Lat`/`Lng` and set `countryOK = true` **only when** `rec.Country.IsoCode != ""`
    (preserves today's "found means country resolved" contract that the world
    map relies on).
  - If `m.asn != nil`: look up ASN; set `loc.ASNOrg = rec.AutonomousSystemOrganization`
    (independent of `countryOK`).
  - Return `(loc, countryOK)`.

  Net effect: the world-map fallback and drill-down behave exactly as before
  (they branch on the bool and `loc.Country`), while `loc.ASNOrg` is available
  even for IPs that don't resolve to a country (they land in the `Unknown`
  group but still show their org).

### 4. Startup wiring (`cmd/main.go`)

Mirror the City flow:
- In the auto-update block (when `GeoIPAutoUpdate` && `GeoIPLicenseKey != ""`),
  after the City `Update`, also call
  `geo.Update(ctx, cfg.GeoIPLicenseKey, "GeoLite2-ASN", cfg.GeoIPASNPath)`,
  logging a warning (not fatal) on error — same tolerance as City.
- The existing City `Update` call becomes
  `geo.Update(ctx, cfg.GeoIPLicenseKey, "GeoLite2-City", cfg.GeoIPPath)`.
- After opening the City resolver (`geo.Open(cfg.GeoIPPath)`), call
  `resolver.LoadASN(cfg.GeoIPASNPath)`; on success log the loaded path, on error
  log a warning that AS org will be blank (do not fail startup).

### 5. Handler (`internal/handlers/handlers.go`)

In `groupCallersByCountry`, the per-IP `caller` struct gains `org string`,
populated from `loc.ASNOrg` (read regardless of `found`, since org is
country-independent). Each emitted IP `gin.H` gains `"asnOrg": x.org`. Group
keying/sorting and the `count`/empty-shape contract are unchanged.

---

## Frontend (`packages/web/src/pages/Callers.jsx`)

The IP row renders inline: `IP · city · org · requests`. City and org are each
shown only when non-empty, as muted text consistent with the current row. The
`requests` value stays right-aligned. No other component changes; tokens and
layout primitives are the existing ones.

---

## Plumbing

- `monitoring/.gitignore`: ignore `GeoLite2-ASN.mmdb`, `GeoLite2-ASN.mmdb.sha256`,
  `GeoLite2-ASN.mmdb.tmp` (mirror the City entries).
- `packages/app/.env.example`: note `GEOIP_ASN_DB_PATH` (optional; default
  `./GeoLite2-ASN.mmdb`; downloaded automatically with the same license key).
- `monitoring/CLAUDE.md` GeoIP section: note both GeoLite2-City and GeoLite2-ASN
  are auto-downloaded with the same `GEOIP_LICENSE_KEY`, and that the callers
  list shows the MaxMind-resolved AS organization per IP.

## Testing

| Layer | Test |
|---|---|
| Go updater | `Update`/`httpGet` use the passed edition in the request URL (assert the httptest server sees `edition_id=GeoLite2-ASN`). |
| Go resolver | `Lookup` returns `ASNOrg` when only the ASN reader has data and the City reader yields no country (org present, `found==false`); and both populated when both resolve. |
| Go handler | `/api/callers` IP entries include `asnOrg`; an IP with org but no country still shows org in the `Unknown` group. |
| Go config | default `GeoIPASNPath == "./GeoLite2-ASN.mmdb"`; `GEOIP_ASN_DB_PATH` override honored. |
| Web | oxlint clean; manual smoke (operator, needs live SSO + both .mmdb): org appears inline per IP. |
| Go sweep | `go vet ./...`, `go test ./...` green. |

## Open questions

None.
