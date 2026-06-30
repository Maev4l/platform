package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"isnan.eu/monitoring/internal/athena"
	"isnan.eu/monitoring/internal/cache"
	"isnan.eu/monitoring/internal/config"
	"isnan.eu/monitoring/internal/geo"
)

type fakeQ struct{ rows []map[string]string }

func (f fakeQ) Query(context.Context, string, []string) ([]map[string]string, error) {
	return f.rows, nil
}

// routeQ returns different rows depending on which query the handler runs, so
// the c_country-first / IP-fallback branches can be exercised.
type routeQ struct {
	countries []map[string]string // GeoCountries (world, "AS country")
	geoIPs    []map[string]string // GeoIPs (drill, "c_country = ?")
	allIPs    []map[string]string // GeoAllIPs (fallback, "AS ip")
}

func (q routeQ) Query(_ context.Context, sql string, _ []string) ([]map[string]string, error) {
	switch {
	case strings.Contains(sql, `"c_country" = ?`):
		return q.geoIPs, nil
	case strings.Contains(sql, "AS country"):
		return q.countries, nil
	case strings.Contains(sql, "AS ip"):
		return q.allIPs, nil
	}
	return nil, nil
}

func newAPIQ(q athena.Querier) *API {
	return &API{
		Cfg:   &config.Config{Sources: map[string]config.Source{"bl-site": {Name: "bl-site", Table: "bl_site"}}},
		Q:     q,
		Geo:   fakeGeo{},
		Cache: cache.New(time.Minute),
	}
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

type worldResp struct {
	Level     string `json:"level"`
	Countries []struct {
		Country string `json:"country"`
		Callers int    `json:"callers"`
		IPs     int    `json:"ips"`
	} `json:"countries"`
}

func TestGeoWorldFromCountryField(t *testing.T) {
	// c_country populated → world uses it directly (no IP resolution).
	q := routeQ{countries: []map[string]string{{"country": "FR", "callers": "200", "ips": "5"}}}
	w := do(newAPIQ(q), "/api/geo?source=bl-site&from=2026-06-01&to=2026-06-27")
	var got worldResp
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Level != "world" || len(got.Countries) != 1 || got.Countries[0].Country != "FR" ||
		got.Countries[0].Callers != 200 || got.Countries[0].IPs != 5 {
		t.Fatalf("bad world (c_country): %+v", got)
	}
}

func TestGeoWorldIPFallback(t *testing.T) {
	// c_country empty → fall back to MaxMind-resolved aggregation (fakeGeo → FR).
	q := routeQ{
		countries: []map[string]string{},
		allIPs:    []map[string]string{{"ip": "1.2.3.4", "requests": "9000"}, {"ip": "5.6.7.8", "requests": "241"}},
	}
	w := do(newAPIQ(q), "/api/geo?source=bl-site&from=2026-06-01&to=2026-06-27")
	var got worldResp
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Level != "world" || len(got.Countries) != 1 || got.Countries[0].Country != "FR" ||
		got.Countries[0].Callers != 9241 || got.Countries[0].IPs != 2 {
		t.Fatalf("bad world (ip fallback): %+v", got)
	}
}

func TestGeoDrilldown(t *testing.T) {
	// c_country path: GeoIPs returns IPs already in the country; resolve coords.
	q := routeQ{geoIPs: []map[string]string{{"ip": "92.184.105.12", "requests": "842"}}}
	w := do(newAPIQ(q), "/api/geo?source=bl-site&from=2026-06-01&to=2026-06-27&country=FR")
	var got struct {
		Level  string `json:"level"`
		Points []struct {
			City string  `json:"city"`
			Lat  float64 `json:"lat"`
		} `json:"points"`
	}
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Level != "country" || len(got.Points) != 1 || got.Points[0].City != "Paris" || got.Points[0].Lat != 48.85 {
		t.Fatalf("bad drilldown: %+v", got)
	}
}

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
		{"ip": "9.9.9.9", "requests": "5"},   // unresolved → Unknown
		{"ip": "1.1.1.0", "requests": "10"},  // ties with 1.1.1.1, lower IP should sort first
	}
	g := mapGeo{
		"1.1.1.1": {City: "Lyon", Country: "FR", CountryName: "France", Lat: 45.7, Lng: 4.8},
		"2.2.2.2": {City: "Paris", Country: "FR", CountryName: "France", Lat: 48.8, Lng: 2.3},
		"3.3.3.3": {City: "Berlin", Country: "DE", CountryName: "Germany", Lat: 52.5, Lng: 13.4},
		"1.1.1.0": {City: "Nice", Country: "FR", CountryName: "France", Lat: 43.7, Lng: 7.2},
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
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.Bytes())
	}

	// Alphabetical by full country name (France, Germany) then Unknown last.
	if len(got.Groups) != 3 || got.Groups[0].Country != "France" ||
		got.Groups[1].Country != "Germany" || got.Groups[2].Country != "Unknown" {
		t.Fatalf("bad group order: %+v", got.Groups)
	}
	// France group: requests-desc → Paris(50) before tied IPs(10); lower IP wins tie; city carried through.
	fr := got.Groups[0]
	if fr.Count != 3 || len(fr.IPs) != 3 ||
		fr.IPs[0].IP != "2.2.2.2" || fr.IPs[0].Requests != 50 || fr.IPs[0].City != "Paris" ||
		fr.IPs[1].IP != "1.1.1.0" || fr.IPs[1].Requests != 10 || fr.IPs[1].City != "Nice" ||
		fr.IPs[2].IP != "1.1.1.1" || fr.IPs[2].City != "Lyon" {
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
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.Bytes())
	}
	if w.Code != 200 || len(got.Groups) != 0 {
		t.Fatalf("want 200 + empty groups, got %d %+v", w.Code, got.Groups)
	}
}
