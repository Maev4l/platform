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
