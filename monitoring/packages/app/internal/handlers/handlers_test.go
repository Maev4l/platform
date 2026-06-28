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
