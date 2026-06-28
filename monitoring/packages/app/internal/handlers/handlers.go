package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
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
	r.NoRoute(gin.WrapH(web.Handler())) // embedded SPA fallback for all non-API routes
}

const dateLayout = "2006-01-02"

// validate extracts and validates source, from, to query params.
// Returns early with the appropriate HTTP error if any param is invalid.
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

// cached checks the in-memory cache before executing the Athena query.
// On a hit the raw JSON bytes are served directly; on a miss the query runs,
// result is marshalled, stored, and served. Athena errors produce 502.
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

// sources returns the list of configured log source names.
func (a *API) sources(c *gin.Context) {
	names := make([]string, 0, len(a.Cfg.Sources))
	for n := range a.Cfg.Sources {
		names = append(names, n)
	}
	sort.Strings(names) // stable order so the UI source selector doesn't reshuffle
	c.JSON(http.StatusOK, names)
}

// access returns time-bucketed HTTP status counts for the given source and date range.
func (a *API) access(c *gin.Context) {
	src, from, to, ok := a.validate(c)
	if !ok {
		return
	}
	groupBy := c.DefaultQuery("groupBy", "day")
	sql, args, err := query.Access(src.Table, from, to, groupBy)
	if err != nil {
		// query.ErrBadGroupBy is the only error Access can return
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

// geo returns either world-level country aggregates or per-IP drill-down for a country.
func (a *API) geo(c *gin.Context) {
	src, from, to, ok := a.validate(c)
	if !ok {
		return
	}
	country := c.Query("country")
	if country == "" {
		// World view: prefer CloudFront's c_country (cheap); if it's unpopulated
		// (no rows), fall back to resolving each IP's country via MaxMind.
		cSQL, cArgs := query.GeoCountries(src.Table, from, to)
		allSQL, allArgs := query.GeoAllIPs(src.Table, from, to)
		a.cached(c, "geoW|"+src.Name+"|"+from+"|"+to, func(ctx context.Context) (any, error) {
			rows, err := a.Q.Query(ctx, cSQL, cArgs)
			if err != nil {
				return nil, err
			}
			if len(rows) > 0 {
				out := make([]gin.H, 0, len(rows))
				for _, r := range rows {
					out = append(out, gin.H{"country": r["country"], "callers": atoi(r["callers"]), "ips": atoi(r["ips"])})
				}
				return gin.H{"level": "world", "countries": out}, nil
			}
			// Fallback: aggregate requests + distinct IPs by MaxMind-resolved country.
			ipRows, err := a.Q.Query(ctx, allSQL, allArgs)
			if err != nil {
				return nil, err
			}
			type agg struct{ callers, ips int }
			m := map[string]*agg{}
			for _, r := range ipRows {
				loc, found := a.Geo.Lookup(r["ip"])
				if !found || loc.Country == "" {
					continue
				}
				g := m[loc.Country]
				if g == nil {
					g = &agg{}
					m[loc.Country] = g
				}
				g.callers += atoi(r["requests"])
				g.ips++
			}
			out := make([]gin.H, 0, len(m))
			for cc, g := range m {
				out = append(out, gin.H{"country": cc, "callers": g.callers, "ips": g.ips})
			}
			return gin.H{"level": "world", "countries": out}, nil
		})
		return
	}
	// Country drill-down: prefer the c_country-filtered IPs; if none (c_country
	// unpopulated), fall back to all IPs filtered by MaxMind-resolved country.
	cSQL, cArgs := query.GeoIPs(src.Table, from, to, country)
	allSQL, allArgs := query.GeoAllIPs(src.Table, from, to)
	a.cached(c, "geoC|"+src.Name+"|"+from+"|"+to+"|"+country, func(ctx context.Context) (any, error) {
		rows, err := a.Q.Query(ctx, cSQL, cArgs)
		if err != nil {
			return nil, err
		}
		if len(rows) > 0 {
			// c_country path: IPs are already in `country`; just need coords.
			return gin.H{"level": "country", "country": country, "points": a.resolvePoints(rows, "")}, nil
		}
		ipRows, err := a.Q.Query(ctx, allSQL, allArgs)
		if err != nil {
			return nil, err
		}
		return gin.H{"level": "country", "country": country, "points": a.resolvePoints(ipRows, country)}, nil
	})
}

// resolvePoints turns {ip,requests} rows into geo map points via MaxMind,
// skipping IPs with no coordinates. When filterCountry != "", only IPs that
// MaxMind resolves to that country are kept.
func (a *API) resolvePoints(rows []map[string]string, filterCountry string) []gin.H {
	points := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		loc, found := a.Geo.Lookup(r["ip"])
		if !found || (loc.Lat == 0 && loc.Lng == 0) {
			continue
		}
		if filterCountry != "" && loc.Country != filterCountry {
			continue
		}
		points = append(points, gin.H{"ip": r["ip"], "city": loc.City, "lat": loc.Lat, "lng": loc.Lng, "requests": atoi(r["requests"])})
	}
	return points
}

// summary returns aggregate stats and top URIs for the given source and date range.
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
			return gin.H{"total": 0, "uniqueIps": 0, "errors": 0, "errorRate": 0.0, "topUris": []gin.H{}}, nil
		}
		r := rows[0]
		total, errs := atoi(r["total"]), atoi(r["errors"])
		rate := 0.0
		if total > 0 {
			// errorRate is a percentage of 4xx+5xx responses out of total requests
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
		return gin.H{"total": total, "uniqueIps": atoi(r["unique_ips"]), "errors": errs, "errorRate": rate, "topUris": uris}, nil
	})
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
