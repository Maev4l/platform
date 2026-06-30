package geo

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

type Location struct {
	City        string  `json:"city"`
	Country     string  `json:"country"`     // ISO 3166-1 alpha-2 code (e.g. "FR") — keyed by the world map / CENTROIDS
	CountryName string  `json:"countryName"` // full English name (e.g. "France") — used by the callers list
	Lat         float64 `json:"lat"`
	Lng         float64 `json:"lng"`
}

type Resolver interface {
	Lookup(ip string) (Location, bool)
}

type MMDB struct{ db *geoip2.Reader }

// New returns a resolver with no database loaded. Lookup returns false for
// every IP until a DB is opened via Open. Used when the .mmdb is absent so
// the app still starts and the world view (based on c-country) keeps working.
func New() *MMDB { return &MMDB{} }

func Open(path string) (*MMDB, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &MMDB{db: db}, nil
}

func (m *MMDB) Lookup(ipStr string) (Location, bool) {
	// Nil-safe: when no DB was loaded (e.g. missing file) Lookup is a no-op
	// instead of panicking; the country drill-down returns no points gracefully.
	if m.db == nil {
		return Location{}, false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Location{}, false
	}
	rec, err := m.db.City(ip)
	// Require a resolved country (the world map groups by it). Coordinates may be
	// missing/zero for some IPs — that's fine for the world view; the drill-down
	// skips zero-coord points itself.
	if err != nil || rec == nil || rec.Country.IsoCode == "" {
		return Location{}, false
	}
	return Location{
		City:        rec.City.Names["en"],
		Country:     rec.Country.IsoCode,
		CountryName: rec.Country.Names["en"],
		Lat:         rec.Location.Latitude,
		Lng:         rec.Location.Longitude,
	}, true
}

func (m *MMDB) Close() error {
	// Nil-safe: allow Close on a resolver created with New() (no DB loaded).
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
