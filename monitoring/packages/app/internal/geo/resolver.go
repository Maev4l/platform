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
