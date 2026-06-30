package geo

import (
	"errors"
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
// without an ASN DB closes cleanly). Both are closed unconditionally — a
// failure closing one must not leak the other's file descriptor — and any
// errors are joined.
func (m *MMDB) Close() error {
	var errs []error
	if m.city != nil {
		errs = append(errs, m.city.Close())
	}
	if m.asn != nil {
		errs = append(errs, m.asn.Close())
	}
	return errors.Join(errs...)
}
