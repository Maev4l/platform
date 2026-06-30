package geo

import "testing"

type fakeResolver struct {
	loc Location
	ok  bool
}

func (f fakeResolver) Lookup(string) (Location, bool) { return f.loc, f.ok }

func TestResolverInterface(t *testing.T) {
	var r Resolver = fakeResolver{loc: Location{City: "Paris", Country: "FR", Lat: 48.85, Lng: 2.35}, ok: true}
	if loc, ok := r.Lookup("1.2.3.4"); !ok || loc.City != "Paris" {
		t.Fatalf("unexpected %+v ok=%v", loc, ok)
	}
}

func TestOpenMissingFile(t *testing.T) {
	if _, err := Open("/no/such/file.mmdb"); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewResolverLookupReturnsFalse(t *testing.T) {
	// New() produces a zero-DB resolver; Lookup must return false (no panic)
	// so the app can start gracefully when the .mmdb is absent.
	m := New()
	if _, ok := m.Lookup("1.2.3.4"); ok {
		t.Fatal("expected Lookup on empty resolver to return false")
	}
	// Close on a nil-DB resolver must not panic.
	if err := m.Close(); err != nil {
		t.Fatalf("Close on empty resolver: %v", err)
	}
}

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
