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
