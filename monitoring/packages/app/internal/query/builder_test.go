package query

import (
	"strings"
	"testing"
)

func TestAccessGroupByDay(t *testing.T) {
	sql, args, err := Access("bl_site", "2026-06-01", "2026-06-27", "day")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, `"bl_site"`) || !strings.Contains(sql, "date_trunc('day'") {
		t.Fatalf("bad sql: %s", sql)
	}
	// integer-composite partition pruning (varchar cols cast to int) + inlined bounds
	if !strings.Contains(sql, `CAST("year" AS integer) * 10000`) {
		t.Fatalf("missing composite partition key: %s", sql)
	}
	if !strings.Contains(sql, "BETWEEN 20260601 AND 20260627") {
		t.Fatalf("missing inlined integer bounds: %s", sql)
	}
	// dates are inlined into the predicate, so there are no positional args
	if len(args) != 0 {
		t.Fatalf("expected no args, got %v", args)
	}
}

func TestAccessRejectsBadGroupBy(t *testing.T) {
	if _, _, err := Access("t", "a", "b", "hour"); err != ErrBadGroupBy {
		t.Fatalf("want ErrBadGroupBy, got %v", err)
	}
}

func TestGeoCountries(t *testing.T) {
	sql, args := GeoCountries("t", "2026-06-01", "2026-06-27")
	if !strings.Contains(sql, `"c_country" AS country`) || !strings.Contains(strings.ToLower(sql), "group by") {
		t.Fatalf("bad sql: %s", sql)
	}
	if !strings.Contains(sql, "BETWEEN 20260601 AND 20260627") || len(args) != 0 {
		t.Fatalf("bad bounds/args: %s %v", sql, args)
	}
}

func TestGeoIPsFiltersCountry(t *testing.T) {
	sql, args := GeoIPs("t", "2026-06-01", "2026-06-27", "FR")
	if !strings.Contains(sql, `"c_country" = ?`) || !strings.Contains(sql, `"c_ip" AS ip`) {
		t.Fatalf("bad sql: %s", sql)
	}
	if len(args) != 1 || args[0] != "FR" {
		t.Fatalf("bad args: %v", args)
	}
}

func TestGeoAllIPs(t *testing.T) {
	sql, args := GeoAllIPs("t", "2026-06-01", "2026-06-27")
	if !strings.Contains(sql, `"c_ip" AS ip`) || !strings.Contains(strings.ToLower(sql), "group by") {
		t.Fatalf("bad sql: %s", sql)
	}
	if !strings.Contains(sql, "BETWEEN 20260601 AND 20260627") {
		t.Fatalf("missing partition bounds: %s", sql)
	}
	if len(args) != 0 {
		t.Fatalf("expected no args, got %v", args)
	}
}

func TestSummaryAndTopURIs(t *testing.T) {
	if sql, args := Summary("t", "2026-06-01", "2026-06-27"); !strings.Contains(sql, "count(") || len(args) != 0 {
		t.Fatalf("bad summary: %s args=%v", sql, args)
	}
	if sql, args := TopURIs("t", "2026-06-01", "2026-06-27", 8); !strings.Contains(sql, "LIMIT 8") || len(args) != 0 {
		t.Fatalf("bad topuris: %s args=%v", sql, args)
	}
}
