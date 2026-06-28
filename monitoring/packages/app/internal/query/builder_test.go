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
	if !strings.Contains(sql, `"bl_site"`) || !strings.Contains(sql, "BETWEEN ? AND ?") || !strings.Contains(sql, "date_trunc('day'") {
		t.Fatalf("bad sql: %s", sql)
	}
	if len(args) != 2 || args[0] != "2026-06-01" || args[1] != "2026-06-27" {
		t.Fatalf("bad args: %v", args)
	}
}

func TestAccessRejectsBadGroupBy(t *testing.T) {
	if _, _, err := Access("t", "a", "b", "hour"); err != ErrBadGroupBy {
		t.Fatalf("want ErrBadGroupBy, got %v", err)
	}
}

func TestGeoCountries(t *testing.T) {
	sql, args := GeoCountries("t", "2026-06-01", "2026-06-27")
	if !strings.Contains(sql, `"c-country"`) || !strings.Contains(strings.ToLower(sql), "group by") || len(args) != 2 {
		t.Fatalf("bad: %s %v", sql, args)
	}
}

func TestGeoIPsFiltersCountry(t *testing.T) {
	sql, args := GeoIPs("t", "2026-06-01", "2026-06-27", "FR")
	if !strings.Contains(sql, `"c-country" = ?`) || !strings.Contains(sql, `"c-ip"`) || len(args) != 3 || args[2] != "FR" {
		t.Fatalf("bad: %s %v", sql, args)
	}
}

func TestSummaryAndTopURIs(t *testing.T) {
	if sql, args := Summary("t", "2026-06-01", "2026-06-27"); !strings.Contains(sql, "count(") || len(args) != 2 {
		t.Fatalf("bad summary: %s %v", sql, args)
	}
	if sql, args := TopURIs("t", "2026-06-01", "2026-06-27", 8); !strings.Contains(sql, "LIMIT 8") || len(args) != 2 {
		t.Fatalf("bad topuris: %s %v", sql, args)
	}
}
